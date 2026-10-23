"""Builds the pipeline in its fixed order. Tests can swap any slot by name."""

from __future__ import annotations

from dataclasses import dataclass, field

from keystone.core.types import CallContext
from keystone.defense.scanner import OutputScanner
from keystone.gateway.interceptors.approval import (
    ApprovalGate,
    ApprovalInterceptor,
    Revalidation,
)
from keystone.gateway.interceptors.credentials import CredentialInterceptor, HeaderSource
from keystone.gateway.interceptors.flags import SessionFlagsInterceptor
from keystone.gateway.interceptors.pinning import PinningInterceptor, ToolStateLookup
from keystone.gateway.interceptors.policy import PolicyInterceptor
from keystone.gateway.interceptors.scan import OutputScanInterceptor
from keystone.gateway.pipeline import AuditSink, Dispatcher, Interceptor, Pipeline
from keystone.gateway.sessions import SessionStore, refresh
from keystone.gateway.stubs import ApprovalInterceptor as StubApprovalInterceptor
from keystone.gateway.stubs import (
    BudgetInterceptor,
    MeteringInterceptor,
    RateLimitInterceptor,
)
from keystone.gateway.stubs import OutputScanInterceptor as StubOutputScanInterceptor
from keystone.gateway.stubs import PolicyInterceptor as StubPolicyInterceptor
from keystone.policy.engine import PolicyEngine
from keystone.settings import Settings
from keystone.telemetry.metrics import Metrics
from keystone.telemetry.tracing import NoopTracer, Tracer

# Plan section 3.4. The order never changes; a phase replaces the class in a slot.
INTERCEPTOR_ORDER = (
    "rate_limit",
    "pinning",
    "budget",
    "policy",
    "approval",
    "credential",
    "output_scan",
    "session_flags",
    "metering",
)


# What a call that waited for approval is not checked against a second time. The rate limit charges
# a call once, when it arrives (KS-691). Every other slot ahead of the approval slot runs again.
NOT_REPEATED = ("rate_limit",)


@dataclass(frozen=True)
class PipelineDeps:
    dispatcher: Dispatcher
    audit: AuditSink
    tracer: Tracer = field(default_factory=NoopTracer)
    # Where the pipeline counts calls and times stages. Without one it counts nothing.
    metrics: Metrics | None = None
    # Where the pinning slot reads a tool's current status. Without one it trusts the tool it was
    # handed, which is what the unit tests want.
    tool_states: ToolStateLookup | None = None
    # Where the credential slot gets upstream headers. Without one it adds none.
    vault: HeaderSource | None = None
    # The engine that decides every call. The app always passes one. Without one the slot is the
    # Phase 1 stub that allows everything, which only the unit tests of the pipeline want.
    policy: PolicyEngine | None = None
    # Where a call that needs approval is stored and waited for (KS-602). Without one the slot is
    # the stub that refuses it: the unit tests of the pipeline, and an app with no master key.
    approvals: ApprovalGate | None = None
    # Where the sessions are kept. A call that waited for approval reads its session again from
    # here before it is checked a second time (KS-791), and the flags and output slots record what
    # a call learned here (KS-704). Without one the call is checked on the copy it started with and
    # records on that copy alone, which is what the unit tests of the pipeline want.
    sessions: SessionStore | None = None
    # What reads the output of a tool (KS-704). Without one the output slot is the Phase 1 stub that
    # records a benign scan, which only the unit tests of the pipeline want. `scanner.enabled`
    # false switches the scan off whatever is given here.
    scanner: OutputScanner | None = None


def output_slot(settings: Settings, deps: PipelineDeps) -> Interceptor:
    """The scanner is off when the settings say so: nothing is scanned and the audit record has no
    scan, which is not the same as a scan that found nothing. With the scanner on and none given,
    the slot is the stub that records a benign scan."""
    if not settings.scanner.enabled:
        return OutputScanInterceptor(None)
    if deps.scanner is None:
        return StubOutputScanInterceptor()
    return OutputScanInterceptor(deps.scanner, deps.sessions, deps.metrics)


def build_pipeline(
    settings: Settings,
    deps: PipelineDeps,
    overrides: dict[str, Interceptor] | None = None,
) -> Pipeline:
    """A slot not named in `overrides` gets its stub. A name that is not a slot is an error,
    so a typo cannot silently leave a stub in place of the real interceptor."""
    overrides = overrides or {}
    unknown = sorted(set(overrides) - set(INTERCEPTOR_ORDER))
    if unknown:
        raise ValueError(f"unknown interceptor slot: {', '.join(unknown)}")
    revalidation = Revalidation()
    stubs: dict[str, Interceptor] = {
        "rate_limit": RateLimitInterceptor(),
        "pinning": PinningInterceptor(deps.tool_states),
        "budget": BudgetInterceptor(),
        "policy": PolicyInterceptor(deps.policy) if deps.policy else StubPolicyInterceptor(),
        "approval": (
            ApprovalInterceptor(
                deps.approvals,
                wait_seconds=settings.approvals.wait_seconds,
                revalidate=revalidation,
            )
            if deps.approvals is not None
            else StubApprovalInterceptor()
        ),
        "credential": CredentialInterceptor(deps.vault),
        "output_scan": output_slot(settings, deps),
        "session_flags": SessionFlagsInterceptor(deps.sessions),
        "metering": MeteringInterceptor(),
    }
    interceptors = [overrides.get(slot, stubs[slot]) for slot in INTERCEPTOR_ORDER]
    pipeline = Pipeline(
        interceptors,
        deps.dispatcher,
        deps.audit,
        deps.tracer,
        fail_closed=settings.audit_fail_closed,
        metrics=deps.metrics,
    )

    async def check_again(ctx: CallContext) -> None:
        # The copy of the session that the call carries is from before the wait, and another call
        # of the session may have been tainted or flagged in the meantime. The policy decides
        # again on the session as it is now. A session that cannot be read fails the call.
        if deps.sessions is not None:
            await refresh(deps.sessions, ctx.session)
        await pipeline.run_before(ctx, "approval", skip=NOT_REPEATED)

    revalidation.bind(check_again)
    return pipeline
