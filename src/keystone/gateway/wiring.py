"""Builds the pipeline in its fixed order. Tests can swap any slot by name."""

from __future__ import annotations

from dataclasses import dataclass, field

from keystone.gateway.pipeline import AuditSink, Dispatcher, Interceptor, Pipeline
from keystone.gateway.stubs import (
    ApprovalInterceptor,
    BudgetInterceptor,
    CredentialInterceptor,
    MeteringInterceptor,
    OutputScanInterceptor,
    PinningInterceptor,
    PolicyInterceptor,
    RateLimitInterceptor,
    SessionFlagsInterceptor,
)
from keystone.settings import Settings
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


@dataclass(frozen=True)
class PipelineDeps:
    dispatcher: Dispatcher
    audit: AuditSink
    tracer: Tracer = field(default_factory=NoopTracer)


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
    stubs: dict[str, Interceptor] = {
        "rate_limit": RateLimitInterceptor(),
        "pinning": PinningInterceptor(),
        "budget": BudgetInterceptor(),
        "policy": PolicyInterceptor(),
        "approval": ApprovalInterceptor(),
        "credential": CredentialInterceptor(),
        "output_scan": OutputScanInterceptor(),
        "session_flags": SessionFlagsInterceptor(),
        "metering": MeteringInterceptor(),
    }
    interceptors = [overrides.get(slot, stubs[slot]) for slot in INTERCEPTOR_ORDER]
    return Pipeline(interceptors, deps.dispatcher, deps.audit, deps.tracer)
