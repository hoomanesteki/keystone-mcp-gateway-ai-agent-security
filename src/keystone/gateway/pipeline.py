"""Every tool call goes through Pipeline.run (plan section 3.4, ADR-0004).

Rules the code below keeps:
- The audit sink runs in `finally`, shielded from cancellation, so every call leaves one record
  (invariant I2).
- Nothing the agent sees contains exception text. A rejection carries the message its raiser
  wrote for the agent. Any other exception becomes a generic message and goes to the log.
- A hook that crashes fails closed: before the dispatch the call is denied, after it the
  output is blocked. The audit outcome for a crash is "error", not "rejected".
- The pipeline dispatches only when a decision allows it (`require_dispatch_decision`), so
  invariant I1 does not rest on the policy slot alone.
- With `fail_closed`, a call is refused before anything runs while the audit sink is unhealthy
  (KS-501, ADR-0009): an action with no record is what the audit log exists to prevent.
- A call that waited for a person is checked again before it goes on: `run_before` runs the slots
  ahead of the approval slot a second time (KS-691), so it is dispatched under the rules of the
  moment it is dispatched and not those of the moment it arrived.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Awaitable, Callable, Collection
from typing import Literal, Protocol

import anyio
import structlog
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from keystone.core.canonical import canonical_json
from keystone.core.errors import Code, Reject, to_tool_result
from keystone.core.types import CallContext, Effect, ToolResult
from keystone.gateway.hooks import is_noop
from keystone.telemetry.metrics import Metrics
from keystone.telemetry.tracing import NO_SPAN, SpanHandle, Tracer

log = structlog.get_logger()

MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_VALIDATION_MESSAGE = 300

CRASH_MESSAGE = "the gateway could not finish checking this call"
NO_DECISION = "no-decision"
AUDIT_UNAVAILABLE = "audit-unavailable"
# What a failed span says. It is fixed text: an exception's own would be sent to the collector.
INTERCEPTOR_FAILED = "the interceptor failed"
UPSTREAM_FAILED = "the upstream call failed"
CALL_FAILED = "the call failed"

Outcome = Literal["ok", "rejected", "error"]


class Interceptor(Protocol):
    name: str

    async def before_call(self, ctx: CallContext) -> None: ...  # may raise Reject, may mutate ctx
    async def after_call(self, ctx: CallContext) -> None: ...  # may replace ctx.result


class Dispatcher(Protocol):
    async def dispatch(self, ctx: CallContext) -> ToolResult: ...


class AuditSink(Protocol):
    async def record(self, ctx: CallContext, outcome: Outcome, reject: Reject | None) -> None: ...

    # False when a record handed to the sink might not be written: the queue is nearly full or
    # the last flush failed. Added in KS-501 (ADR-0009).
    def healthy(self) -> bool: ...


class _Crash(Reject):
    """A Reject standing in for an interceptor that raised something else."""


def validate_arguments(ctx: CallContext) -> None:
    """Raise Reject(INVALID_ARGUMENTS) unless the arguments fit the size limit and the schema."""
    try:
        size = len(canonical_json(ctx.arguments))
    except (TypeError, ValueError):
        raise Reject(Code.INVALID_ARGUMENTS, "arguments are not valid JSON") from None
    if size > MAX_ARGUMENT_BYTES:
        raise Reject(
            Code.INVALID_ARGUMENTS, f"arguments are {size} bytes, the limit is {MAX_ARGUMENT_BYTES}"
        )
    try:
        error = best_match(Draft202012Validator(ctx.tool.input_schema).iter_errors(ctx.arguments))
    except Exception:
        # A broken schema is the upstream's fault, and the agent cannot fix it.
        log.error("tool_schema_unusable", call_id=ctx.call_id, tool=ctx.tool.name, exc_info=True)
        raise Reject(Code.UPSTREAM_ERROR, "the tool's input schema cannot be used") from None
    if error is not None:
        message = error.message
        if len(message) > MAX_VALIDATION_MESSAGE:
            message = message[:MAX_VALIDATION_MESSAGE] + "..."
        raise Reject(Code.INVALID_ARGUMENTS, f"{message} (at {error.json_path})")


def require_dispatch_decision(ctx: CallContext) -> None:
    """Raise Reject(DENIED) unless ctx holds a decision that lets the call reach the upstream:
    `allow`, or `require_approval` with an approval id (structural invariant I1, KS-191).

    The approval interceptor (KS-602) sets `ctx.approval_id` only after `consume` succeeded on an
    approved request. Setting it on any other path turns a pending approval into an allow.
    """
    decision = ctx.decision
    if decision is not None and (
        decision.effect is Effect.ALLOW
        or (decision.effect is Effect.REQUIRE_APPROVAL and ctx.approval_id)
    ):
        return
    log.error(
        "dispatch_without_decision",
        call_id=ctx.call_id,
        tool=ctx.tool.name,
        effect=decision.effect.value if decision else None,
    )
    raise Reject(
        Code.DENIED,
        "no decision allows this call to run (no-decision)",
        {"keystone/reason": NO_DECISION},
    )


class Pipeline:
    def __init__(
        self,
        interceptors: list[Interceptor],
        dispatcher: Dispatcher,
        audit: AuditSink,
        tracer: Tracer,
        *,
        fail_closed: bool = False,
        metrics: Metrics | None = None,
    ) -> None:
        self.interceptors = interceptors
        self.dispatcher = dispatcher
        self.audit = audit
        self.tracer = tracer
        self.fail_closed = fail_closed
        self.metrics = metrics
        # A plain counter until Phase 5 adds a metric.
        self.audit_failures = 0

    async def run(self, ctx: CallContext) -> ToolResult:
        reject: Reject | None = None
        # A cancelled call (the client went away) never reaches a line that sets the outcome.
        outcome: Outcome = "error"
        started = time.perf_counter()
        with self.tracer.tool_call(ctx) as span:
            try:
                try:
                    self._require_audit(ctx)
                    validate_arguments(ctx)
                    for interceptor in self.interceptors:
                        await self._hook(interceptor, interceptor.before_call, ctx, Code.DENIED)
                    require_dispatch_decision(ctx)
                    ctx.dispatched = True
                    ctx.result = await self._dispatch(ctx)
                    for interceptor in self.interceptors:
                        await self._hook(
                            interceptor, interceptor.after_call, ctx, Code.OUTPUT_BLOCKED
                        )
                    if ctx.result is None:
                        raise _Crash(Code.OUTPUT_BLOCKED, CRASH_MESSAGE)
                    outcome = "ok"
                except Reject as r:
                    reject = r
                    ctx.result = to_tool_result(r, ctx.call_id)
                    outcome = "error" if is_failure(r) else "rejected"
                return ctx.result
            finally:
                self._describe(span, ctx, outcome, reject)
                self._count(ctx, outcome, reject, started)
                await self._audit(ctx, outcome, reject)

    async def run_before(self, ctx: CallContext, slot: str, *, skip: Collection[str] = ()) -> None:
        """Run the `before_call` of every slot ahead of `slot` again, on a call that has waited.

        The approval slot holds a call for a person, for up to `approvals.wait_seconds`, and the
        slots ahead of it decided the call before the wait. In that time a tool can be
        quarantined, a policy reloaded, a budget spent, the audit log fall behind. The approval
        slot calls this once the person has approved and before it uses the approval, so a call
        is never dispatched on the strength of a check that is out of date.

        What a slot says is raised as it is: a refusal stops the call, and the approval is not
        used. A slot that crashes is a denial that says nothing of the cause, as in `run`. A slot
        in `skip` is left out: the rate limit charges a call once, when it arrives. A name that is
        no slot is an error before anything runs, so that a typo cannot make this check nothing.

        It decides again and changes `ctx` as the slots do (the decision above all), and it does
        not dispatch, run the after hooks or write the record: the call goes on in `run`.
        """
        names = [interceptor.name for interceptor in self.interceptors]
        if slot not in names:
            raise ValueError(f"no interceptor is named {slot!r}")
        unknown = sorted(set(skip) - set(names))
        if unknown:
            raise ValueError(f"no interceptor is named {', '.join(map(repr, unknown))}")
        self._require_audit(ctx)
        for interceptor in self.interceptors[: names.index(slot)]:
            if interceptor.name not in skip:
                await self._hook(interceptor, interceptor.before_call, ctx, Code.DENIED)

    async def reject(self, ctx: CallContext, reject: Reject) -> ToolResult:
        """Refuse a call that cannot enter the pipeline (a tool that does not exist). The
        refusal is still audited, so every call leaves one record (invariant I2)."""
        started = time.perf_counter()
        with self.tracer.tool_call(ctx) as span:
            try:
                ctx.result = to_tool_result(reject, ctx.call_id)
                return ctx.result
            finally:
                self._describe(span, ctx, "rejected", reject)
                self._count(ctx, "rejected", reject, started)
                await self._audit(ctx, "rejected", reject)

    def _count(
        self, ctx: CallContext, outcome: Outcome, reject: Reject | None, started: float
    ) -> None:
        """The call's counters and total time. A metric that fails to write never fails a call."""
        if self.metrics is None:
            return
        try:
            self.metrics.call_finished(ctx, outcome, reject, time.perf_counter() - started)
        except Exception:
            log.error("metrics_failed", call_id=ctx.call_id, exc_info=True)

    @staticmethod
    def _describe(
        span: SpanHandle, ctx: CallContext, outcome: Outcome, reject: Reject | None
    ) -> None:
        """What the root span says of the call once it is over: identifiers and verdicts. The
        arguments and the user's id are not on a span (KS-504)."""
        span.set("keystone.outcome", outcome)
        decision = ctx.decision
        if decision is not None:
            span.set("keystone.decision.effect", decision.effect.value)
            span.set("keystone.decision.reasons", list(decision.reasons))
        if reject is not None:
            span.set("keystone.reject_code", reject.code.value)
        if outcome == "error":
            span.fail(CALL_FAILED)

    def _require_audit(self, ctx: CallContext) -> None:
        """Raise Reject(DENIED) when the pipeline fails closed and the audit sink says it may
        lose records. It runs before any interceptor, so nothing is decided or dispatched."""
        if not self.fail_closed:
            return
        try:
            healthy = self.audit.healthy()
        except Exception:
            log.error("audit_health_check_failed", call_id=ctx.call_id, exc_info=True)
            healthy = False
        if healthy:
            return
        log.warning("audit_unavailable", call_id=ctx.call_id, tool=ctx.tool.name)
        raise Reject(Code.DENIED, "audit unavailable", {"keystone/reason": AUDIT_UNAVAILABLE})

    async def _hook(
        self,
        interceptor: Interceptor,
        hook: Callable[[CallContext], Awaitable[None]],
        ctx: CallContext,
        crash_code: Code,
    ) -> None:
        started = time.perf_counter()
        try:
            # A hook marked `noop_hook` has no span: it has nothing to show (KS-992).
            with (
                contextlib.nullcontext(NO_SPAN)
                if is_noop(hook)
                else self.tracer.span(
                    f"keystone.interceptor.{interceptor.name}", {"keystone.hook": hook.__name__}
                )
            ) as span:
                try:
                    await hook(ctx)
                except Reject:
                    raise
                except Exception:
                    span.fail(INTERCEPTOR_FAILED)
                    raise
        except Reject:
            raise
        except Exception:
            log.exception(
                "interceptor_crashed",
                call_id=ctx.call_id,
                interceptor=interceptor.name,
                hook=hook.__name__,
            )
            raise _Crash(crash_code, CRASH_MESSAGE) from None
        finally:
            elapsed = (time.perf_counter() - started) * 1000
            ctx.timings_ms[interceptor.name] = ctx.timings_ms.get(interceptor.name, 0.0) + elapsed
            self._observe_stage(interceptor.name, elapsed / 1000)

    async def _dispatch(self, ctx: CallContext) -> ToolResult:
        started = time.perf_counter()
        try:
            with self.tracer.span(
                "keystone.upstream.call", {"keystone.upstream": ctx.tool.upstream_id}, kind="client"
            ) as span:
                try:
                    return await self.dispatcher.dispatch(ctx)
                except Reject as refusal:
                    span.set("keystone.reject_code", refusal.code.value)
                    if is_failure(refusal):
                        span.fail(UPSTREAM_FAILED)
                        self._upstream_failed(ctx, upstream_error_kind(ctx, refusal))
                    raise
                except Exception:
                    span.fail(UPSTREAM_FAILED)
                    self._upstream_failed(ctx, "error")
                    raise
        except Reject:
            raise
        except Exception:
            # The exception text can hold a URL, a header or a path. The agent gets none of it.
            log.exception("dispatch_failed", call_id=ctx.call_id, tool=ctx.tool.name)
            raise Reject(Code.UPSTREAM_ERROR, "the upstream server failed to answer") from None
        finally:
            elapsed = time.perf_counter() - started
            ctx.timings_ms["dispatch"] = elapsed * 1000
            self._observe_stage("upstream", elapsed)

    def _observe_stage(self, stage: str, seconds: float) -> None:
        if self.metrics is None:
            return
        try:
            self.metrics.stage(stage, seconds)
        except Exception:
            log.error("metrics_failed", stage=stage, exc_info=True)

    def _upstream_failed(self, ctx: CallContext, kind: str) -> None:
        if self.metrics is None:
            return
        try:
            self.metrics.upstream_error(ctx.tool.upstream_id, kind)
        except Exception:
            log.error("metrics_failed", upstream=ctx.tool.upstream_id, exc_info=True)

    async def _audit(self, ctx: CallContext, outcome: Outcome, reject: Reject | None) -> None:
        # Shielded: a cancelled call still owes the audit trail its one record.
        with anyio.CancelScope(shield=True):
            try:
                await self.audit.record(ctx, outcome, reject)
            except Exception:
                self.audit_failures += 1
                log.error("audit_record_failed", call_id=ctx.call_id, exc_info=True)


def upstream_error_kind(ctx: CallContext, reject: Reject) -> str:
    """How an upstream failed, for the metric: it timed out, it was refused without a try because
    it is marked down (the dispatcher clears `dispatched` for that), or it answered badly."""
    if reject.code is Code.UPSTREAM_TIMEOUT:
        return "timeout"
    return "error" if ctx.dispatched else "down"


def is_failure(reject: Reject) -> bool:
    """Audit outcome "error" means Keystone or the upstream failed. "rejected" means it refused."""
    return isinstance(reject, _Crash) or reject.code in (Code.UPSTREAM_ERROR, Code.UPSTREAM_TIMEOUT)
