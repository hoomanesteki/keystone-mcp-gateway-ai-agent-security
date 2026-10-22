"""Every tool call goes through Pipeline.run (plan section 3.4, ADR-0004).

Rules the code below keeps:
- The audit sink runs in `finally`, shielded from cancellation, so every call leaves one record
  (invariant I2).
- Nothing the agent sees contains exception text. A rejection carries the message its raiser
  wrote for the agent. Any other exception becomes a generic message and goes to the log.
- A hook that crashes fails closed: before the dispatch the call is denied, after it the
  output is blocked. The audit outcome for a crash is "error", not "rejected".
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Literal, Protocol

import anyio
import structlog
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from keystone.core.canonical import canonical_json
from keystone.core.errors import Code, Reject, to_tool_result
from keystone.core.types import CallContext, ToolResult
from keystone.telemetry.tracing import Tracer

log = structlog.get_logger()

MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_VALIDATION_MESSAGE = 300

CRASH_MESSAGE = "the gateway could not finish checking this call"

Outcome = Literal["ok", "rejected", "error"]


class Interceptor(Protocol):
    name: str

    async def before_call(self, ctx: CallContext) -> None: ...  # may raise Reject, may mutate ctx
    async def after_call(self, ctx: CallContext) -> None: ...  # may replace ctx.result


class Dispatcher(Protocol):
    async def dispatch(self, ctx: CallContext) -> ToolResult: ...


class AuditSink(Protocol):
    async def record(self, ctx: CallContext, outcome: Outcome, reject: Reject | None) -> None: ...


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


class Pipeline:
    def __init__(
        self,
        interceptors: list[Interceptor],
        dispatcher: Dispatcher,
        audit: AuditSink,
        tracer: Tracer,
    ) -> None:
        self.interceptors = interceptors
        self.dispatcher = dispatcher
        self.audit = audit
        self.tracer = tracer
        # A plain counter until Phase 5 adds a metric.
        self.audit_failures = 0

    async def run(self, ctx: CallContext) -> ToolResult:
        reject: Reject | None = None
        # A cancelled call (the client went away) never reaches a line that sets the outcome.
        outcome: Outcome = "error"
        with self.tracer.span("pipeline.run", call_id=ctx.call_id, tool=ctx.tool.name):
            try:
                try:
                    validate_arguments(ctx)
                    for interceptor in self.interceptors:
                        await self._hook(interceptor, interceptor.before_call, ctx, Code.DENIED)
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
                await self._audit(ctx, outcome, reject)

    async def _hook(
        self,
        interceptor: Interceptor,
        hook: Callable[[CallContext], Awaitable[None]],
        ctx: CallContext,
        crash_code: Code,
    ) -> None:
        started = time.perf_counter()
        try:
            with self.tracer.span(f"interceptor.{interceptor.name}.{hook.__name__}"):
                await hook(ctx)
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

    async def _dispatch(self, ctx: CallContext) -> ToolResult:
        started = time.perf_counter()
        try:
            with self.tracer.span("dispatch", upstream=ctx.tool.upstream_id):
                return await self.dispatcher.dispatch(ctx)
        except Reject:
            raise
        except Exception:
            # The exception text can hold a URL, a header or a path. The agent gets none of it.
            log.exception("dispatch_failed", call_id=ctx.call_id, tool=ctx.tool.name)
            raise Reject(Code.UPSTREAM_ERROR, "the upstream server failed to answer") from None
        finally:
            ctx.timings_ms["dispatch"] = (time.perf_counter() - started) * 1000

    async def _audit(self, ctx: CallContext, outcome: Outcome, reject: Reject | None) -> None:
        # Shielded: a cancelled call still owes the audit trail its one record.
        with anyio.CancelScope(shield=True):
            try:
                await self.audit.record(ctx, outcome, reject)
            except Exception:
                self.audit_failures += 1
                log.error("audit_record_failed", call_id=ctx.call_id, exc_info=True)


def is_failure(reject: Reject) -> bool:
    """Audit outcome "error" means Keystone or the upstream failed. "rejected" means it refused."""
    return isinstance(reject, _Crash) or reject.code in (Code.UPSTREAM_ERROR, Code.UPSTREAM_TIMEOUT)
