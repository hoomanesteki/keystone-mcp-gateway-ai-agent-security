"""Phase 1 stubs for every slot in the pipeline (plan section 3.4).

Each later phase replaces one class and keeps its name and position. The names below are the
slot keys that `build_pipeline` accepts as overrides.
"""

from __future__ import annotations

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ScanResult


class _Passthrough:
    name = ""

    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        return None


class RateLimitInterceptor(_Passthrough):
    name = "rate_limit"


class PinningInterceptor(_Passthrough):
    name = "pinning"


class BudgetInterceptor(_Passthrough):
    name = "budget"


class PolicyInterceptor(_Passthrough):
    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(effect=Effect.ALLOW, source="stub")


class ApprovalInterceptor(_Passthrough):
    name = "approval"

    async def before_call(self, ctx: CallContext) -> None:
        if ctx.decision is not None and ctx.decision.effect is Effect.REQUIRE_APPROVAL:
            raise Reject(Code.DENIED, "approval not available")


class OutputScanInterceptor(_Passthrough):
    name = "output_scan"

    async def after_call(self, ctx: CallContext) -> None:
        ctx.scan = ScanResult(score=0.0, label="benign", action="pass")


class SessionFlagsInterceptor(_Passthrough):
    name = "session_flags"


class MeteringInterceptor(_Passthrough):
    name = "metering"
