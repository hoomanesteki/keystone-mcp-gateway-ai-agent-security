"""The pinning slot: a tool that is not active does not run (KS-205, invariant I4)."""

from __future__ import annotations

from typing import Protocol

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, ToolStatus
from keystone.registry.naming import is_virtual
from keystone.registry.pinning import reason_category
from keystone.registry.repo import ToolState


class ToolStateLookup(Protocol):
    async def tool_state(self, tenant_id: str, name: str) -> ToolState | None: ...


class PinningInterceptor:
    """Refuse a call to a tool that is quarantined or disabled.

    The gateway looks tools up in a cache that can be a couple of seconds old. A quarantine made
    by another process (the CLI) must stop the next call, not the one after the cache expires,
    so this asks the database for the tool's status itself. If it cannot, the call fails: the
    pipeline turns an interceptor that raises into a denial.
    """

    name = "pinning"

    def __init__(self, states: ToolStateLookup | None = None) -> None:
        self._states = states

    async def before_call(self, ctx: CallContext) -> None:
        if is_virtual(ctx.tool):
            return  # Keystone's own tools have no registry row to pin
        status, reason = ctx.tool.status, None
        if self._states is not None:
            state = await self._states.tool_state(ctx.tool.tenant_id, ctx.tool.name)
            if state is None:
                raise Reject(Code.TOOL_NOT_FOUND, f"there is no tool named {ctx.tool.name!r}")
            status, reason = state.status, state.reason
        if status is ToolStatus.ACTIVE:
            return
        # The category only: the agent is not told which screening rule fired.
        why = reason_category(reason)
        detail = f" ({why})" if why else ""
        raise Reject(
            Code.QUARANTINED,
            f"tool {ctx.tool.name} is {status.value}{detail} and cannot be called until a person "
            "reviews it",
            {"keystone/reason": why or status.value},
        )

    async def after_call(self, ctx: CallContext) -> None:
        return None
