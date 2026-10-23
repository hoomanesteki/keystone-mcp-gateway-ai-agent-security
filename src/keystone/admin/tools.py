"""Changing a tool by hand: approve a held definition, disable, enable (KS-205, KS-507).

The CLI and the admin API both call this, so approving a change through the API is the same
operation as the CLI's, with the same checks and the same messages. Nothing here knows who asks:
the caller has already checked that, and says which tenant.
"""

from __future__ import annotations

from collections.abc import Callable

import structlog

from keystone.core.types import ToolStatus
from keystone.db.models import Tool
from keystone.registry.pinning import OPERATOR_DISABLED, REMOVED
from keystone.registry.repo import PinningError, Sessionmaker, ToolRepo

log = structlog.get_logger()


class ToolNotFound(LookupError):
    """There is no such tool in the tenant."""


class ToolConflict(ValueError):
    """The tool is in a state that does not allow the change. The message says why."""


class ToolAdmin:
    def __init__(self, sessions: Sessionmaker, on_change: Callable[[], None] | None = None) -> None:
        self._tools = ToolRepo(sessions)
        # Told after every change, so a gateway in this process drops its cached list of tools.
        self._on_change = on_change

    async def get(self, tenant_id: str, name: str) -> Tool:
        found = await self._tools.get(tenant_id, name)
        if found is None:
            raise ToolNotFound(f"there is no tool {name!r} in tenant {tenant_id!r}")
        return found

    async def approve_change(
        self,
        tenant_id: str,
        name: str,
        *,
        expect: str | None = None,
        note: str | None = None,
        by: str | None = None,
    ) -> Tool:
        """Accept the pending definition of a quarantined tool and make the tool active. `expect`
        is the fingerprint of the definition that was looked at (a prefix will do)."""
        found = await self.get(tenant_id, name)
        try:
            row = await self._tools.approve_change(tenant_id, name, expect_hash=expect)
        except PinningError as exc:
            raise ToolConflict(str(exc)) from exc
        log.warning(
            "tool_change_approved",
            tool=name,
            tenant=tenant_id,
            was=found.quarantine_reason,
            description_hash=row.description_hash,
            note=note,
            by=by,
        )
        self._changed()
        return row

    async def disable(self, tenant_id: str, name: str) -> Tool:
        """Take a tool out of the list and refuse calls to it. Sync will not turn it back on."""
        found = await self.get(tenant_id, name)
        if found.status == ToolStatus.QUARANTINED.value:
            # It is out of service already. Disabling it would lose the fact that it awaits a
            # review, and `enable` would then put it back without one.
            raise ToolConflict(
                f"{name} is quarantined and cannot be called; review it with tool show"
            )
        await self._tools.set_status(tenant_id, name, ToolStatus.DISABLED, reason=OPERATOR_DISABLED)
        self._changed()
        return await self.get(tenant_id, name)

    async def enable(self, tenant_id: str, name: str) -> tuple[Tool, bool]:
        """Turn a tool an operator disabled back on. Returns the tool and whether it changed."""
        found = await self.get(tenant_id, name)
        if found.status == ToolStatus.ACTIVE.value:
            return found, False
        if found.status == ToolStatus.QUARANTINED.value:
            raise ToolConflict(f"{name} is quarantined: review it, then use approve-change")
        if found.quarantine_reason != OPERATOR_DISABLED:
            why = (
                "its upstream no longer lists it"
                if found.quarantine_reason == REMOVED
                else "it was not disabled by an operator"
            )
            raise ToolConflict(f"{name} cannot be enabled by hand: {why}")
        await self._tools.set_status(tenant_id, name, ToolStatus.ACTIVE)
        self._changed()
        return await self.get(tenant_id, name), True

    def _changed(self) -> None:
        if self._on_change is not None:
            self._on_change()
