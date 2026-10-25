"""The metering slot: a call that ran is charged for (KS-805, ADR-0014).

After the upstream answers, the price of the tool is written on the call (`ctx.cost_usd`, which the
audit record keeps), recorded in the ledger and added to the counters of the budgets that apply,
and added to the session's spend. A tool with no price leaves no row and costs nothing.

It charges any call that was dispatched and came back with a result, including one that came back as
an error: the request reached the upstream and was answered, and a price per call is for the call.
A call that never reached the upstream (a refusal, a tool that is down) is not charged, and neither
are Keystone's own tools.

The session is changed with the store's own `add_spend` and the call's copy is then brought up to
date with what the store returned, as the other slots do (ADR-0015). Saving the copy would write
back a spend that is as old as the start of the call.

The ledger is written first and the counters second, so a counter is never ahead of the ledger. If
either fails the pipeline blocks the output (a crash after the dispatch), the audit record shows the
price, and the ledger tells which of the two happened. The record is idempotent on the call id.
"""

from __future__ import annotations

from typing import Protocol

from keystone.core.types import CallContext
from keystone.gateway.hooks import noop_hook
from keystone.gateway.sessions import SessionStore, catch_up
from keystone.metering.budgets import money
from keystone.metering.ledger import LedgerEntry
from keystone.registry.naming import is_virtual


class Recording(Protocol):
    async def record(self, entry: LedgerEntry) -> bool: ...


class MeteringInterceptor:
    name = "metering"

    def __init__(self, budgets: Recording | None, sessions: SessionStore | None = None) -> None:
        self._budgets = budgets
        self._sessions = sessions

    @noop_hook
    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        if not ctx.dispatched or is_virtual(ctx.tool):
            return
        price = ctx.tool.cost_per_call_usd
        ctx.cost_usd = price
        if price <= 0:
            return
        if self._budgets is not None:
            await self._budgets.record(
                LedgerEntry(
                    ts=ctx.received_at,
                    tenant_id=ctx.principal.tenant_id,
                    user_id=ctx.principal.user_id,
                    agent_id=ctx.principal.agent_id,
                    kind="tool",
                    ref=ctx.call_id,
                    cost_usd=money(price),
                )
            )
        session = ctx.session
        if self._sessions is not None:
            changed = await self._sessions.add_spend(session.session_id, price)
            if changed is not None:
                catch_up(session, changed)
                return
        # No store, or a session it does not have (a request with no session id has a throwaway
        # one): the call counts itself on the copy it has.
        session.spent_usd += price
