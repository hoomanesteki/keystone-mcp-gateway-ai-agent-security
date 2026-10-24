"""The budget slot: a call that would take the spend over a limit does not run (KS-805, ADR-0014).

It sits ahead of the policy and of the dispatch, and it asks `BudgetService.check` for the price of
one more call of this tool against every budget that applies to the caller. The money is spent when
the call runs, so this is the last place it can be stopped: the check is before the dispatch and
the upstream sees no request. A tool with no price is not held by a budget, and neither are
Keystone's own tools.

A call that waited for approval runs this slot a second time after the wait (`Pipeline.run_before`,
ADR-0010), so a budget spent while it waited still stops it.

The refusal is `KS_BUDGET_EXCEEDED`. Its data says which budget (`scope`, and the `window` it is
counted over), its `limit_usd`, what has been spent (`spent_usd`) and when the window ends
(`resets_at`, UTC). A budget service that fails raises, and the pipeline turns that into a denial:
a call that cannot be checked against a limit does not run without one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, Principal
from keystone.metering.budgets import BudgetExceeded, usd
from keystone.registry.naming import is_virtual

WHOSE = {"tenant": "organization's", "user": "user's", "agent": "agent's"}


class Budgeting(Protocol):
    async def check(self, principal: Principal, cost: float | Decimal) -> None: ...


def when(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def refusal(exceeded: BudgetExceeded) -> Reject:
    budget = exceeded.budget
    facts = {
        "scope": budget.scope,
        "window": budget.window,
        "limit_usd": float(budget.limit_usd),
        "spent_usd": float(exceeded.spent),
        "resets_at": when(exceeded.resets_at),
    }
    return Reject(
        Code.BUDGET_EXCEEDED,
        f"the {WHOSE[budget.scope]} budget of {usd(budget.limit_usd)} a {budget.window} would be "
        f"passed by this call ({usd(exceeded.spent)} spent); it resets at {facts['resets_at']}",
        # Only keys with this prefix reach the metadata of the result itself.
        {**facts, **{f"keystone/{key}": value for key, value in facts.items()}},
    )


class BudgetInterceptor:
    name = "budget"

    def __init__(self, budgets: Budgeting) -> None:
        self._budgets = budgets

    async def before_call(self, ctx: CallContext) -> None:
        if is_virtual(ctx.tool):
            return
        try:
            await self._budgets.check(ctx.principal, ctx.tool.cost_per_call_usd)
        except BudgetExceeded as exceeded:
            ctx.decision = Decision(
                effect=Effect.DENY,
                reasons=[f"budget:{exceeded.budget.scope}:{exceeded.budget.window}"],
                source="budget",
            )
            raise refusal(exceeded) from None

    async def after_call(self, ctx: CallContext) -> None:
        return None
