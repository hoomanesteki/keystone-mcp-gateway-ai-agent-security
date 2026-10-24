"""The ledger of spend (KS-805, ADR-0014): the record of money that budgets are rebuilt from.

One row for each tool call that has a price and each model request. The row is written first and
the counters in Redis are moved after it, so a counter is never ahead of what the ledger can prove.
`(kind, ref)` is unique and a second record of the same call is ignored, which is what makes it safe
to try again after a failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Literal, Protocol

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.ids import new_id
from keystone.db.models import SpendLedger

Kind = Literal["tool", "llm"]


@dataclass(frozen=True)
class LedgerEntry:
    """What one call cost, and who paid. `ts` is the moment the call began and decides the window
    it belongs to. `ref` is the call id of a tool call, or the id of a model request."""

    ts: datetime
    tenant_id: str
    user_id: str
    agent_id: str
    kind: Kind
    ref: str
    cost_usd: Decimal
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    id: str = field(default_factory=new_id)

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError("a ledger entry needs a time with a time zone")
        if not self.cost_usd.is_finite() or self.cost_usd < 0:
            raise ValueError(f"a cost is 0 or more dollars, not {self.cost_usd!r}")


class LedgerStore(Protocol):
    async def insert(self, entry: LedgerEntry) -> bool:
        """Add the entry. False, with nothing changed, when this call is in the ledger already."""
        ...

    async def total(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
    ) -> Decimal:
        """What the tenant spent from `start` up to, and not including, `end`; of one user or one
        agent when it is given."""
        ...


class PostgresLedger:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def insert(self, entry: LedgerEntry) -> bool:
        statement = (
            insert(SpendLedger)
            .values(
                id=entry.id,
                ts=entry.ts,
                tenant_id=entry.tenant_id,
                user_id=entry.user_id,
                agent_id=entry.agent_id,
                kind=entry.kind,
                ref=entry.ref,
                model=entry.model,
                input_tokens=entry.input_tokens,
                output_tokens=entry.output_tokens,
                cost_usd=entry.cost_usd,
            )
            .on_conflict_do_nothing(constraint="uq_spend_ledger_ref")
            .returning(SpendLedger.id)
        )
        async with self._sessionmaker() as session, session.begin():
            return (await session.execute(statement)).first() is not None

    async def total(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
    ) -> Decimal:
        statement = select(func.coalesce(func.sum(SpendLedger.cost_usd), 0)).where(
            SpendLedger.tenant_id == tenant_id, SpendLedger.ts >= start, SpendLedger.ts < end
        )
        if user_id is not None:
            statement = statement.where(SpendLedger.user_id == user_id)
        if agent_id is not None:
            statement = statement.where(SpendLedger.agent_id == agent_id)
        async with self._sessionmaker() as session:
            return Decimal((await session.execute(statement)).scalar_one())


class MemoryLedger:
    """The same ledger in this process, for tests that need no database."""

    def __init__(self) -> None:
        self.entries: list[LedgerEntry] = []

    async def insert(self, entry: LedgerEntry) -> bool:
        if any((e.kind, e.ref) == (entry.kind, entry.ref) for e in self.entries):
            return False
        self.entries.append(entry)
        return True

    async def total(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
    ) -> Decimal:
        return sum(
            (
                e.cost_usd
                for e in self.entries
                if e.tenant_id == tenant_id
                and start <= e.ts < end
                and (user_id is None or e.user_id == user_id)
                and (agent_id is None or e.agent_id == agent_id)
            ),
            Decimal(0),
        )
