"""Budgets: hard caps on spend, checked before a call runs (KS-805, ADR-0014).

A budget is a limit in dollars for one tenant, one user or one agent over a day or a month, counted
in UTC. Before a call, the pre-check adds the tool's price to what has been spent in each window
that applies to the caller, and refuses the call if any sum is over its limit. The money is not
spent yet at that point, which is the reason for checking there: after the call it is.

Where the numbers live. The ledger (Postgres) is the record, one row for each charge. The
counters (Redis, `INCRBYFLOAT`) are a cache of it that the pre-check can read in one round trip.
That is the whole of the design:

- a charge is written to the ledger first, then added to the counters, so a counter is never ahead
  of what the ledger can prove (except when the ledger write works and Redis fails afterwards, where
  the next start repairs it);
- at startup every counter of the current windows is raised to what the ledger says, and never
  lowered, so a Redis that lost its data, or a second process that already counted, is never undone;
- a counter that is missing when the pre-check needs it (Redis restarted while Keystone ran) is read
  back from the ledger on the spot, so a Redis restart cannot reset anyone's spend to zero.

A charge is added to the windows its call began in. A call that began before midnight and ended
after it is charged to the day it began.

The check is not a reservation: two calls that are checked together both see the same spend, and
each may pass when only one fits. A cap is overshot by at most the price of the calls that were in
flight at once. The alternative, holding the money while the call runs, would need to be given back
whenever a later slot refuses the call, and the pipeline has no hook for that.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, Protocol

import structlog
from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.ids import new_id
from keystone.core.types import Principal
from keystone.db.models import BudgetRow
from keystone.metering.ledger import LedgerEntry, LedgerStore
from keystone.settings import BudgetConfig
from keystone.telemetry.metrics import Metrics

log = structlog.get_logger()

Scope = Literal["tenant", "user", "agent"]
Window = Literal["day", "month"]

KEY_PREFIX = "ks:spend:"
# A counter is kept for the length of its window and a day more (plan section 3.7), so that a
# late reader of the window that just ended still finds it.
KEEP_AFTER_WINDOW = timedelta(days=1)
NANO = Decimal("0.000000001")
REFRESH_S = 30.0
# The order budgets are checked in, and listed in.
_SCOPE_ORDER = {"tenant": 0, "user": 1, "agent": 2}
_WINDOW_ORDER = {"day": 0, "month": 1}


class BudgetConfigError(ValueError):
    """The budgets in the config cannot be applied. The message names every problem."""


def money(value: float | Decimal | str | int) -> Decimal:
    """An amount of dollars, read as the number it looks like and kept to nine decimal places. A
    float is read through its shortest text (0.1 is a tenth, not the nearest binary fraction), so
    a price in the config and the same price in the ledger are the same number."""
    try:
        amount = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"money is a number of dollars, not {value!r}") from None
    if not amount.is_finite():
        raise ValueError(f"money is a number of dollars, not {value!r}")
    return amount.quantize(NANO)


def _utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("a moment needs a time zone; a window is counted in UTC")
    return moment.astimezone(UTC)


def window_start(window: Window, moment: datetime) -> datetime:
    """The start of the window that holds `moment`: midnight UTC of its day, or of the first of its
    month. The boundary belongs to the window that starts there."""
    at = _utc(moment)
    if window == "day":
        return at.replace(hour=0, minute=0, second=0, microsecond=0)
    return at.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def window_end(window: Window, start: datetime) -> datetime:
    """The start of the next window: when the spend of this one is forgotten."""
    if window == "day":
        return start + timedelta(days=1)
    first = start.replace(day=1)
    return (first + timedelta(days=32)).replace(day=1)


def plain(amount: Decimal) -> str:
    """Digits with no exponent and no trailing zeros: 0.02, as `INCRBYFLOAT` writes it."""
    return format(amount.normalize(), "f")


def _expire_at(end: datetime) -> int:
    return int((end + KEEP_AFTER_WINDOW).timestamp())


def counter_key(budget: Budget, start: datetime) -> str:
    """`ks:spend:{tenant}:{scope}:{id}:{window}:{start}`. The window is part of the last field,
    since the first of a month starts a day and a month, which are two counters. A colon in an id
    would let one key pass for another, so it is written %3A."""
    scope_id = budget.scope_id.replace("%", "%25").replace(":", "%3A")
    return (
        f"{KEY_PREFIX}{budget.tenant_id}:{budget.scope}:{scope_id}:"
        f"{budget.window}:{start.date().isoformat()}"
    )


@dataclass(frozen=True)
class Budget:
    tenant_id: str
    scope: Scope
    scope_id: str
    window: Window
    limit_usd: Decimal

    def applies_to(self, tenant_id: str, user_id: str, agent_id: str) -> bool:
        if self.tenant_id != tenant_id:
            return False
        if self.scope == "tenant":
            return True
        return self.scope_id == (user_id if self.scope == "user" else agent_id)

    def sort_key(self) -> tuple[int, str, int]:
        return (_SCOPE_ORDER[self.scope], self.scope_id, _WINDOW_ORDER[self.window])


class BudgetExceeded(Exception):
    """The call would take the spend over a limit. `spent` is what the window holds now and
    `projected` that plus the call's price."""

    def __init__(
        self, budget: Budget, *, spent: Decimal, projected: Decimal, resets_at: datetime
    ) -> None:
        super().__init__(f"{budget.scope} budget of {budget.limit_usd} is used up")
        self.budget = budget
        self.spent = spent
        self.projected = projected
        self.resets_at = resets_at


@dataclass(frozen=True)
class BudgetStatus:
    budget: Budget
    spent: Decimal
    window_start: datetime
    resets_at: datetime


@dataclass
class SyncReport:
    created: int = 0
    updated: int = 0
    removed: int = 0


@dataclass(frozen=True)
class Increment:
    key: str
    amount: Decimal
    expire_at: int


class BudgetStore(Protocol):
    """The `budgets` table."""

    async def load(self) -> list[Budget]: ...

    async def sync(self, wanted: Sequence[Budget]) -> SyncReport:
        """Make the table hold exactly `wanted`: add, change and remove."""
        ...


class Counters(Protocol):
    """The running totals of the current windows, by key."""

    async def read(self, keys: Sequence[str]) -> list[Decimal | None]:
        """The total of each key, or None for a key that does not exist."""
        ...

    async def add(self, increments: Sequence[Increment]) -> list[Decimal]:
        """Add each amount to its key, set the key to expire, and return the new totals."""
        ...

    async def raise_to(self, key: str, value: Decimal, expire_at: int) -> Decimal:
        """Set the key to `value` unless it already holds more, and return what it holds."""
        ...


class MemoryBudgets:
    def __init__(self, budgets: Iterable[Budget] = ()) -> None:
        self._rows = {self._key(b): b for b in budgets}

    @staticmethod
    def _key(b: Budget) -> tuple[str, str, str, str]:
        return (b.tenant_id, b.scope, b.scope_id, b.window)

    async def load(self) -> list[Budget]:
        return list(self._rows.values())

    async def sync(self, wanted: Sequence[Budget]) -> SyncReport:
        report = SyncReport()
        keep = {self._key(b): b for b in wanted}
        for key, budget in keep.items():
            before = self._rows.get(key)
            if before is None:
                report.created += 1
            elif before.limit_usd != budget.limit_usd:
                report.updated += 1
        report.removed = len(set(self._rows) - set(keep))
        self._rows = keep
        return report


class PostgresBudgets:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    @staticmethod
    def _of(row: BudgetRow) -> Budget:
        return Budget(
            tenant_id=row.tenant_id,
            scope=row.scope,  # type: ignore[arg-type]
            scope_id=row.scope_id,
            window=row.window,  # type: ignore[arg-type]
            limit_usd=Decimal(row.limit_usd),
        )

    async def load(self) -> list[Budget]:
        async with self._sessionmaker() as session:
            rows = (await session.scalars(select(BudgetRow))).all()
        return [self._of(row) for row in rows]

    async def sync(self, wanted: Sequence[Budget]) -> SyncReport:
        report = SyncReport()
        async with self._sessionmaker() as session, session.begin():
            existing = {
                (r.tenant_id, r.scope, r.scope_id, r.window): r
                for r in (await session.scalars(select(BudgetRow))).all()
            }
            for budget in wanted:
                key = (budget.tenant_id, budget.scope, budget.scope_id, budget.window)
                before = existing.pop(key, None)
                if before is None:
                    report.created += 1
                elif Decimal(before.limit_usd) != budget.limit_usd:
                    report.updated += 1
                # An upsert, so that two processes starting together do not clash on the row.
                insertion = insert(BudgetRow).values(
                    id=new_id(),
                    tenant_id=budget.tenant_id,
                    scope=budget.scope,
                    scope_id=budget.scope_id,
                    window=budget.window,
                    limit_usd=budget.limit_usd,
                )
                await session.execute(
                    insertion.on_conflict_do_update(
                        constraint="uq_budgets_scope",
                        set_={"limit_usd": insertion.excluded.limit_usd},
                    )
                )
            for row in existing.values():
                log.warning(
                    "budget_removed",
                    tenant=row.tenant_id,
                    scope=row.scope,
                    scope_id=row.scope_id,
                    window=row.window,
                )
                await session.execute(delete(BudgetRow).where(BudgetRow.id == row.id))
                report.removed += 1
        return report


class MemoryCounters:
    def __init__(self) -> None:
        self.values: dict[str, Decimal] = {}
        self.reads = 0

    async def read(self, keys: Sequence[str]) -> list[Decimal | None]:
        self.reads += 1
        return [self.values.get(key) for key in keys]

    async def add(self, increments: Sequence[Increment]) -> list[Decimal]:
        for item in increments:
            self.values[item.key] = self.values.get(item.key, Decimal(0)) + item.amount
        return [self.values[item.key] for item in increments]

    async def raise_to(self, key: str, value: Decimal, expire_at: int) -> Decimal:
        if key not in self.values or self.values[key] < value:
            self.values[key] = value
        return self.values[key]


# KEYS[1] the counter. ARGV[1] the value to reach, as plain digits, ARGV[2] when the counter
# expires (epoch seconds). Sets the counter when it is missing or lower, and returns what it holds.
RAISE_SCRIPT = """
local current = tonumber(redis.call('GET', KEYS[1]))
if current == nil or current < tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], ARGV[1])
end
redis.call('EXPIREAT', KEYS[1], ARGV[2])
return redis.call('GET', KEYS[1])
"""


def _decimal(value: Any) -> Decimal:
    text = value.decode() if isinstance(value, bytes) else str(value)
    return Decimal(text).quantize(NANO)


class RedisCounters:
    """Totals as plain Redis strings under `ks:spend:...` (plan section 3.7), moved with
    `INCRBYFLOAT`. Redis keeps a decimal text, so 0.01 three times is 0.03 and not a float's
    0.030000000000000002; the text is read back as a Decimal."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        self._raise = redis.register_script(RAISE_SCRIPT)

    async def read(self, keys: Sequence[str]) -> list[Decimal | None]:
        if not keys:
            return []
        found = await self._redis.mget(list(keys))
        return [None if value is None else _decimal(value) for value in found]

    async def add(self, increments: Sequence[Increment]) -> list[Decimal]:
        if not increments:
            return []
        async with self._redis.pipeline(transaction=True) as pipe:
            for item in increments:
                pipe.execute_command("INCRBYFLOAT", item.key, plain(item.amount))
                pipe.execute_command("EXPIREAT", item.key, item.expire_at)
            replies = await pipe.execute()
        return [_decimal(value) for value in replies[0::2]]

    async def raise_to(self, key: str, value: Decimal, expire_at: int) -> Decimal:
        reply = await self._raise(keys=[key], args=[plain(value), expire_at])
        return _decimal(reply)


class BudgetService:
    def __init__(
        self,
        store: BudgetStore,
        ledger: LedgerStore,
        counters: Counters,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        metrics: Metrics | None = None,
        refresh_s: float = REFRESH_S,
    ) -> None:
        self._store = store
        self._ledger = ledger
        self._counters = counters
        self._clock = clock
        self._metrics = metrics
        self._refresh_s = refresh_s
        self._by_tenant: dict[str, list[Budget]] = {}
        self._loaded_at: float | None = None
        # (tenant, scope, window) -> (start of the window, the highest spend seen in it), for the
        # gauge.
        self._highest: dict[tuple[str, str, str], tuple[datetime, Decimal]] = {}

    # -- the budgets

    async def start(
        self, configured: Sequence[BudgetConfig], tenant_ids: Iterable[str]
    ) -> SyncReport:
        """Store the budgets of the config, drop the ones that are not in it, load them and set the
        counters of the current windows from the ledger. Raises BudgetConfigError before anything is
        written when a budget names a tenant that is not listed."""
        known = set(tenant_ids)
        problems = [
            f"the budget for {c.scope} {c.scope_id!r} names tenant {c.tenant!r}, "
            "which is not in `tenants`"
            for c in configured
            if c.tenant not in known
        ]
        if problems:
            raise BudgetConfigError("; ".join(problems))
        wanted = [
            Budget(c.tenant, c.scope, c.scope_id or c.tenant, c.window, money(c.limit_usd))
            for c in configured
        ]
        report = await self._store.sync(wanted)
        await self._reload()
        try:
            await self.rebuild()
        except Exception as error:
            # The counters are a cache. A pre-check that finds one missing reads the ledger itself.
            log.error("budget_rebuild_failed", error=type(error).__name__)
        log.info(
            "budgets_applied",
            created=report.created,
            updated=report.updated,
            removed=report.removed,
        )
        return report

    async def _reload(self) -> None:
        found: dict[str, list[Budget]] = {}
        for budget in sorted(await self._store.load(), key=Budget.sort_key):
            found.setdefault(budget.tenant_id, []).append(budget)
        self._by_tenant = found
        self._loaded_at = time.monotonic()

    async def budgets_for(self, tenant_id: str) -> list[Budget]:
        """The tenant's budgets, in the order they are checked. They are read again every
        `refresh_s`, so a change made in the table reaches a running Keystone within that time."""
        if self._loaded_at is None or time.monotonic() - self._loaded_at >= self._refresh_s:
            await self._reload()
        return self._by_tenant.get(tenant_id, [])

    # -- the counters

    def _window(self, budget: Budget, at: datetime) -> tuple[datetime, datetime, str]:
        start = window_start(budget.window, at)
        end = window_end(budget.window, start)
        return start, end, counter_key(budget, start)

    async def _total(self, budget: Budget, start: datetime, end: datetime) -> Decimal:
        return await self._ledger.total(
            budget.tenant_id,
            start,
            end,
            user_id=budget.scope_id if budget.scope == "user" else None,
            agent_id=budget.scope_id if budget.scope == "agent" else None,
        )

    async def rebuild(self) -> int:
        """Raise the counter of every budget, for the window it is in now, to what the ledger holds.
        A counter that holds more is left as it is. Returns how many budgets it looked at."""
        at = self._clock()
        looked = 0
        for budgets in list(self._by_tenant.values()):
            for budget in budgets:
                start, end, key = self._window(budget, at)
                total = await self._total(budget, start, end)
                held = await self._counters.raise_to(key, money(total), _expire_at(end))
                self._observe(budget, start, held)
                looked += 1
        return looked

    async def _spent(
        self, budgets: Sequence[Budget], at: datetime
    ) -> list[tuple[Decimal, datetime, datetime]]:
        """What each budget's window holds: the spend, the start of the window and its end. A
        counter that is not there is read from the ledger and stored."""
        windows = [self._window(b, at) for b in budgets]
        held = await self._counters.read([key for _, _, key in windows])
        found: list[tuple[Decimal, datetime, datetime]] = []
        for budget, (start, end, key), value in zip(budgets, windows, held, strict=True):
            if value is None:
                value = await self._counters.raise_to(
                    key, money(await self._total(budget, start, end)), _expire_at(end)
                )
            found.append((value, start, end))
        return found

    # -- the pre-check

    async def check(self, principal: Principal, cost: float | Decimal) -> None:
        """Raise BudgetExceeded when the price of one more call would take any budget that applies
        to the caller over its limit. Nothing is held back: this only reads."""
        price = money(cost)
        if price <= 0:
            return  # a call that costs nothing spends nothing, and no budget can stop it
        budgets = [
            b
            for b in await self.budgets_for(principal.tenant_id)
            if b.applies_to(principal.tenant_id, principal.user_id, principal.agent_id)
        ]
        if not budgets:
            return
        for budget, (spent, _start, end) in zip(
            budgets, await self._spent(budgets, self._clock()), strict=True
        ):
            if spent + price > budget.limit_usd:
                raise BudgetExceeded(budget, spent=spent, projected=spent + price, resets_at=end)

    # -- recording

    async def record(self, entry: LedgerEntry) -> bool:
        """Write the charge to the ledger and add it to the counters of the budgets that apply.
        False, and nothing counted, when this call is in the ledger already."""
        if not await self._ledger.insert(entry):
            return False
        if entry.cost_usd <= 0:
            return True
        budgets = [
            b
            for b in await self.budgets_for(entry.tenant_id)
            if b.applies_to(entry.tenant_id, entry.user_id, entry.agent_id)
        ]
        if not budgets:
            return True
        windows = [self._window(b, entry.ts) for b in budgets]
        totals = await self._counters.add(
            [Increment(key, entry.cost_usd, _expire_at(end)) for (_start, end, key) in windows]
        )
        for budget, (start, _end, _key), total in zip(budgets, windows, totals, strict=True):
            self._observe(budget, start, total)
        return True

    # -- what the admin API and the gauge show

    async def status(self, tenant_id: str) -> list[BudgetStatus]:
        budgets = await self.budgets_for(tenant_id)
        if not budgets:
            return []
        shown: list[BudgetStatus] = []
        for budget, (spent, start, end) in zip(
            budgets, await self._spent(budgets, self._clock()), strict=True
        ):
            self._observe(budget, start, spent)
            shown.append(BudgetStatus(budget, spent, start, end))
        return shown

    def _observe(self, budget: Budget, start: datetime, spent: Decimal) -> None:
        """Keep the gauge at the highest spend, in the window it is in, among a scope's budgets."""
        if self._metrics is None:
            return
        key = (budget.tenant_id, budget.scope, budget.window)
        before = self._highest.get(key)
        highest = spent if before is None or before[0] != start else max(before[1], spent)
        self._highest[key] = (start, highest)
        top = max(
            value
            for (tenant, scope, _), (_, value) in self._highest.items()
            if (tenant, scope) == (budget.tenant_id, budget.scope)
        )
        try:
            self._metrics.budget_spent(budget.tenant_id, budget.scope, float(top))
        except Exception:
            log.error("metrics_failed", exc_info=True)


def usd(amount: Decimal) -> str:
    """Dollars for a person: two decimals at least, and as many more as the amount has."""
    text = plain(amount)
    whole, _, cents = text.partition(".")
    return f"${whole}.{cents.ljust(2, '0')}"


def seconds_until(moment: datetime, now: datetime) -> float:
    return max(0.0, math.ceil((moment - now).total_seconds()))
