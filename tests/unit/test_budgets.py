"""KS-805 without Postgres or Redis: the windows, the counters, the pre-check and the two slots.

The service runs here over the in-memory ledger, store and counters, which follow the same
contracts as the real ones (tests/integration/test_budgets.py runs the same service over those).
"""

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from keystone.core.errors import Code, Reject
from keystone.core.types import Effect, Principal
from keystone.gateway.interceptors.budget import BudgetInterceptor
from keystone.gateway.interceptors.metering import MeteringInterceptor
from keystone.gateway.sessions import InMemorySessionStore
from keystone.metering.budgets import (
    Budget,
    BudgetConfigError,
    BudgetExceeded,
    BudgetService,
    MemoryBudgets,
    MemoryCounters,
    counter_key,
    money,
    window_end,
    window_start,
)
from keystone.metering.ledger import LedgerEntry, MemoryLedger
from keystone.settings import BudgetConfig, Settings
from keystone.telemetry.metrics import Metrics
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool

pytestmark = pytest.mark.phase(8)

NOON = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = NOON) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def budget(
    scope: str = "user", scope_id: str = "olivia", window: str = "day", limit: str = "0.03"
) -> Budget:
    return Budget(
        tenant_id="acme",
        scope=scope,  # type: ignore[arg-type]
        scope_id="acme" if scope == "tenant" else scope_id,
        window=window,  # type: ignore[arg-type]
        limit_usd=Decimal(limit),
    )


def service(
    *budgets: Budget, clock: Clock | None = None, metrics: Metrics | None = None
) -> tuple[BudgetService, MemoryLedger, MemoryCounters]:
    ledger, counters = MemoryLedger(), MemoryCounters()
    built = BudgetService(
        MemoryBudgets(budgets), ledger, counters, clock=clock or Clock(), metrics=metrics
    )
    return built, ledger, counters


def entry(
    ref: str,
    cost: str = "0.01",
    *,
    ts: datetime = NOON,
    user: str = "olivia",
    agent: str = "ops-agent",
    kind: str = "tool",
) -> LedgerEntry:
    return LedgerEntry(
        ts=ts,
        tenant_id="acme",
        user_id=user,
        agent_id=agent,
        kind=kind,  # type: ignore[arg-type]
        ref=ref,
        cost_usd=Decimal(cost),
    )


# -- windows, keys and money


def test_a_day_runs_from_midnight_utc_to_midnight_utc() -> None:
    start = window_start("day", datetime(2026, 10, 23, 15, 4, 5, 123456, tzinfo=UTC))

    assert start == datetime(2026, 10, 23, tzinfo=UTC)
    assert window_end("day", start) == datetime(2026, 10, 24, tzinfo=UTC)


@pytest.mark.parametrize(
    ("moment", "start", "end"),
    [
        (datetime(2026, 10, 23, 15, tzinfo=UTC), (2026, 10, 1), (2026, 11, 1)),
        (datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=UTC), (2026, 12, 1), (2027, 1, 1)),
        (datetime(2028, 2, 29, 12, tzinfo=UTC), (2028, 2, 1), (2028, 3, 1)),
        (datetime(2026, 2, 28, 12, tzinfo=UTC), (2026, 2, 1), (2026, 3, 1)),
        (datetime(2026, 11, 1, tzinfo=UTC), (2026, 11, 1), (2026, 12, 1)),
    ],
)
def test_a_month_runs_from_the_first_to_the_first(
    moment: datetime, start: tuple[int, int, int], end: tuple[int, int, int]
) -> None:
    found = window_start("month", moment)

    assert found == datetime(*start, tzinfo=UTC)
    assert window_end("month", found) == datetime(*end, tzinfo=UTC)


def test_the_boundary_belongs_to_the_window_that_starts_there() -> None:
    last = datetime(2026, 10, 23, 23, 59, 59, 999999, tzinfo=UTC)

    assert window_start("day", last) != window_start("day", last + timedelta(microseconds=1))
    assert window_start("day", last + timedelta(microseconds=1)) == datetime(
        2026, 10, 24, tzinfo=UTC
    )


def test_another_time_zone_is_read_as_the_moment_it_is() -> None:
    # 23:30 at UTC-5 is half past four the next morning in UTC.
    moment = datetime(2026, 10, 23, 23, 30, tzinfo=timezone(timedelta(hours=-5)))

    assert window_start("day", moment) == datetime(2026, 10, 24, tzinfo=UTC)


def test_a_time_with_no_zone_is_refused_not_guessed() -> None:
    with pytest.raises(ValueError, match="time zone"):
        window_start("day", datetime(2026, 10, 23, 12, 0))


def test_a_counter_key_names_the_tenant_the_scope_the_id_and_the_window() -> None:
    day = counter_key(budget("user", "olivia", "day"), datetime(2026, 10, 23, tzinfo=UTC))
    month = counter_key(budget("tenant", "acme", "month"), datetime(2026, 10, 1, tzinfo=UTC))

    assert day == "ks:spend:acme:user:olivia:day:2026-10-23"
    assert month == "ks:spend:acme:tenant:acme:month:2026-10-01"


def test_the_first_of_a_month_is_two_windows_with_two_keys() -> None:
    first = datetime(2026, 10, 1, tzinfo=UTC)

    assert counter_key(budget(window="day"), first) != counter_key(budget(window="month"), first)


def test_a_colon_in_an_id_cannot_make_one_key_look_like_another() -> None:
    plain = counter_key(budget("user", "a", "day"), datetime(2026, 10, 23, tzinfo=UTC))
    tricky = counter_key(
        budget("user", "a:day:2026-10-23", "day"), datetime(2026, 10, 23, tzinfo=UTC)
    )

    assert tricky.count(":") == plain.count(":")


def test_money_is_read_as_the_decimal_it_looks_like_and_kept_to_nine_places() -> None:
    assert money(0.01) == Decimal("0.01")
    assert money(0.1 + 0.2) == Decimal("0.3")
    assert money("0.0000000014") == Decimal("0.000000001")
    assert money(3) == Decimal(3)
    for bad in (float("nan"), float("inf"), "x"):
        with pytest.raises(ValueError, match="money"):
            money(bad)


# -- the pre-check


async def test_the_fourth_call_of_three_cents_is_the_one_that_is_refused() -> None:
    svc, _, _ = service(budget("user", "olivia", "day", "0.03"))
    one_cent = Decimal("0.01")

    for n in range(3):
        await svc.check(OLIVIA, one_cent)  # projected 0.01, 0.02, 0.03: not above the limit
        await svc.record(entry(f"call-{n}"))
    with pytest.raises(BudgetExceeded) as raised:
        await svc.check(OLIVIA, one_cent)

    refused = raised.value
    assert (refused.budget.scope, refused.budget.window) == ("user", "day")
    assert (refused.spent, refused.projected) == (Decimal("0.03"), Decimal("0.04"))
    assert refused.resets_at == datetime(2026, 10, 24, tzinfo=UTC)


async def test_a_call_with_no_price_is_never_held_by_a_budget() -> None:
    svc, _, _ = service(budget("user", "olivia", "day", "0.03"))
    for n in range(5):
        await svc.record(entry(f"call-{n}"))  # five cents against a limit of three

    await svc.check(OLIVIA, Decimal(0))  # does not raise


async def test_every_scope_that_matches_is_checked_and_the_first_to_fail_is_reported() -> None:
    svc, _, _ = service(
        budget("tenant", limit="1.00"),
        budget("user", "olivia", limit="0.02"),
        budget("agent", "ops-agent", limit="0.02"),
    )
    await svc.record(entry("a", "0.02"))

    with pytest.raises(BudgetExceeded) as raised:
        await svc.check(OLIVIA, Decimal("0.01"))

    # The tenant has room; the user's budget comes before the agent's.
    assert raised.value.budget.scope == "user"


async def test_a_month_budget_holds_when_the_day_budget_has_room() -> None:
    svc, _, _ = service(
        budget("user", "olivia", "day", "5.00"), budget("user", "olivia", "month", "0.02")
    )
    await svc.record(entry("a", "0.02"))

    with pytest.raises(BudgetExceeded) as raised:
        await svc.check(OLIVIA, Decimal("0.01"))

    assert raised.value.budget.window == "month"
    assert raised.value.resets_at == datetime(2026, 11, 1, tzinfo=UTC)


async def test_a_budget_of_someone_else_does_not_apply() -> None:
    svc, _, _ = service(
        budget("user", "alice", limit="0.01"), budget("agent", "support-agent", limit="0.01")
    )
    await svc.record(entry("a", "0.05", user="alice", agent="support-agent"))

    await svc.check(OLIVIA, Decimal("0.01"))  # olivia, through ops-agent


async def test_a_budget_of_another_tenant_does_not_apply() -> None:
    other = Budget("globex", "tenant", "globex", "day", Decimal("0.01"))
    svc, _, _ = service(other)

    await svc.check(OLIVIA, Decimal("1.00"))


async def test_no_budgets_means_nothing_is_read() -> None:
    svc, _, counters = service()

    await svc.check(OLIVIA, Decimal("1.00"))

    assert counters.reads == 0


async def test_spend_from_yesterday_does_not_count_today() -> None:
    svc, _, _ = service(budget("user", "olivia", "day", "0.03"))
    await svc.record(entry("old", "0.03", ts=NOON - timedelta(days=1)))

    await svc.check(OLIVIA, Decimal("0.03"))  # does not raise


async def test_the_window_resets_at_midnight_and_the_month_at_the_first() -> None:
    clock = Clock(datetime(2026, 10, 31, 23, 59, 30, tzinfo=UTC))
    svc, _, _ = service(
        budget("user", "olivia", "day", "0.03"),
        budget("user", "olivia", "month", "0.05"),
        clock=clock,
    )
    for n in range(3):
        await svc.record(entry(f"a{n}", ts=clock.now))
    with pytest.raises(BudgetExceeded) as day:
        await svc.check(OLIVIA, Decimal("0.01"))
    assert day.value.budget.window == "day"

    # Half a minute later it is the first of November, the 1st at 00:00:30.
    clock.now = datetime(2026, 11, 1, 0, 0, 30, tzinfo=UTC)
    await svc.check(OLIVIA, Decimal("0.01"))  # a new day and a new month: both empty

    # Spend that day, and the day budget fills again while the month's has its own count.
    for n in range(3):
        await svc.record(entry(f"b{n}", ts=clock.now))
    with pytest.raises(BudgetExceeded) as again:
        await svc.check(OLIVIA, Decimal("0.01"))
    assert (again.value.spent, again.value.budget.window) == (Decimal("0.03"), "day")
    # Next day: the day is empty and the month (0.03 of 0.05) has room for 0.01 but not 0.03.
    clock.now = datetime(2026, 11, 2, 0, 0, 1, tzinfo=UTC)
    await svc.check(OLIVIA, Decimal("0.01"))
    with pytest.raises(BudgetExceeded) as month:
        await svc.check(OLIVIA, Decimal("0.03"))
    assert month.value.budget.window == "month"


async def test_a_call_that_began_before_midnight_is_charged_to_that_day() -> None:
    clock = Clock(datetime(2026, 10, 23, 23, 59, 59, tzinfo=UTC))
    svc, _, _ = service(budget("user", "olivia", "day", "0.03"), clock=clock)
    began = clock.now

    # The call ends after midnight, and is recorded then, with the moment it began.
    clock.now = datetime(2026, 10, 24, 0, 0, 1, tzinfo=UTC)
    await svc.record(entry("late", "0.03", ts=began))

    # It filled the 23rd, and the 24th is empty.
    await svc.check(OLIVIA, Decimal("0.03"))
    clock.now = began
    with pytest.raises(BudgetExceeded):
        await svc.check(OLIVIA, Decimal("0.01"))


# -- recording


async def test_a_ledger_row_is_written_even_when_no_budget_counts_it() -> None:
    svc, ledger, counters = service()

    assert await svc.record(entry("a", "0.01")) is True

    assert [(e.ref, e.cost_usd) for e in ledger.entries] == [("a", Decimal("0.01"))]
    assert counters.values == {}


async def test_a_call_recorded_twice_is_counted_once() -> None:
    svc, ledger, counters = service(budget("user", "olivia", limit="1.00"))

    first = await svc.record(entry("same", "0.25"))
    again = await svc.record(entry("same", "0.25"))

    assert (first, again) == (True, False)
    assert len(ledger.entries) == 1
    assert list(counters.values.values()) == [Decimal("0.25")]


async def test_a_tool_call_and_a_model_request_may_share_a_ref_without_clashing() -> None:
    svc, ledger, _ = service()

    await svc.record(entry("01X", kind="tool"))
    await svc.record(entry("01X", kind="llm"))

    assert len(ledger.entries) == 2


async def test_the_counters_of_every_matching_budget_move_together() -> None:
    svc, _, counters = service(
        budget("tenant", limit="9"),
        budget("user", "olivia", "day", "9"),
        budget("user", "olivia", "month", "9"),
        budget("agent", "ops-agent", limit="9"),
        budget("user", "alice", limit="9"),
    )

    await svc.record(entry("a", "0.40"))
    await svc.record(entry("b", "0.35"))

    assert sorted(counters.values) == [
        "ks:spend:acme:agent:ops-agent:day:2026-10-23",
        "ks:spend:acme:tenant:acme:day:2026-10-23",
        "ks:spend:acme:user:olivia:day:2026-10-23",
        "ks:spend:acme:user:olivia:month:2026-10-01",
    ]
    assert set(counters.values.values()) == {Decimal("0.75")}


async def test_a_priced_amount_that_float_arithmetic_would_blur_stays_exact() -> None:
    svc, _, _ = service(budget("user", "olivia", limit="0.30"))
    for n in range(2):
        await svc.record(entry(f"a{n}", "0.10"))

    await svc.check(OLIVIA, money(0.1 + 0.0))  # 0.1 + 0.1 + 0.1 is 0.30000000000000004 in floats
    with pytest.raises(BudgetExceeded):
        await svc.check(OLIVIA, Decimal("0.100000001"))


# -- the counters are a cache of the ledger


async def test_a_flushed_counter_is_read_back_from_the_ledger_before_it_is_trusted() -> None:
    svc, ledger, counters = service(budget("user", "olivia", "day", "0.03"))
    for n in range(3):
        await svc.record(entry(f"a{n}"))
    counters.values.clear()  # Redis restarted: the counters are gone and the ledger is not

    with pytest.raises(BudgetExceeded) as raised:
        await svc.check(OLIVIA, Decimal("0.01"))

    assert raised.value.spent == Decimal("0.03")
    assert len(ledger.entries) == 3
    # And the counter is back, so the next check does not read the ledger again.
    assert list(counters.values.values()) == [Decimal("0.03")]


async def test_rebuild_sets_the_counters_of_the_current_windows_from_the_ledger() -> None:
    svc, _, counters = service(
        budget("tenant", limit="9"),
        budget("user", "olivia", "month", "9"),
        budget("agent", "x", limit="9"),
    )
    await svc.record(entry("today", "0.10"))
    await svc.record(entry("last-week", "0.20", ts=NOON - timedelta(days=7)))
    await svc.record(entry("last-month", "0.40", ts=NOON - timedelta(days=40)))
    counters.values.clear()

    rebuilt = await svc.rebuild()

    assert rebuilt == 3
    assert counters.values == {
        "ks:spend:acme:tenant:acme:day:2026-10-23": Decimal("0.10"),
        "ks:spend:acme:user:olivia:month:2026-10-01": Decimal("0.30"),
        "ks:spend:acme:agent:x:day:2026-10-23": Decimal(0),
    }


async def test_a_rebuild_never_lowers_a_counter_another_process_has_raised() -> None:
    svc, _, counters = service(budget("user", "olivia", limit="9"))
    await svc.record(entry("a", "0.10"))
    [key] = counters.values
    counters.values[key] = Decimal("0.50")  # another process counted a call the ledger will show

    await svc.rebuild()

    assert counters.values[key] == Decimal("0.50")


async def test_a_counter_that_is_missing_and_has_no_spend_is_stored_as_zero() -> None:
    svc, _, counters = service(budget("user", "olivia", limit="9"))

    await svc.check(OLIVIA, Decimal("0.01"))

    assert list(counters.values.values()) == [Decimal(0)]
    assert counters.reads == 1


# -- the status the admin API shows


async def test_status_lists_each_budget_with_its_spend_and_its_reset() -> None:
    svc, _, _ = service(
        budget("tenant", limit="25"),
        budget("user", "olivia", "month", "0.50"),
        budget("user", "alice"),
    )
    await svc.record(entry("a", "0.12"))

    shown = await svc.status("acme")

    assert [(s.budget.scope, s.budget.scope_id, s.budget.window) for s in shown] == [
        ("tenant", "acme", "day"),
        ("user", "alice", "day"),
        ("user", "olivia", "month"),
    ]
    by_scope = {(s.budget.scope, s.budget.scope_id): s for s in shown}
    assert by_scope[("tenant", "acme")].spent == Decimal("0.12")
    assert by_scope[("user", "alice")].spent == Decimal(0)
    month = by_scope[("user", "olivia")]
    assert month.spent == Decimal("0.12")
    assert (month.window_start, month.resets_at) == (
        datetime(2026, 10, 1, tzinfo=UTC),
        datetime(2026, 11, 1, tzinfo=UTC),
    )


async def test_status_of_another_tenant_shows_nothing_of_this_one() -> None:
    svc, _, _ = service(budget("tenant", limit="25"))

    assert await svc.status("globex") == []


async def test_the_gauge_follows_the_highest_spend_of_each_scope() -> None:
    metrics = Metrics(tenants=["acme"])
    svc, _, _ = service(
        budget("tenant", limit="9"),
        budget("user", "olivia", limit="9"),
        budget("user", "alice", limit="9"),
        metrics=metrics,
    )

    await svc.record(entry("a", "0.30"))
    await svc.record(entry("b", "0.45", user="alice"))

    page = metrics.render().decode()
    assert 'keystone_budget_spent_usd{scope="tenant",tenant="acme"} 0.75' in page
    assert 'keystone_budget_spent_usd{scope="user",tenant="acme"} 0.45' in page


# -- the budgets themselves


async def test_config_budgets_are_stored_and_the_ones_that_left_the_file_are_removed() -> None:
    store = MemoryBudgets()
    svc = BudgetService(store, MemoryLedger(), MemoryCounters(), clock=Clock())
    wanted = [
        BudgetConfig(tenant="acme", scope="tenant", window="day", limit_usd=Decimal("25")),
        BudgetConfig(
            tenant="acme", scope="user", scope_id="olivia", window="day", limit_usd=Decimal("1")
        ),
    ]

    first = await svc.start(wanted, ["acme"])
    second = await svc.start(wanted[:1], ["acme"])

    assert (first.created, first.removed) == (2, 0)
    assert (second.created, second.updated, second.removed) == (0, 0, 1)
    assert [(b.scope, b.scope_id) for b in await svc.budgets_for("acme")] == [("tenant", "acme")]


async def test_a_changed_limit_is_an_update() -> None:
    store = MemoryBudgets()
    svc = BudgetService(store, MemoryLedger(), MemoryCounters(), clock=Clock())
    config = BudgetConfig(tenant="acme", scope="tenant", window="day", limit_usd=Decimal("25"))
    await svc.start([config], ["acme"])

    report = await svc.start([config.model_copy(update={"limit_usd": Decimal("30")})], ["acme"])

    assert (report.updated, report.created) == (1, 0)
    [stored] = await svc.budgets_for("acme")
    assert stored.limit_usd == Decimal("30")


async def test_a_budget_of_a_tenant_that_is_not_listed_stops_startup() -> None:
    svc, _, _ = service()

    with pytest.raises(BudgetConfigError, match="initech"):
        await svc.start(
            [BudgetConfig(tenant="initech", scope="tenant", window="day", limit_usd=Decimal("1"))],
            ["acme"],
        )


def test_a_tenant_budget_takes_the_tenant_as_its_id() -> None:
    config = BudgetConfig(tenant="acme", scope="tenant", window="day", limit_usd=Decimal("25"))

    assert config.scope_id == "acme"


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"scope": "user"}, "scope_id"),
        ({"scope": "agent"}, "scope_id"),
        ({"scope": "tenant", "scope_id": "globex"}, "scope_id"),
        ({"limit_usd": Decimal(0)}, "limit_usd"),
        ({"limit_usd": Decimal("-1")}, "limit_usd"),
        ({"window": "week"}, "window"),
        ({"scope": "everyone"}, "scope"),
        ({"surprise": 1}, "surprise"),
    ],
)
def test_a_budget_that_makes_no_sense_is_refused(fields: dict[str, Any], message: str) -> None:
    base: dict[str, Any] = {
        "tenant": "acme",
        "scope": "tenant",
        "window": "day",
        "limit_usd": Decimal("1"),
    }

    with pytest.raises(ValueError, match=message):
        BudgetConfig(**{**base, **fields})


def test_the_same_budget_twice_is_refused_when_the_settings_load() -> None:
    twice = [
        {"tenant": "acme", "scope": "tenant", "window": "day", "limit_usd": 5},
        {"tenant": "acme", "scope": "tenant", "window": "day", "limit_usd": 9},
    ]

    with pytest.raises(ValueError, match="twice"):
        Settings(budgets=twice)  # type: ignore[arg-type]


def test_budgets_load_from_yaml(tmp_path: Any) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "budgets:\n"
        "  - {tenant: acme, scope: tenant, window: day, limit_usd: 25}\n"
        "  - {tenant: acme, scope: user, scope_id: lena, window: month, limit_usd: 0.03}\n"
    )

    settings = Settings(config_path=config)

    assert [(b.scope, b.scope_id, b.window, b.limit_usd) for b in settings.budgets] == [
        ("tenant", "acme", "day", Decimal("25")),
        ("user", "lena", "month", Decimal("0.03")),
    ]


# -- the two slots


class Booked:
    """What a slot is asked to record: stands in for the service."""

    def __init__(self, error: Exception | None = None) -> None:
        self.entries: list[LedgerEntry] = []
        self.checks: list[tuple[Principal, Decimal]] = []
        self.error = error

    async def check(self, principal: Principal, cost: Decimal | float) -> None:
        self.checks.append((principal, Decimal(str(cost))))
        if self.error is not None:
            raise self.error

    async def record(self, row: LedgerEntry) -> bool:
        self.entries.append(row)
        return True


def exceeded() -> BudgetExceeded:
    return BudgetExceeded(
        budget("user", "olivia", limit="0.03"),
        spent=Decimal("0.03"),
        projected=Decimal("0.04"),
        resets_at=datetime(2026, 10, 24, tzinfo=UTC),
    )


async def test_the_budget_slot_refuses_a_call_over_budget_before_anything_else_happens() -> None:
    ctx = make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.01))

    with pytest.raises(Reject) as raised:
        await BudgetInterceptor(Booked(exceeded())).before_call(ctx)  # type: ignore[arg-type]

    refusal = raised.value
    assert refusal.code is Code.BUDGET_EXCEEDED
    assert refusal.data["scope"] == "user"
    assert refusal.data["limit_usd"] == 0.03 and refusal.data["spent_usd"] == 0.03
    assert refusal.data["resets_at"] == "2026-10-24T00:00:00Z"
    assert refusal.data["window"] == "day"
    # Where a client reads the result's own metadata.
    assert refusal.data["keystone/scope"] == "user"
    assert refusal.data["keystone/resets_at"] == "2026-10-24T00:00:00Z"
    assert "$0.03" in refusal.message and "2026-10-24" in refusal.message
    assert ctx.decision is not None
    assert (ctx.decision.effect, ctx.decision.source) == (Effect.DENY, "budget")
    assert ctx.decision.reasons == ["budget:user:day"]


async def test_the_budget_slot_asks_with_the_price_of_the_tool() -> None:
    booked = Booked()
    ctx = make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.0024))

    await BudgetInterceptor(booked).before_call(ctx)  # type: ignore[arg-type]

    assert booked.checks == [(OLIVIA, Decimal("0.0024"))]


async def test_the_budget_slot_leaves_keystones_own_tools_alone() -> None:
    booked = Booked(exceeded())

    await BudgetInterceptor(booked).before_call(make_ctx({}, make_tool("keystone", "whoami")))  # type: ignore[arg-type]

    assert booked.checks == []


async def test_a_budget_service_that_fails_does_not_let_the_call_through() -> None:
    with pytest.raises(ConnectionError):
        await BudgetInterceptor(Booked(ConnectionError("redis is down"))).before_call(  # type: ignore[arg-type]
            make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.01))
        )


async def test_metering_records_the_price_of_a_call_that_was_dispatched() -> None:
    booked = Booked()
    ctx = make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.01), dispatched=True)

    await MeteringInterceptor(booked).after_call(ctx)  # type: ignore[arg-type]

    [row] = booked.entries
    assert (row.kind, row.ref, row.cost_usd) == ("tool", ctx.call_id, Decimal("0.01"))
    assert (row.tenant_id, row.user_id, row.agent_id) == ("acme", "olivia", "ops-agent")
    assert row.ts == ctx.received_at
    assert ctx.cost_usd == 0.01


async def test_metering_adds_the_spend_to_the_session_with_the_stores_own_change() -> None:
    sessions = InMemorySessionStore()
    ctx = make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.01), dispatched=True)
    await sessions.create(ctx.session.session_id, ctx.principal)
    # Another call of the session recorded 0.05 after this call read its copy.
    await sessions.add_spend(ctx.session.session_id, 0.05)

    await MeteringInterceptor(Booked(), sessions).after_call(ctx)  # type: ignore[arg-type]

    stored = await sessions.get(ctx.session.session_id)
    assert stored is not None and stored.spent_usd == pytest.approx(0.06)
    # The call's own copy caught up with what the store holds, the other call's spend included.
    assert ctx.session.spent_usd == pytest.approx(0.06)


async def test_metering_counts_on_the_calls_copy_when_there_is_no_session_to_change() -> None:
    ctx = make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.01), dispatched=True)

    await MeteringInterceptor(Booked(), InMemorySessionStore()).after_call(ctx)  # type: ignore[arg-type]

    assert ctx.session.spent_usd == pytest.approx(0.01)


async def test_a_free_tool_costs_nothing_and_leaves_no_row() -> None:
    booked = Booked()
    ctx = make_ctx(dispatched=True)

    await MeteringInterceptor(booked).after_call(ctx)  # type: ignore[arg-type]

    assert (booked.entries, ctx.cost_usd, ctx.session.spent_usd) == ([], 0.0, 0.0)


async def test_a_call_that_never_reached_the_upstream_is_not_charged() -> None:
    booked = Booked()
    ctx = make_ctx(tool=make_tool("echo", "echo", cost_per_call_usd=0.01), dispatched=False)

    await MeteringInterceptor(booked).after_call(ctx)  # type: ignore[arg-type]

    assert booked.entries == [] and ctx.cost_usd == 0.0


async def test_keystones_own_tools_are_never_charged() -> None:
    booked = Booked()
    ctx = make_ctx({}, make_tool("keystone", "whoami", cost_per_call_usd=1.0), dispatched=True)

    await MeteringInterceptor(booked).after_call(ctx)  # type: ignore[arg-type]

    assert booked.entries == [] and ctx.cost_usd == 0.0


async def test_a_call_that_returned_an_error_was_still_run_and_is_charged() -> None:
    from keystone.core.types import ToolResult

    booked = Booked()
    ctx = make_ctx(
        tool=make_tool("echo", "echo", cost_per_call_usd=0.01),
        dispatched=True,
        result=ToolResult(content=[], is_error=True),
    )

    await MeteringInterceptor(booked).after_call(ctx)  # type: ignore[arg-type]

    assert len(booked.entries) == 1
