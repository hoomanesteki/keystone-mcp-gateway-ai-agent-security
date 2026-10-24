"""KS-805 through the running gateway, Postgres and Redis: the ledger, the pre-check, the windows
and the rebuild of the counters.

Echo is priced at a cent a call and a user has three cents a day, so the fourth call is the one that
is refused. The tests that cross a window read the time from a clock the test holds
(`create_app(clock=...)`), set relative to the real time because the counters in Redis expire at
absolute moments.
"""

import asyncio
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from keystone.app import create_app
from keystone.metering.budgets import BudgetConfigError
from keystone.registry.config import ToolOverride, UpstreamConfig
from keystone.settings import BudgetConfig, Settings, TenantConfig
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import TEST_SCANNER, KeystoneApp, McpConnect, auth_options
from tests.fixtures.mcp_results import one, texts
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(8), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
API = "/admin/api/v1"
ECHO = {"payload": "x"}


class Clock:
    """The time of the app under test, in seconds, held by the test."""

    def __init__(self, at: datetime) -> None:
        self.at = at

    def __call__(self) -> float:
        return self.at.timestamp()


def next_midnight() -> datetime:
    now = datetime.now(UTC)
    return now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)


def next_first_of_month() -> datetime:
    day = next_midnight()
    while day.day != 1:
        day += timedelta(days=1)
    return day


def priced_echo(demo: DemoUpstreams, cost: float = 0.01) -> UpstreamConfig:
    return UpstreamConfig(
        id="echo",
        tenant="acme",
        url=demo.url("echo"),
        tools={"echo": ToolOverride(cost_per_call_usd=cost)},
    )


def budget(scope: str, window: str, limit: str, scope_id: str | None = None) -> BudgetConfig:
    return BudgetConfig(
        tenant="acme",
        scope=scope,  # type: ignore[arg-type]
        scope_id=scope_id,
        window=window,  # type: ignore[arg-type]
        limit_usd=Decimal(limit),
    )


def with_budgets(demo: DemoUpstreams, *budgets: BudgetConfig, cost: float = 0.01) -> dict[str, Any]:
    return {"upstreams": [priced_echo(demo, cost)], "budgets": list(budgets)}


def codes(answers: list[Any]) -> list[str]:
    return ["ok" if not a.is_error else re.findall(r"KS_[A-Z_]+", texts(a)[0])[0] for a in answers]


async def sql(app: KeystoneApp, statement: str, **values: Any) -> list[Any]:
    """A statement run as the owner of the tables, and its rows."""
    engine = create_async_engine(app.database_url, poolclass=NullPool)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(text(statement), values)
            return list(result.mappings()) if result.returns_rows else []
    finally:
        await engine.dispose()


def admin_get(app: KeystoneApp, idp: FakeIdp, path: str, user: str = "root") -> Any:
    response = httpx.get(
        f"{app.base}{API}{path}",
        headers={"Authorization": f"Bearer {idp.token_for(user)}"},
        timeout=15,
    )
    assert response.status_code == 200, response.text
    return response.json()


def admin_response(app: KeystoneApp, token: str, path: str) -> httpx.Response:
    return httpx.get(
        f"{app.base}{API}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=15
    )


def metrics_page(app: KeystoneApp) -> str:
    return httpx.get(f"{app.base}/metrics", timeout=10).text


async def test_tool_cost_recorded_in_ledger(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(settings=with_budgets(demo_upstreams))

    async with mcp_client(app, user="olivia") as client:
        answers = [await client.call_tool("echo__echo", ECHO) for _ in range(3)]
        free = await client.call_tool("echo__sleep", {"seconds": 0})
        mine = one(await client.call_tool("keystone__whoami", {}))

    assert codes([*answers, free]) == ["ok"] * 4
    app.audit.wait()
    rows = await sql(app, "SELECT * FROM spend_ledger ORDER BY ts, id")
    assert len(rows) == 3  # the call to the free tool left none
    calls = {r["call_id"]: r for r in app.audit.records if r["tool_name"] == "echo__echo"}
    for row in rows:
        assert (row["kind"], row["tenant_id"], row["user_id"], row["agent_id"]) == (
            "tool",
            "acme",
            "olivia",
            "ops-agent",
        )
        assert row["cost_usd"] == Decimal("0.01")
        # The row names the call, and so the audit record, which carries the same price.
        assert row["ref"] in calls
        assert Decimal(calls[row["ref"]]["cost_usd"]) == Decimal("0.01")
        assert row["model"] is None and row["input_tokens"] is None
        # The moment the call began, to the microsecond the audit record has.
        assert abs((row["ts"] - calls[row["ref"]]["ts"]).total_seconds()) < 1
    # The session adds up what its calls cost.
    assert mine["spent_usd"] == pytest.approx(0.03)
    free_row = next(r for r in app.audit.records if r["tool_name"] == "echo__sleep")
    assert Decimal(free_row["cost_usd"]) == 0


async def test_budget_blocks_before_dispatch(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    redis: Redis,
) -> None:
    app = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("user", "day", "0.03", "olivia"))
    )

    async with mcp_client(app, user="olivia") as client:
        answers = [await client.call_tool("echo__echo", ECHO) for _ in range(4)]
        # A tool without a price is not held by a budget that is used up.
        free = await client.call_tool("echo__sleep", {"seconds": 0})

    assert codes(answers) == ["ok", "ok", "ok", "KS_BUDGET_EXCEEDED"]
    assert codes([free]) == ["ok"]
    refused = answers[3]
    # The upstream saw the three calls it was allowed, and the fourth never reached it.
    assert demo_upstreams.state("echo")["calls"] == ["echo"] * 3 + ["sleep"]
    block = refused.content[0].meta
    assert block is not None and refused.meta is not None
    assert (block["scope"], block["window"]) == ("user", "day")
    assert (block["limit_usd"], block["spent_usd"]) == (0.03, 0.03)
    tomorrow = next_midnight().strftime("%Y-%m-%dT%H:%M:%SZ")
    assert block["resets_at"] in (
        tomorrow,
        (next_midnight() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert refused.meta["keystone/limit_usd"] == 0.03
    assert "$0.03" in texts(refused)[0] and "resets at" in texts(refused)[0]
    app.audit.wait()
    last = next(r for r in app.audit.records if r["reject_code"] == "KS_BUDGET_EXCEEDED")
    assert (last["effect"], last["decision_source"], last["dispatched"]) == (
        "deny",
        "budget",
        False,
    )
    assert last["reasons"] == ["budget:user:day"] and Decimal(last["cost_usd"]) == 0
    # The counter in Redis holds exactly three cents, as text.
    [key] = [k async for k in redis.scan_iter(match="ks:spend:*:user:olivia:day:*")]
    assert await redis.get(key) == "0.03"
    assert 0 < await redis.ttl(key) <= 3 * 86400


async def test_a_budget_of_another_user_does_not_hold_this_one(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("user", "day", "0.01", "olivia"))
    )

    async with mcp_client(app, user="olivia") as olivia:
        mine = [await olivia.call_tool("echo__echo", ECHO) for _ in range(2)]
    async with mcp_client(app) as alice:
        hers = [await alice.call_tool("echo__echo", ECHO) for _ in range(3)]

    assert codes(mine) == ["ok", "KS_BUDGET_EXCEEDED"]
    assert codes(hers) == ["ok", "ok", "ok"]


async def test_the_tenant_and_the_agent_have_budgets_too(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(
        settings=with_budgets(
            demo_upstreams,
            budget("tenant", "month", "0.05"),
            budget("agent", "day", "0.03", "support-agent"),
        )
    )

    async with mcp_client(app) as alice:  # through support-agent
        hers = [await alice.call_tool("echo__echo", ECHO) for _ in range(4)]
    async with mcp_client(app, user="olivia") as olivia:  # through ops-agent
        his = [await olivia.call_tool("echo__echo", ECHO) for _ in range(3)]

    assert codes(hers) == ["ok", "ok", "ok", "KS_BUDGET_EXCEEDED"]
    assert hers[3].content[0].meta["scope"] == "agent"  # type: ignore[index]
    # Three cents are spent. The tenant's five cents leave room for two more, and then it is over.
    assert codes(his) == ["ok", "ok", "KS_BUDGET_EXCEEDED"]
    assert his[2].content[0].meta["scope"] == "tenant"  # type: ignore[index]


async def test_window_reset(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    midnight = next_midnight()
    clock = Clock(midnight - timedelta(seconds=30))
    app = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("user", "day", "0.03", "olivia")),
        clock=clock,
    )

    async with mcp_client(app, user="olivia") as client:
        before = [await client.call_tool("echo__echo", ECHO) for _ in range(4)]
        # A minute later it is the next day.
        clock.at = midnight + timedelta(seconds=30)
        after = [await client.call_tool("echo__echo", ECHO) for _ in range(4)]

    assert codes(before) == ["ok", "ok", "ok", "KS_BUDGET_EXCEEDED"]
    assert codes(after) == ["ok", "ok", "ok", "KS_BUDGET_EXCEEDED"]
    # The two days kept their own counters.
    shown = after[3].content[0].meta
    assert shown is not None
    next_day = (midnight + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert shown["resets_at"] == next_day


async def test_a_month_resets_on_the_first(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    first = next_first_of_month()
    clock = Clock(first - timedelta(seconds=30))
    app = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("user", "month", "0.02", "olivia")),
        clock=clock,
    )

    async with mcp_client(app, user="olivia") as client:
        last_day = [await client.call_tool("echo__echo", ECHO) for _ in range(3)]
        clock.at = first + timedelta(seconds=30)
        first_day = [await client.call_tool("echo__echo", ECHO) for _ in range(3)]

    assert codes(last_day) == ["ok", "ok", "KS_BUDGET_EXCEEDED"]
    assert codes(first_day) == ["ok", "ok", "KS_BUDGET_EXCEEDED"]


async def test_counters_rebuilt_from_ledger_on_start(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    redis: Redis,
) -> None:
    settings = with_budgets(
        demo_upstreams, budget("user", "day", "0.03", "olivia"), budget("tenant", "month", "5")
    )
    first = keystone_app_factory(settings=settings)
    async with mcp_client(first, user="olivia") as client:
        two = [await client.call_tool("echo__echo", ECHO) for _ in range(2)]
    first.audit.wait()
    first.thread.stop()
    assert codes(two) == ["ok", "ok"]
    assert [k async for k in redis.scan_iter(match="ks:spend:*")], "nothing was counted"

    # Redis loses everything. The ledger is in Postgres.
    await redis.flushdb()
    assert [k async for k in redis.scan_iter(match="ks:spend:*")] == []
    second = keystone_app_factory(settings=settings)

    # The counters are back before anyone has made a call.
    keys = {k: str(await redis.get(k)) async for k in redis.scan_iter(match="ks:spend:*")}
    assert sorted(keys.values()) == ["0.02", "0.02"]
    async with mcp_client(second, user="olivia") as client:
        rest = [await client.call_tool("echo__echo", ECHO) for _ in range(2)]
    assert codes(rest) == ["ok", "KS_BUDGET_EXCEEDED"]  # one cent was left of three


async def test_a_redis_that_is_flushed_while_keystone_runs_does_not_reset_the_spend(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    redis: Redis,
) -> None:
    app = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("user", "day", "0.03", "olivia"))
    )

    async with mcp_client(app, user="olivia") as client:
        spent = [await client.call_tool("echo__echo", ECHO) for _ in range(3)]
        await redis.flushdb()  # a restart of Redis, with Keystone still running
        after = await client.call_tool("echo__echo", ECHO)

    assert codes(spent) == ["ok", "ok", "ok"]
    # The pre-check found no counter, read the ledger and refused.
    assert codes([after]) == ["KS_BUDGET_EXCEEDED"]


async def test_the_ledger_cannot_be_changed_by_the_gateway(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    app_database_url: str,
) -> None:
    app = keystone_app_factory(settings=with_budgets(demo_upstreams))
    async with mcp_client(app, user="olivia") as client:
        await client.call_tool("echo__echo", ECHO)
    engine = create_async_engine(app_database_url, poolclass=NullPool)

    try:
        async with engine.connect() as connection:
            seen = (
                await connection.execute(text("SELECT count(*) FROM spend_ledger"))
            ).scalar_one()
        for statement in (
            "UPDATE spend_ledger SET cost_usd = 0",
            "DELETE FROM spend_ledger",
            "TRUNCATE spend_ledger",
        ):
            async with engine.connect() as connection:
                with pytest.raises(ProgrammingError, match="permission denied"):
                    await connection.execute(text(statement))
    finally:
        await engine.dispose()

    assert seen == 1


async def test_the_budgets_of_the_config_are_stored_and_the_ones_it_dropped_are_removed(
    keystone_app_factory: Factory, demo_upstreams: DemoUpstreams
) -> None:
    both = with_budgets(
        demo_upstreams, budget("tenant", "day", "25"), budget("user", "day", "0.03", "olivia")
    )
    first = keystone_app_factory(settings=both)
    rows = await sql(
        first, 'SELECT scope, scope_id, "window", limit_usd FROM budgets ORDER BY scope'
    )
    first.thread.stop()

    second = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("tenant", "day", "30"))
    )
    after = await sql(second, 'SELECT scope, scope_id, "window", limit_usd FROM budgets')

    assert [(r["scope"], r["scope_id"], r["window"], r["limit_usd"]) for r in rows] == [
        ("tenant", "acme", "day", Decimal("25")),
        ("user", "olivia", "day", Decimal("0.03")),
    ]
    # One left the file and one got a new limit.
    assert [(r["scope"], r["limit_usd"]) for r in after] == [("tenant", Decimal("30"))]


async def test_a_budget_for_a_tenant_that_is_not_listed_stops_startup(
    fake_idp: FakeIdp,
    clean_db: None,
    redis: Redis,
    app_database_url: str,
    test_redis_url: str,
    demo_upstreams: DemoUpstreams,
) -> None:
    stray = BudgetConfig(tenant="initech", scope="tenant", window="day", limit_usd=Decimal(5))
    settings = Settings(
        env="test",
        database_url=SecretStr(app_database_url),
        redis_url=SecretStr(test_redis_url),
        tenants=[TenantConfig(id="acme", name="Acme Corp")],
        budgets=[stray],
        scanner=TEST_SCANNER,
        **auth_options(fake_idp),
    )
    app = create_app(settings)

    # Startup stops before the app serves anything, and says which budget is wrong.
    with pytest.raises(BudgetConfigError, match="initech"):
        async with app.router.lifespan_context(app):
            pytest.fail("the app started")


async def test_the_admin_api_shows_each_budget_with_its_spend_and_its_reset(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
) -> None:
    app = keystone_app_factory(
        globex=True,
        settings=with_budgets(
            demo_upstreams,
            budget("tenant", "day", "25"),
            budget("user", "month", "0.50", "olivia"),
        ),
    )
    async with mcp_client(app, user="olivia") as client:
        for _ in range(2):
            await client.call_tool("echo__echo", ECHO)

    shown = admin_get(app, fake_idp, "/budgets")

    assert [(b["scope"], b["scope_id"], b["window"]) for b in shown] == [
        ("tenant", "acme", "day"),
        ("user", "olivia", "month"),
    ]
    assert [(b["limit_usd"], b["spent_usd"]) for b in shown] == [("25", "0.02"), ("0.5", "0.02")]
    day, month = shown
    now = datetime.now(UTC)
    assert datetime.fromisoformat(day["resets_at"]) > now
    assert datetime.fromisoformat(day["window_start"]) <= now
    assert datetime.fromisoformat(month["resets_at"]).day == 1
    # The admin of another tenant sees none of these, and a user without the role is refused.
    gina = fake_idp.make_token(
        "gina", "globex", groups=("/tenants/globex", "/admins"), azp="ops-agent", roles=("admin",)
    )
    assert admin_response(app, gina, "/budgets").json() == []
    assert admin_response(app, fake_idp.token_for("alice"), "/budgets").status_code == 403


async def test_the_spend_gauge_follows_the_budget(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(settings=with_budgets(demo_upstreams, budget("tenant", "day", "25")))

    async with mcp_client(app, user="olivia") as client:
        for _ in range(3):
            await client.call_tool("echo__echo", ECHO)

    assert 'keystone_budget_spent_usd{scope="tenant",tenant="acme"} 0.03' in metrics_page(app)


async def test_calls_checked_together_may_pass_together_but_not_by_much(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    """The check is not a reservation (ADR-0014): calls in flight at once all see the same spend.
    The overshoot is the price of the calls in flight, and the next call is refused."""
    app = keystone_app_factory(
        settings=with_budgets(demo_upstreams, budget("user", "day", "0.03", "olivia"))
    )

    async with mcp_client(app, user="olivia") as client:
        together = await asyncio.gather(*(client.call_tool("echo__echo", ECHO) for _ in range(8)))
        after = await client.call_tool("echo__echo", ECHO)

    passed = codes(list(together)).count("ok")
    assert 3 <= passed <= 8
    assert codes([after]) == ["KS_BUDGET_EXCEEDED"]
    shown = [await sql(app, "SELECT count(*) AS n FROM spend_ledger")][0][0]["n"]
    assert shown == passed
