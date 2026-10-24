"""KS-804 through the running gateway and against a real Redis: the buckets, the script, the slot.

The apps here read the time from a clock the test holds (`create_app(clock=...)`), so "within a
second" and "after the refill time" are exact and nothing waits for a real second to pass.
"""

import asyncio
import random
import re
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from redis.asyncio import Redis

from keystone.metering.ratelimit import Bucket, MemoryLimiter, RedisLimiter
from keystone.settings import ApprovalSettings, RateLimit, RateLimitSettings
from tests.fixtures.approvals import Approver
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(8), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
ECHO = {"payload": "x"}
BIG = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}


class Clock:
    """The time of the app under test, held by the test."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def limited(**scopes: tuple[float, float]) -> dict[str, Any]:
    """Settings with these scopes: per_user=(capacity, refill_per_s)."""
    return {
        "rate_limits": RateLimitSettings(
            **{name: RateLimit(capacity=c, refill_per_s=r) for name, (c, r) in scopes.items()}
        )
    }


def meta(result: Any) -> dict[str, Any]:
    """The metadata of a tool result, which the SDK types as possibly missing."""
    found: dict[str, Any] | None = result.meta
    assert found is not None
    return found


def metrics_page(app: KeystoneApp) -> str:
    return httpx.get(f"{app.base}/metrics", timeout=10).text


def pending_approvals(app: KeystoneApp, idp: FakeIdp) -> list[Any]:
    response = httpx.get(
        f"{app.base}/admin/api/v1/approvals",
        headers={"Authorization": f"Bearer {idp.token_for('root')}"},
        timeout=15,
    )
    listed: list[Any] = response.json()
    return listed


def codes(answers: list[Any]) -> list[str]:
    return ["ok" if not a.is_error else re.findall(r"KS_[A-Z_]+", texts(a)[0])[0] for a in answers]


async def test_burst_over_capacity_rejected(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    clock = Clock()
    app = keystone_app_factory(settings=limited(per_user=(5, 0.5)), clock=clock)

    async with mcp_client(app) as client:
        answers = [await client.call_tool("echo__echo", ECHO) for _ in range(6)]

    assert codes(answers) == ["ok"] * 5 + ["KS_RATE_LIMITED"]
    refused = answers[5]
    # The wait is in the text the model reads, in the metadata of the block, and in the metadata
    # of the result, where a program looks first.
    assert "try again in 2.0 seconds" in texts(refused)[0]
    block = meta(refused.content[0])
    assert (block["scope"], block["retry_after_s"]) == ("per_user", 2.0)
    assert (meta(refused)["keystone/scope"], meta(refused)["keystone/retry_after_s"]) == (
        "per_user",
        2.0,
    )
    # The upstream saw the five calls it was allowed and not the sixth.
    assert len(demo_upstreams.state("echo")["calls"]) == 5  # type: ignore[arg-type]
    app.audit.wait()
    last = app.audit.records[-1]
    assert (last["reject_code"], last["effect"], last["decision_source"]) == (
        "KS_RATE_LIMITED",
        "deny",
        "rate_limit",
    )
    assert (last["reasons"], last["dispatched"], last["outcome"]) == (
        ["rate-limit:per_user"],
        False,
        "rejected",
    )


async def test_refill_allows_again(keystone_app_factory: Factory, mcp_client: McpConnect) -> None:
    clock = Clock()
    app = keystone_app_factory(settings=limited(per_user=(5, 0.5)), clock=clock)

    async with mcp_client(app) as client:
        for _ in range(5):
            await client.call_tool("echo__echo", ECHO)
        assert codes([await client.call_tool("echo__echo", ECHO)]) == ["KS_RATE_LIMITED"]
        # Not yet: the sixth asked for a token that is two seconds away, and 1.9 have passed.
        clock.now += 1.9
        early = await client.call_tool("echo__echo", ECHO)
        clock.now += 0.2
        again = await client.call_tool("echo__echo", ECHO)
        straight_after = await client.call_tool("echo__echo", ECHO)

    assert codes([early, again, straight_after]) == ["KS_RATE_LIMITED", "ok", "KS_RATE_LIMITED"]
    assert "try again in 0.1 seconds" in texts(early)[0]


async def test_limits_per_user_independent(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(globex=True, settings=limited(per_user=(2, 0.1)), clock=Clock())

    async with mcp_client(app) as alice:
        first = [await alice.call_tool("echo__echo", ECHO) for _ in range(3)]
    async with mcp_client(app, user="olivia") as olivia:
        second = [await olivia.call_tool("echo__echo", ECHO) for _ in range(3)]
    async with mcp_client(app, user="bob") as bob:
        third = [await bob.call_tool("files_globex__read_file", {"path": "README.txt"})]

    assert codes(first) == ["ok", "ok", "KS_RATE_LIMITED"]
    # Olivia and bob have buckets of their own, full.
    assert codes(second) == ["ok", "ok", "KS_RATE_LIMITED"]
    assert codes(third) == ["ok"]


async def test_two_tenants_do_not_share_a_bucket_even_for_one_user_id(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(globex=True, settings=limited(per_user=(1, 0.01)), clock=Clock())
    acme_alice = fake_idp.make_token("alice", "acme", groups=("/support",), azp="support-agent")
    globex_alice = fake_idp.make_token("alice", "globex", groups=("/support",), azp="support-agent")

    async with mcp_client(app, token=acme_alice) as acme:
        used_up = [await acme.call_tool("echo__echo", ECHO) for _ in range(2)]
    async with mcp_client(app, token=globex_alice) as globex:
        elsewhere = [await globex.call_tool("files_globex__read_file", {"path": "README.txt"})]

    assert codes(used_up) == ["ok", "KS_RATE_LIMITED"]
    assert codes(elsewhere) == ["ok"]


async def test_a_limit_on_a_tool_is_shared_by_everyone_who_calls_it(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(settings=limited(per_tool=(2, 0.01)), clock=Clock())

    async with mcp_client(app) as alice:
        used = [await alice.call_tool("echo__echo", ECHO) for _ in range(2)]
    async with mcp_client(app, user="olivia") as olivia:
        later = await olivia.call_tool("echo__echo", ECHO)
        other_tool = await olivia.call_tool("echo__sleep", {"seconds": 0})

    assert codes(used) == ["ok", "ok"]
    assert codes([later, other_tool]) == ["KS_RATE_LIMITED", "ok"]
    assert meta(later)["keystone/scope"] == "per_tool"


async def test_a_refusal_by_a_later_scope_takes_no_token_from_an_earlier_one(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(
        settings=limited(per_user=(3, 0.01), per_tool=(1, 0.01)), clock=Clock()
    )

    async with mcp_client(app, user="olivia") as olivia:
        first = await olivia.call_tool("echo__echo", ECHO)
        # The tool's bucket is empty now. Each of these is refused by it, and must not spend one of
        # olivia's three.
        refused = [await olivia.call_tool("echo__echo", ECHO) for _ in range(5)]
        # Each tool has a bucket of its own, so three other tools take three of her tokens.
        others = [
            await olivia.call_tool("echo__sleep", {"seconds": 0}),
            await olivia.call_tool("bank__get_balance", {"account": "CHK-001"}),
            await olivia.call_tool("files__list_files", {}),
        ]

    assert codes([first]) == ["ok"]
    assert codes(refused) == ["KS_RATE_LIMITED"] * 5
    # Two of her three tokens were left, because the first call spent one.
    assert codes(others) == ["ok", "ok", "KS_RATE_LIMITED"]
    assert meta(refused[0])["keystone/scope"] == "per_tool"
    assert meta(others[2])["keystone/scope"] == "per_user"


async def test_calls_that_ask_for_approval_are_limited_too(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    """The gate of Phase 6 found that nothing limited how many approval requests an agent could
    make. The limit comes before the policy, so the sixth request is refused before it is a row."""
    app = keystone_app_factory(
        settings={
            **limited(per_user=(3, 0.01)),
            "approvals": ApprovalSettings(wait_seconds=0.0, poll_interval_s=0.2),
        },
        clock=Clock(),
    )

    async with mcp_client(app, user="olivia") as olivia:
        answers = [await olivia.call_tool("bank__transfer", BIG) for _ in range(6)]

    assert codes(answers) == ["KS_APPROVAL_PENDING"] * 3 + ["KS_RATE_LIMITED"] * 3
    assert len(pending_approvals(app, fake_idp)) == 3  # three requests, not six


async def test_the_await_tool_and_whoami_are_calls_like_the_rest(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(settings=limited(per_user=(3, 0.01)), clock=Clock())

    async with mcp_client(app) as client:
        answers = [await client.call_tool("keystone__whoami", {}) for _ in range(4)]
        polling = await client.call_tool("keystone__await_approval", {"approval_id": "01NONE"})

    assert codes(answers) == ["ok", "ok", "ok", "KS_RATE_LIMITED"]
    assert codes([polling]) == ["KS_RATE_LIMITED"]


async def test_the_call_the_await_tool_runs_after_an_approval_is_not_charged_again(
    keystone_app_factory: Factory, mcp_client: McpConnect, approver: Approver
) -> None:
    # Two tokens: the transfer that asks, and the await. The call that the await then runs is the
    # transfer again, and it must not need a third.
    app = keystone_app_factory(
        settings={
            **limited(per_user=(2, 0.001)),
            "approvals": ApprovalSettings(wait_seconds=0.0, poll_interval_s=0.2),
        },
        clock=Clock(),
    )

    async with mcp_client(app, user="olivia") as olivia:
        pending = await olivia.call_tool("bank__transfer", BIG)
        approval_id = meta(pending)["keystone/approval_id"]
        await approver.approve("fine")
        completed = await olivia.call_tool(
            "keystone__await_approval", {"approval_id": approval_id, "wait_seconds": 5}
        )
        after = await olivia.call_tool("keystone__whoami", {})

    assert codes([pending]) == ["KS_APPROVAL_PENDING"]
    assert codes([completed]) == ["ok"] and "completed" in texts(completed)[0]
    assert codes([after]) == ["KS_RATE_LIMITED"]


async def test_nothing_is_stored_when_no_limit_is_set(
    keystone_app_factory: Factory, mcp_client: McpConnect, redis: Redis
) -> None:
    app = keystone_app_factory()

    async with mcp_client(app) as client:
        await client.call_tool("echo__echo", ECHO)

    assert [key async for key in redis.scan_iter(match="ks:rl:*")] == []


async def test_a_refusal_is_counted_in_the_metrics(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(settings=limited(per_agent=(1, 0.01)), clock=Clock())

    async with mcp_client(app) as client:
        for _ in range(3):
            await client.call_tool("echo__echo", ECHO)

    page = metrics_page(app)
    assert 'keystone_rate_limited_total{scope="per_agent",tenant="acme"} 2.0' in page
    denied = 'keystone_tool_calls_total{effect="deny",outcome="rejected",tenant="acme",'
    assert f'{denied}tool="echo__echo"}} 2.0' in page


# -- the script, against the math


def bucket(scope: str, key: str, capacity: float, refill: float) -> Bucket:
    return Bucket(scope=scope, key=key, capacity=capacity, refill_per_s=refill)


async def test_the_script_agrees_with_the_plain_math(redis: Redis) -> None:
    """The same random asks, in the same order, against Redis and against the in-memory limiter,
    which is `step`. Sizes and gaps are binary fractions, so the nine decimals Redis stores lose
    nothing and a call at the edge of a token cannot go either way."""
    generator = random.Random(804)  # noqa: S311 - a seeded sequence for a test
    scopes = [
        bucket("per_tenant", "ks:rl:test:tenant", 6, 0.5),
        bucket("per_user", "ks:rl:test:user", 3, 0.25),
        bucket("per_tool", "ks:rl:test:tool", 2, 1.0),
    ]
    in_redis, in_memory = RedisLimiter(redis), MemoryLimiter()
    now = 5_000.0
    verdicts: list[tuple[bool, str | None]] = []

    for _ in range(300):
        now += generator.choice([0.0, 0.0, 0.25, 0.5, 1.0, 2.0, 8.0])
        asked = [b for b in scopes if generator.random() < 0.7] or [scopes[1]]
        real, model = await in_redis.check(asked, now), await in_memory.check(asked, now)

        assert (real.allowed, real.scope) == (model.allowed, model.scope), (now, asked)
        assert real.retry_after_s == pytest.approx(model.retry_after_s, abs=1e-6)
        verdicts.append((real.allowed, real.scope))

    # The run used both outcomes and more than one scope, so the comparison meant something.
    assert {allowed for allowed, _ in verdicts} == {True, False}
    assert {scope for _, scope in verdicts if scope} >= {"per_user", "per_tool"}


async def test_many_calls_at_once_cannot_take_more_than_a_bucket_holds(redis: Redis) -> None:
    limiter = RedisLimiter(redis)
    one = [bucket("per_user", "ks:rl:test:race", 5, 0.001)]

    verdicts = await asyncio.gather(*(limiter.check(one, 100.0) for _ in range(60)))

    assert sum(v.allowed for v in verdicts) == 5


async def test_one_script_run_is_atomic_across_buckets(redis: Redis) -> None:
    limiter = RedisLimiter(redis)
    wide = bucket("per_user", "ks:rl:test:wide", 100, 0.001)
    narrow = bucket("per_tool", "ks:rl:test:narrow", 1, 0.001)

    verdicts = await asyncio.gather(*(limiter.check([wide, narrow], 100.0) for _ in range(30)))

    assert sum(v.allowed for v in verdicts) == 1
    # The 29 refusals took nothing from the wide bucket: 99 of 100 tokens are left.
    assert float(await redis.hget("ks:rl:test:wide", "tokens")) == pytest.approx(99.0)  # type: ignore[arg-type]


async def test_an_idle_bucket_expires_when_it_would_be_full_again(redis: Redis) -> None:
    limiter = RedisLimiter(redis)

    await limiter.check([bucket("per_user", "ks:rl:test:idle", 4, 2.0)], 100.0)

    # From empty it takes 4 / 2 = 2 seconds to fill, and a second more is left as a margin.
    assert 2_000 < await redis.pttl("ks:rl:test:idle") <= 3_000


async def test_a_flushed_redis_gives_every_bucket_back_full(redis: Redis) -> None:
    limiter = RedisLimiter(redis)
    one = [bucket("per_user", "ks:rl:test:flush", 1, 0.001)]
    await limiter.check(one, 100.0)
    assert not (await limiter.check(one, 100.0)).allowed

    await redis.flushdb()

    assert (await limiter.check(one, 100.0)).allowed


async def test_a_clock_that_runs_slow_does_not_refill_twice(redis: Redis) -> None:
    limiter = RedisLimiter(redis)
    one = [bucket("per_user", "ks:rl:test:slow", 2, 1.0)]
    await limiter.check(one, 100.0)
    await limiter.check(one, 100.0)  # empty at 100

    # One process says it is 90, another 101: only the real second since 100 counts, once.
    behind = await limiter.check(one, 90.0)
    ahead = await limiter.check(one, 101.0)
    again = await limiter.check(one, 101.0)

    assert (behind.allowed, ahead.allowed, again.allowed) == (False, True, False)
