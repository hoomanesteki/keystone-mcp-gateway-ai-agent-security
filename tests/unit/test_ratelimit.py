"""KS-804 without Redis: the bucket math, the in-memory limiter that follows it, and the slot."""

import hashlib
from collections.abc import Sequence
from typing import Any

import pytest

from keystone.core.errors import Code, Reject
from keystone.core.types import Effect, Principal
from keystone.gateway.interceptors.ratelimit import RateLimitInterceptor
from keystone.gateway.wiring import INTERCEPTOR_ORDER, PipelineDeps, build_pipeline
from keystone.metering.ratelimit import Bucket, MemoryLimiter, Verdict, step
from keystone.settings import RateLimit, RateLimitSettings, Settings
from keystone.telemetry.metrics import Metrics
from tests.fixtures.calls import make_ctx, make_tool

pytestmark = pytest.mark.phase(8)


class Clock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_bucket_math() -> None:
    # A bucket seen for the first time is full: capacity 5 allows five calls at one instant and
    # refuses the sixth.
    held, stamp = None, None
    for _ in range(5):
        taken = step(held, stamp, 100.0, capacity=5, refill_per_s=2)
        assert taken.allowed
        held, stamp = taken.held, taken.stamp
    sixth = step(held, stamp, 100.0, capacity=5, refill_per_s=2)
    assert sixth.allowed is False
    # Empty, at 2 tokens a second: half a second to the next one.
    assert sixth.retry_after_s == pytest.approx(0.5)

    # A refusal takes nothing and moves nothing.
    assert (sixth.held, sixth.stamp) == (held, stamp)

    # Half a second later there is one token, and one call, and then it is empty again.
    again = step(held, stamp, 100.5, capacity=5, refill_per_s=2)
    assert again.allowed
    assert again.held == pytest.approx(0.0)
    empty = step(again.held, again.stamp, 100.5, capacity=5, refill_per_s=2)
    assert empty.allowed is False

    # A quarter of a second of refill is half a token: the wait is the other half.
    partial = step(0.0, 100.0, 100.25, capacity=5, refill_per_s=2)
    assert partial.allowed is False
    assert partial.held == pytest.approx(0.5)
    assert partial.retry_after_s == pytest.approx(0.25)

    # Idle for a long time, a bucket holds its capacity and no more.
    idle = step(0.0, 100.0, 10_000.0, capacity=5, refill_per_s=2)
    assert idle.allowed and idle.held == pytest.approx(4.0)


def test_a_clock_that_goes_back_gives_nothing_and_takes_nothing() -> None:
    # The stamp stays at the later moment, so a process with a slow clock cannot make a bucket
    # refill twice for the same second.
    behind = step(2.0, 100.0, 90.0, capacity=5, refill_per_s=1)

    assert behind.allowed
    assert behind.held == pytest.approx(1.0)
    assert behind.stamp == 100.0


def test_a_bucket_that_holds_more_than_a_lowered_capacity_is_cut_down() -> None:
    cut = step(50.0, 100.0, 100.0, capacity=3, refill_per_s=1)

    assert cut.allowed and cut.held == pytest.approx(2.0)


def bucket(scope: str, key: str, capacity: float = 5, refill: float = 1) -> Bucket:
    return Bucket(scope=scope, key=key, capacity=capacity, refill_per_s=refill)


async def test_the_memory_limiter_follows_the_same_math() -> None:
    limiter = MemoryLimiter()
    one = [bucket("per_user", "acme:olivia", capacity=2, refill=0.5)]

    results = [await limiter.check(one, 10.0) for _ in range(3)]
    later = await limiter.check(one, 12.0)

    assert [r.allowed for r in results] == [True, True, False]
    assert results[2].scope == "per_user"
    assert results[2].retry_after_s == pytest.approx(2.0)
    assert later.allowed


async def test_a_refusal_takes_a_token_from_no_bucket() -> None:
    limiter = MemoryLimiter()
    user = bucket("per_user", "acme:olivia", capacity=5)
    tool = bucket("per_tool", "acme:echo__echo", capacity=1)
    await limiter.check([tool], 10.0)  # the tool's bucket is now empty

    refused = await limiter.check([user, tool], 10.0)
    after = [await limiter.check([user], 10.0) for _ in range(5)]

    assert (refused.allowed, refused.scope) == (False, "per_tool")
    # The user bucket still has all five: the refused call took nothing from it.
    assert all(v.allowed for v in after)


async def test_the_first_bucket_that_refuses_is_the_one_reported() -> None:
    limiter = MemoryLimiter()
    buckets = [
        bucket("per_tenant", "acme", capacity=1, refill=0.1),
        bucket("per_user", "acme:olivia", capacity=1, refill=1),
    ]
    await limiter.check(buckets, 10.0)

    refused = await limiter.check(buckets, 10.0)

    assert refused.scope == "per_tenant"
    assert refused.retry_after_s == pytest.approx(10.0)


async def test_buckets_with_other_keys_are_independent() -> None:
    limiter = MemoryLimiter()

    first = await limiter.check([bucket("per_user", "acme:alice", capacity=1)], 10.0)
    other = await limiter.check([bucket("per_user", "acme:olivia", capacity=1)], 10.0)
    again = await limiter.check([bucket("per_user", "acme:alice", capacity=1)], 10.0)

    assert (first.allowed, other.allowed, again.allowed) == (True, True, False)


async def test_no_buckets_is_an_allow() -> None:
    assert (await MemoryLimiter().check([], 10.0)).allowed


async def test_the_memory_limiter_forgets_buckets_that_have_filled_again() -> None:
    limiter = MemoryLimiter()
    await limiter.check([bucket("per_user", "acme:olivia", capacity=2, refill=1)], 10.0)
    assert limiter.size == 1

    # A full bucket is the same as none, so a long idle user costs nothing to keep.
    await limiter.check([bucket("per_user", "acme:someone-else", capacity=2)], 100.0)

    assert limiter.size == 1


# -- the slot


class Recording:
    """A limiter that answers as told and keeps what it was asked."""

    def __init__(self, verdict: Verdict | Exception) -> None:
        self.verdict = verdict
        self.asked: list[tuple[list[Bucket], float]] = []

    async def check(self, buckets: Sequence[Bucket], now: float) -> Verdict:
        self.asked.append((list(buckets), now))
        if isinstance(self.verdict, Exception):
            raise self.verdict
        return self.verdict


ALLOW = Verdict(allowed=True)
EVERY_SCOPE = RateLimitSettings(
    per_tenant=RateLimit(capacity=100, refill_per_s=10),
    per_user=RateLimit(capacity=60, refill_per_s=1),
    per_agent=RateLimit(capacity=120, refill_per_s=2),
    per_tool=RateLimit(capacity=30, refill_per_s=0.5),
)


def slot(
    limiter: Any, limits: RateLimitSettings = EVERY_SCOPE, **options: Any
) -> RateLimitInterceptor:
    return RateLimitInterceptor(limiter, limits, clock=Clock(), **options)


async def test_the_slot_asks_for_every_scope_that_is_set_in_a_fixed_order() -> None:
    limiter = Recording(ALLOW)

    await slot(limiter).before_call(make_ctx(tool=make_tool("echo", "echo")))

    [(buckets, now)] = limiter.asked
    assert now == 1_000.0
    assert [(b.scope, b.key) for b in buckets] == [
        ("per_tenant", "ks:rl:per_tenant:acme"),
        ("per_user", "ks:rl:per_user:acme:olivia"),
        ("per_agent", "ks:rl:per_agent:acme:ops-agent"),
        ("per_tool", "ks:rl:per_tool:acme:echo__echo"),
    ]
    assert [(b.capacity, b.refill_per_s) for b in buckets] == [
        (100, 10),
        (60, 1),
        (120, 2),
        (30, 0.5),
    ]


async def test_a_scope_that_is_not_set_is_not_asked() -> None:
    limiter = Recording(ALLOW)
    only_users = RateLimitSettings(per_user=RateLimit(capacity=5, refill_per_s=1))

    await slot(limiter, only_users).before_call(make_ctx())

    [(buckets, _)] = limiter.asked
    assert [b.scope for b in buckets] == ["per_user"]


async def test_with_no_limits_the_limiter_is_not_asked_at_all() -> None:
    limiter = Recording(ALLOW)

    await slot(limiter, RateLimitSettings()).before_call(make_ctx())

    assert limiter.asked == []


async def test_a_tenants_buckets_are_its_own() -> None:
    limiter = Recording(ALLOW)
    globex = Principal(tenant_id="globex", user_id="olivia", agent_id="ops-agent")

    await slot(limiter).before_call(make_ctx(principal=globex))

    [(buckets, _)] = limiter.asked
    assert {b.key for b in buckets if b.scope in ("per_user", "per_tenant")} == {
        "ks:rl:per_tenant:globex",
        "ks:rl:per_user:globex:olivia",
    }


async def test_a_long_identifier_is_hashed_so_a_key_stays_short() -> None:
    limiter = Recording(ALLOW)
    sub = "u" * 500
    who = Principal(tenant_id="acme", user_id=sub, agent_id="ops-agent")

    await slot(limiter).before_call(make_ctx(principal=who))

    [(buckets, _)] = limiter.asked
    [user] = [b for b in buckets if b.scope == "per_user"]
    assert user.key == f"ks:rl:per_user:acme:{hashlib.sha256(sub.encode()).hexdigest()}"


async def test_a_refusal_is_rate_limited_with_the_scope_and_the_wait() -> None:
    limiter = Recording(Verdict(allowed=False, scope="per_user", retry_after_s=1.2341))
    ctx = make_ctx()

    with pytest.raises(Reject) as raised:
        await slot(limiter).before_call(ctx)

    refusal = raised.value
    assert refusal.code is Code.RATE_LIMITED
    assert refusal.data["scope"] == "per_user"
    # Rounded up to the millisecond, so that a client that waits this long is not refused again for
    # a fraction of one.
    assert refusal.data["retry_after_s"] == 1.235
    assert refusal.data["retry_after_s"] > 0
    # The same two facts where a client reads the result's own metadata.
    assert refusal.data["keystone/scope"] == "per_user"
    assert refusal.data["keystone/retry_after_s"] == 1.235
    assert "1.2" in refusal.message and "per_user" not in refusal.message
    assert ctx.decision is not None
    assert (ctx.decision.effect, ctx.decision.source) == (Effect.DENY, "rate_limit")
    assert ctx.decision.reasons == ["rate-limit:per_user"]


async def test_a_wait_that_rounds_to_nothing_is_still_a_wait() -> None:
    limiter = Recording(Verdict(allowed=False, scope="per_tool", retry_after_s=1e-9))

    with pytest.raises(Reject) as raised:
        await slot(limiter).before_call(make_ctx())

    assert raised.value.data["retry_after_s"] == 0.001


async def test_keystones_own_tools_count_like_any_other() -> None:
    limiter = Recording(ALLOW)
    whoami = make_tool("keystone", "whoami")

    await slot(limiter).before_call(make_ctx({}, whoami))

    [(buckets, _)] = limiter.asked
    assert "ks:rl:per_tool:acme:keystone__whoami" in {b.key for b in buckets}


async def test_a_call_that_comes_back_from_the_await_tool_is_not_charged_a_second_time() -> None:
    # The call was charged when it first arrived, and the await tool was charged as a call of its
    # own. The call that it runs after the approval is the same call.
    limiter = Recording(ALLOW)
    returning = make_ctx(approval_id="01APPROVAL")

    await slot(limiter).before_call(returning)

    assert limiter.asked == []


async def test_a_refusal_is_counted_by_tenant_and_scope() -> None:
    metrics = Metrics(tenants=["acme"])
    limiter = Recording(Verdict(allowed=False, scope="per_agent", retry_after_s=2))

    with pytest.raises(Reject):
        await slot(limiter, metrics=metrics).before_call(make_ctx())

    text = metrics.render().decode()
    assert 'keystone_rate_limited_total{scope="per_agent",tenant="acme"} 1.0' in text


async def test_a_metric_that_fails_does_not_change_the_refusal() -> None:
    class Broken(Metrics):
        def rate_limit_refused(self, tenant: str, scope: str) -> None:
            raise RuntimeError("the registry is gone")

    limiter = Recording(Verdict(allowed=False, scope="per_user", retry_after_s=1))

    with pytest.raises(Reject) as raised:
        await slot(limiter, metrics=Broken()).before_call(make_ctx())

    assert raised.value.code is Code.RATE_LIMITED


async def test_a_limiter_that_fails_is_not_an_allow() -> None:
    # The pipeline turns a slot that raises into a denial, so a Redis that is down costs calls and
    # never lets one through unlimited.
    limiter = Recording(ConnectionError("redis is down"))

    with pytest.raises(ConnectionError):
        await slot(limiter).before_call(make_ctx())


async def test_the_pipeline_denies_a_call_when_the_limiter_fails() -> None:
    from keystone.audit.sink import InMemoryAuditSink
    from keystone.core.types import ToolResult

    class Dispatching:
        dispatched = 0

        async def dispatch(self, ctx: Any) -> ToolResult:
            self.dispatched += 1
            return ToolResult(content=[])

    dispatcher = Dispatching()
    settings = Settings(env="test", rate_limits=EVERY_SCOPE)
    pipeline = build_pipeline(
        settings,
        PipelineDeps(
            dispatcher=dispatcher,
            audit=InMemoryAuditSink(),
            rate_limiter=Recording(ConnectionError("redis is down")),
        ),
    )

    result = await pipeline.run(make_ctx())

    assert result.is_error and "KS_DENIED" in str(result.content)
    assert dispatcher.dispatched == 0


# -- settings and wiring


def test_the_limits_load_from_yaml(tmp_path: Any) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "rate_limits:\n"
        "  per_user: {capacity: 60, refill_per_s: 1}\n"
        "  per_tool: {capacity: 30, refill_per_s: 0.5}\n"
    )

    settings = Settings(config_path=config)

    assert settings.rate_limits.per_user == RateLimit(capacity=60, refill_per_s=1)
    assert settings.rate_limits.per_tool == RateLimit(capacity=30, refill_per_s=0.5)
    assert settings.rate_limits.per_tenant is None and settings.rate_limits.per_agent is None


def test_a_limit_can_be_tightened_from_the_environment_without_repeating_the_file(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("rate_limits:\n  per_user: {capacity: 600, refill_per_s: 20}\n")
    monkeypatch.setenv("KEYSTONE_RATE_LIMITS__PER_USER__CAPACITY", "5")

    settings = Settings(config_path=config)

    assert settings.rate_limits.per_user == RateLimit(capacity=5, refill_per_s=20)


def test_there_are_no_limits_unless_they_are_set() -> None:
    assert Settings().rate_limits == RateLimitSettings()


@pytest.mark.parametrize(
    "limit",
    [
        {"capacity": 0, "refill_per_s": 1},
        {"capacity": 0.5, "refill_per_s": 1},
        {"capacity": 5, "refill_per_s": 0},
        {"capacity": 5, "refill_per_s": -1},
        {"capacity": 5},
        {"refill_per_s": 1},
        {"capacity": 5, "refill_per_s": 1, "burst": 9},
    ],
)
def test_a_limit_needs_a_capacity_of_one_or_more_and_a_refill_above_zero(
    limit: dict[str, float],
) -> None:
    with pytest.raises(ValueError, match="per_user"):
        Settings(rate_limits={"per_user": limit})  # type: ignore[arg-type]


def test_a_scope_that_does_not_exist_is_an_error() -> None:
    with pytest.raises(ValueError, match="per_session"):
        Settings(rate_limits={"per_session": {"capacity": 5, "refill_per_s": 1}})  # type: ignore[arg-type]


def test_with_limits_and_a_limiter_the_slot_is_the_real_interceptor() -> None:
    from keystone.audit.sink import InMemoryAuditSink
    from keystone.gateway.stubs import RateLimitInterceptor as Stub

    class Dispatching:
        async def dispatch(self, ctx: Any) -> Any:
            raise AssertionError("not called")

    limited = Settings(env="test", rate_limits=EVERY_SCOPE)
    given = PipelineDeps(
        dispatcher=Dispatching(), audit=InMemoryAuditSink(), rate_limiter=MemoryLimiter()
    )
    slot_at = INTERCEPTOR_ORDER.index("rate_limit")

    real = build_pipeline(limited, given)
    no_limits = build_pipeline(Settings(env="test"), given)
    no_limiter = build_pipeline(
        limited, PipelineDeps(dispatcher=Dispatching(), audit=InMemoryAuditSink())
    )

    assert isinstance(real.interceptors[slot_at], RateLimitInterceptor)
    assert type(no_limits.interceptors[slot_at]) is Stub
    assert type(no_limiter.interceptors[slot_at]) is Stub
