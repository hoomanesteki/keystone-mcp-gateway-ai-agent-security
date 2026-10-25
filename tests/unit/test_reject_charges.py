"""KS-992: a call to a tool that does not exist takes a token from the principal's buckets."""

from typing import Any

import pytest

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import ToolResult
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.metering.ratelimit import MemoryLimiter
from keystone.settings import RateLimit, RateLimitSettings, Settings
from tests.fixtures.calls import make_ctx, make_tool

pytestmark = pytest.mark.phase(9)

MISSING = Reject(Code.TOOL_NOT_FOUND, "there is no tool named 'made_up'")


class Dispatching:
    async def dispatch(self, ctx: Any) -> ToolResult:
        return ToolResult(content=[])


def build(limits: RateLimitSettings, limiter: Any = None) -> tuple[Any, InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    pipeline = build_pipeline(
        Settings(env="test", rate_limits=limits),
        PipelineDeps(dispatcher=Dispatching(), audit=sink, rate_limiter=limiter or MemoryLimiter()),
    )
    return pipeline, sink


def message(result: ToolResult) -> str:
    return str(result.content[0]["text"])


async def test_made_up_names_in_a_loop_are_limited() -> None:
    pipeline, sink = build(RateLimitSettings(per_user=RateLimit(capacity=3, refill_per_s=0.001)))

    answers = [await pipeline.reject(make_ctx(), MISSING) for _ in range(5)]

    assert ["KS_TOOL_NOT_FOUND" in message(a) for a in answers] == [True] * 3 + [False] * 2
    assert all("KS_RATE_LIMITED" in message(a) for a in answers[3:])
    # Every call leaves its record, and the limited ones say why.
    codes = [r["reject_code"] for r in sink.records]
    assert codes == ["KS_TOOL_NOT_FOUND"] * 3 + ["KS_RATE_LIMITED"] * 2
    assert {r["outcome"] for r in sink.records} == {"rejected"}


async def test_the_tools_own_bucket_is_not_charged_and_the_principals_is() -> None:
    limiter = MemoryLimiter()
    pipeline, _ = build(
        RateLimitSettings(
            per_user=RateLimit(capacity=2, refill_per_s=0.001),
            per_tool=RateLimit(capacity=1, refill_per_s=0.001),
        ),
        limiter,
    )
    ghost = make_tool("ghost", "tool")

    first = await pipeline.reject(make_ctx(tool=ghost), MISSING)
    second = await pipeline.reject(make_ctx(tool=ghost), MISSING)
    third = await pipeline.reject(make_ctx(tool=ghost), MISSING)

    # per_tool holds one token; if it were charged the second call would be limited by it.
    assert "KS_TOOL_NOT_FOUND" in message(first) + message(second)
    assert "per_user" in message(third) or "your user's" in message(third)


async def test_other_refusals_are_not_charged() -> None:
    pipeline, _ = build(RateLimitSettings(per_user=RateLimit(capacity=1, refill_per_s=0.001)))
    other = Reject(Code.DENIED, "session state is unavailable")

    answers = [await pipeline.reject(make_ctx(), other) for _ in range(3)]

    assert all("KS_DENIED" in message(a) for a in answers)


async def test_a_limiter_that_fails_leaves_the_refusal_as_it_was() -> None:
    class Down:
        async def check(self, buckets: Any, now: float) -> Any:
            raise ConnectionError("redis is down")

    pipeline, sink = build(
        RateLimitSettings(per_user=RateLimit(capacity=1, refill_per_s=1)), Down()
    )

    result = await pipeline.reject(make_ctx(), MISSING)

    assert "KS_TOOL_NOT_FOUND" in message(result)
    assert [r["reject_code"] for r in sink.records] == ["KS_TOOL_NOT_FOUND"]


async def test_no_limits_set_charges_nothing() -> None:
    pipeline, _ = build(RateLimitSettings())

    answers = [await pipeline.reject(make_ctx(), MISSING) for _ in range(5)]

    assert all("KS_TOOL_NOT_FOUND" in message(a) for a in answers)
