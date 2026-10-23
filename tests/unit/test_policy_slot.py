"""KS-406: the policy slot and the tool-list filter, against an engine that answers as told."""

from collections.abc import Mapping
from typing import Any

import pytest

from keystone.core.errors import Code, Reject
from keystone.core.types import Decision, Effect, Principal, Risk, ToolRef, ToolTag
from keystone.gateway.interceptors.policy import (
    CACHE_PREFIX,
    MemoryListCache,
    PolicyInterceptor,
    PolicyToolFilter,
    _decode,
    _encode,
    principal_hash,
    tool_digest,
)
from keystone.policy.entities import Action
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool


class Engine:
    """Answers `effect` for every request and notes what it was asked."""

    def __init__(
        self, effect: Effect = Effect.ALLOW, reasons: tuple[str, ...] = ("a-rule",)
    ) -> None:
        self.effect, self.reasons = effect, list(reasons)
        self.version = "v1"
        self.asked: list[tuple[str, str, dict[str, Any]]] = []
        self.deny_tools: set[str] = set()

    def evaluate(
        self, principal: Principal, action: Action, tool: ToolRef, context: Mapping[str, Any]
    ) -> Decision:
        self.asked.append((action, tool.name, dict(context)))
        effect = Effect.DENY if tool.name in self.deny_tools else self.effect
        return Decision(
            effect=effect, reasons=self.reasons, source="policy", policy_version=self.version
        )


TRANSFER = make_tool(
    "bank",
    "transfer",
    schema={"type": "object"},
    risk=Risk.HIGH,
    tags=frozenset({ToolTag.EXTERNAL_EFFECT}),
    extractors={"amount": "$.amount | cents"},
)


@pytest.mark.phase(4)
async def test_an_allow_is_recorded_on_the_call_and_nothing_is_raised() -> None:
    engine = Engine(Effect.ALLOW, ("operators-high",))
    ctx = make_ctx({"amount": 12.5}, TRANSFER)

    await PolicyInterceptor(engine).before_call(ctx)

    assert ctx.decision is not None
    assert (ctx.decision.effect, ctx.decision.reasons) == (Effect.ALLOW, ["operators-high"])
    [(action, tool, context)] = engine.asked
    assert (action, tool) == ("call_tool", "bank__transfer")
    # The extractors ran, and what they found is on the call and in the context.
    assert ctx.extracted == {"amount": 1250}
    assert context["args"] == {"amount": 1250}
    assert context["agent_id"] == "ops-agent"


@pytest.mark.phase(4)
async def test_a_deny_is_recorded_and_refused_with_the_reasons() -> None:
    engine = Engine(Effect.DENY, ("rule-b", "rule-a"))
    ctx = make_ctx({"amount": 1}, TRANSFER)

    with pytest.raises(Reject) as raised:
        await PolicyInterceptor(engine).before_call(ctx)

    assert raised.value.code is Code.DENIED
    assert raised.value.message == "denied by policy: rule-b, rule-a"
    assert raised.value.data == {"keystone/reasons": ["rule-b", "rule-a"]}
    assert ctx.decision is not None and ctx.decision.effect is Effect.DENY  # the audit sees it


@pytest.mark.phase(4)
async def test_a_require_approval_is_recorded_and_left_to_the_approval_slot() -> None:
    engine = Engine(Effect.REQUIRE_APPROVAL, ("approve-big-transfers",))
    ctx = make_ctx({"amount": 900}, TRANSFER)

    await PolicyInterceptor(engine).before_call(ctx)

    assert ctx.decision is not None
    assert (ctx.decision.effect, ctx.decision.reasons) == (
        Effect.REQUIRE_APPROVAL,
        ["approve-big-transfers"],
    )
    assert ctx.approval_id is None  # only a consumed approval may set it (KS-191)


@pytest.mark.phase(4)
async def test_a_tool_with_no_extractors_gives_an_empty_args_record() -> None:
    engine = Engine()
    ctx = make_ctx({"text": "hi"}, make_tool("echo", "echo"))

    await PolicyInterceptor(engine).before_call(ctx)

    assert ctx.extracted == {} and engine.asked[0][2]["args"] == {}


@pytest.mark.phase(4)
async def test_an_engine_that_raises_propagates_so_the_pipeline_denies() -> None:
    class Broken(Engine):
        def evaluate(self, *args: Any) -> Decision:
            raise RuntimeError("no")

    ctx = make_ctx({"amount": 1}, TRANSFER)

    with pytest.raises(RuntimeError):
        await PolicyInterceptor(Broken()).before_call(ctx)

    assert ctx.decision is None  # nothing was recorded, so the pipeline's own check refuses


@pytest.mark.phase(4)
def test_the_principal_hash_covers_who_can_change_a_decision() -> None:
    base = OLIVIA.model_copy(update={"groups": ("operators", "support"), "roles": ("approver",)})
    same_but_ordered = base.model_copy(update={"groups": ("support", "operators")})
    scopes = base.model_copy(update={"scopes": ("profile",)})

    assert principal_hash(base) == principal_hash(same_but_ordered)  # order is not identity
    assert principal_hash(base) == principal_hash(scopes)  # scopes are not part of it
    for field, value in [
        ("tenant_id", "globex"),
        ("user_id", "someone"),
        ("groups", ("operators",)),
        ("agent_id", "other-agent"),
        ("agent_trust", "low"),
        ("roles", ("admin",)),
    ]:
        assert principal_hash(base.model_copy(update={field: value})) != principal_hash(base), field
    assert len(principal_hash(base)) == 32


@pytest.mark.phase(4)
def test_the_tool_digest_covers_what_a_listing_decision_reads() -> None:
    tool = make_tool("bank", "transfer", risk=Risk.HIGH, tags=frozenset({ToolTag.EXTERNAL_EFFECT}))

    assert tool_digest(tool) == tool_digest(tool.model_copy())
    assert tool_digest(tool) != tool_digest(tool.model_copy(update={"risk": Risk.LOW}))
    assert tool_digest(tool) != tool_digest(tool.model_copy(update={"tags": frozenset()}))
    assert tool_digest(tool) != tool_digest(tool.model_copy(update={"tenant_id": "globex"}))
    # The description is not read by a policy, so it is not part of the digest.
    assert tool_digest(tool) == tool_digest(tool.model_copy(update={"description": "other"}))


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "raw",
    [None, "", "not json", "[]", "3", '{"a": 1}', '{"a": ["d", "yes"]}', '{"a": ["d"]}', b"\xff"],
)
def test_a_cache_entry_that_is_not_an_answer_set_is_ignored(raw: str | bytes | None) -> None:
    decoded = _decode(raw)

    assert not decoded  # nothing usable


@pytest.mark.phase(4)
def test_answers_survive_encoding() -> None:
    answers = {"a__b": ("d1", True), "c__d": ("d2", False)}

    assert _decode(_encode(answers)) == answers


@pytest.mark.phase(4)
async def test_the_memory_cache_expires_and_is_bounded() -> None:
    now = [100.0]
    cache = MemoryListCache(max_entries=2, clock=lambda: now[0])
    await cache.put("a", {"t": ("d", True)}, ttl_s=10)
    await cache.put("b", {"t": ("d", True)}, ttl_s=10)
    await cache.put("c", {"t": ("d", True)}, ttl_s=10)  # pushes "a" out

    assert await cache.get("a") is None
    assert await cache.get("b") == {"t": ("d", True)}
    now[0] = 111.0
    assert await cache.get("b") is None  # ten seconds have passed
    await cache.put("d", {"t": ("d", True)}, ttl_s=0)  # a TTL of zero stores nothing
    assert await cache.get("d") is None


@pytest.mark.phase(4)
async def test_the_filter_keeps_what_the_engine_allows_and_remembers_it() -> None:
    engine = Engine()
    engine.deny_tools = {"bank__transfer"}
    cache = MemoryListCache()
    tools = [make_tool("echo", "echo"), TRANSFER, make_tool("mail", "read_email")]
    visible = PolicyToolFilter(engine, cache, ttl_s=60)

    first = await visible.visible(OLIVIA, tools)
    asked = len(engine.asked)
    second = await visible.visible(OLIVIA, tools)

    assert [t.name for t in first] == ["echo__echo", "mail__read_email"] == [t.name for t in second]
    assert asked == 3 and len(engine.asked) == 3
    assert {action for action, _, _ in engine.asked} == {"list_tool"}
    assert await cache.get(f"{CACHE_PREFIX}:{principal_hash(OLIVIA)}:v1") is not None


@pytest.mark.phase(4)
async def test_a_new_policy_version_asks_again() -> None:
    engine = Engine()
    visible = PolicyToolFilter(engine, MemoryListCache(), ttl_s=60)
    tools = [make_tool("echo", "echo")]
    await visible.visible(OLIVIA, tools)
    engine.version = "v2"
    engine.deny_tools = {"echo__echo"}

    after = await visible.visible(OLIVIA, tools)

    assert after == [] and len(engine.asked) == 2


@pytest.mark.phase(4)
async def test_only_an_allow_makes_a_tool_visible() -> None:
    for effect in (Effect.DENY, Effect.REQUIRE_APPROVAL):
        engine = Engine(effect)
        shown = await PolicyToolFilter(engine, None).visible(OLIVIA, [make_tool("echo", "echo")])

        assert shown == [], effect


@pytest.mark.phase(4)
async def test_the_filter_works_without_a_cache() -> None:
    engine = Engine()
    visible = PolicyToolFilter(engine, None)
    tools = [make_tool("echo", "echo")]

    assert [t.name for t in await visible.visible(OLIVIA, tools)] == ["echo__echo"]
    assert [t.name for t in await visible.visible(OLIVIA, tools)] == ["echo__echo"]
    assert len(engine.asked) == 2  # nothing remembered
