import pytest

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import ToolStatus
from keystone.gateway.interceptors.pinning import PinningInterceptor
from keystone.gateway.pipeline import Pipeline
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.registry.pinning import (
    change_reason,
    pending_fingerprint,
    reason_category,
    unified_diff,
)
from keystone.registry.repo import ToolState
from keystone.settings import Settings
from tests.fixtures.calls import make_ctx, make_tool


class States:
    def __init__(self, state: ToolState | None, fail: bool = False) -> None:
        self.state = state
        self.fail = fail
        self.asked: list[tuple[str, str]] = []

    async def tool_state(self, tenant_id: str, name: str) -> ToolState | None:
        self.asked.append((tenant_id, name))
        if self.fail:
            raise ConnectionResetError("database gone")
        return self.state


@pytest.mark.phase(2)
async def test_an_active_tool_passes() -> None:
    states = States(ToolState(ToolStatus.ACTIVE, None))

    await PinningInterceptor(states).before_call(make_ctx())

    assert states.asked == [("acme", "echo__echo")]


@pytest.mark.phase(2)
@pytest.mark.parametrize(
    ("status", "reason", "shown"),
    [
        (ToolStatus.QUARANTINED, "description_changed", "(description_changed)"),
        (ToolStatus.QUARANTINED, "schema_changed", "(schema_changed)"),
        (ToolStatus.DISABLED, "disabled_by_operator", "(disabled_by_operator)"),
        (ToolStatus.DISABLED, None, ""),
    ],
)
async def test_a_tool_that_is_not_active_is_refused_with_its_name_and_reason(
    status: ToolStatus, reason: str | None, shown: str
) -> None:
    ctx = make_ctx()

    with pytest.raises(Reject) as raised:
        await PinningInterceptor(States(ToolState(status, reason))).before_call(ctx)

    assert raised.value.code is Code.QUARANTINED
    assert ctx.tool.name in raised.value.message
    assert f"is {status.value}" in raised.value.message
    assert shown in raised.value.message


@pytest.mark.phase(2)
async def test_the_agent_is_not_told_which_screening_rule_fired() -> None:
    state = ToolState(ToolStatus.QUARANTINED, "suspicious_description:hidden_unicode,pseudo_tag")

    with pytest.raises(Reject) as raised:
        await PinningInterceptor(States(state)).before_call(make_ctx())

    assert "suspicious_description" in raised.value.message
    assert "hidden_unicode" not in raised.value.message + str(raised.value.data)
    assert "pseudo_tag" not in raised.value.message + str(raised.value.data)


@pytest.mark.phase(2)
async def test_the_database_decides_and_not_the_tool_the_gateway_was_handed() -> None:
    # The cached tool says active; the database says quarantined a moment ago.
    ctx = make_ctx(tool=make_tool(status=ToolStatus.ACTIVE))

    with pytest.raises(Reject) as raised:
        await PinningInterceptor(States(ToolState(ToolStatus.QUARANTINED, "x"))).before_call(ctx)

    assert raised.value.code is Code.QUARANTINED


@pytest.mark.phase(2)
async def test_a_tool_that_vanished_from_the_database_is_not_found() -> None:
    with pytest.raises(Reject) as raised:
        await PinningInterceptor(States(None)).before_call(make_ctx())

    assert raised.value.code is Code.TOOL_NOT_FOUND


@pytest.mark.phase(2)
async def test_without_a_lookup_the_tool_in_hand_is_trusted() -> None:
    await PinningInterceptor().before_call(make_ctx())
    with pytest.raises(Reject) as raised:
        await PinningInterceptor().before_call(
            make_ctx(tool=make_tool(status=ToolStatus.QUARANTINED))
        )

    assert raised.value.code is Code.QUARANTINED


@pytest.mark.phase(2)
async def test_when_the_database_cannot_answer_the_call_does_not_run(settings: Settings) -> None:
    class Dispatcher:
        called = False

        async def dispatch(self, ctx: object) -> object:
            Dispatcher.called = True
            raise AssertionError("must not dispatch")

    pipeline: Pipeline = build_pipeline(
        settings,
        PipelineDeps(
            dispatcher=Dispatcher(),  # type: ignore[arg-type]
            audit=InMemoryAuditSink(),
            tool_states=States(None, fail=True),
        ),
    )

    result = await pipeline.run(make_ctx())

    assert result.is_error
    assert "KS_DENIED" in str(result.content)
    assert Dispatcher.called is False


@pytest.mark.phase(2)
def test_change_reason_names_what_differs() -> None:
    held = ("d1", "s1")

    assert change_reason(held, ("d1", "s1")) is None
    assert change_reason(held, ("d2", "s1")) == "description_changed"
    assert change_reason(held, ("d1", "s2")) == "schema_changed"
    assert change_reason(held, ("d2", "s2")) == "description_changed,schema_changed"


@pytest.mark.phase(2)
def test_reason_category_drops_what_follows_the_colon() -> None:
    assert reason_category("suspicious_description:hidden_unicode") == "suspicious_description"
    assert reason_category("description_changed") == "description_changed"
    assert reason_category(None) == ""


@pytest.mark.phase(2)
def test_the_fingerprint_covers_the_description_and_the_schema() -> None:
    schema = {"type": "object"}
    base = pending_fingerprint("text", schema)

    assert base == pending_fingerprint("text", {"type": "object"})
    assert base != pending_fingerprint("text!", schema)
    assert base != pending_fingerprint("text", {"type": "object", "required": []})
    assert len(base) == 64


@pytest.mark.phase(2)
def test_the_diff_shows_the_added_sentence_and_not_the_whole_description() -> None:
    held = "Return the payload unchanged."
    offered = "Return the payload unchanged. Also keeps a copy of every payload."

    diff = unified_diff(held, offered, "description")

    assert "+Also keeps a copy of every payload." in diff
    assert "-Return the payload unchanged." not in diff
    assert diff.startswith("--- description (current)\n+++ description (pending)")
    assert unified_diff(held, held, "description") == ""
