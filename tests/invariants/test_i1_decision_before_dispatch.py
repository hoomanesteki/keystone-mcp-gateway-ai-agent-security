"""I1: a call reaches an upstream only after a decision that allows it."""

from typing import Any

import pytest

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ToolResult
from keystone.gateway.pipeline import Dispatcher
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.upstreams import DemoUpstreams


class SpyDispatcher:
    """Wraps the real dispatcher and notes the decision it saw at the moment of dispatch."""

    def __init__(self, inner: Dispatcher) -> None:
        self.inner = inner
        self.decisions: list[Decision | None] = []
        self.tools: list[str] = []

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        self.decisions.append(ctx.decision)
        self.tools.append(ctx.tool.name)
        return await self.inner.dispatch(ctx)


class SetsEffect:
    """A policy slot that decides the same way every time."""

    name = "policy"

    def __init__(self, effect: Effect) -> None:
        self.effect = effect

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(effect=self.effect, source="policy")
        if self.effect is Effect.DENY:
            raise Reject(Code.DENIED, "not today")

    async def after_call(self, ctx: CallContext) -> None:
        return None


class LeavesDecisionEmpty:
    """A policy slot that does nothing, like a pass-through stub that forgot to decide."""

    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Approves:
    """An approval slot that plays a consumed approval (Phase 6 does this for real)."""

    name = "approval"

    async def before_call(self, ctx: CallContext) -> None:
        ctx.approval_id = "01JAPPROVED"

    async def after_call(self, ctx: CallContext) -> None:
        return None


SEND_ARGS = {"to": "x@acme.test", "subject": "s", "body": "b"}


@pytest.mark.services
@pytest.mark.phase(6)
async def test_i1_a_tool_of_keystones_own_needs_a_decision_too(
    keystone_app_factory: Any, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    """The policy slot is what gives keystone__whoami its decision. A slot that decides nothing
    stops it like any other call: being virtual is not a way round the structural check."""
    spy: SpyDispatcher | None = None

    def wrap(inner: Dispatcher) -> Dispatcher:
        nonlocal spy
        spy = SpyDispatcher(inner)
        return spy

    app: KeystoneApp = keystone_app_factory(
        wrap_dispatcher=wrap, interceptors={"policy": LeavesDecisionEmpty()}
    )
    async with mcp_client(app, user="olivia") as client:
        result = await client.call_tool("keystone__whoami", {})

    assert result.is_error and result.meta is not None
    assert result.meta["keystone/code"] == "KS_DENIED"
    assert spy is not None and spy.tools == []
    assert [(r["dispatched"], r["reject_code"]) for r in app.audit.records] == [
        (False, "KS_DENIED")
    ]


@pytest.mark.services
@pytest.mark.phase(1)
async def test_i1(
    keystone_app_factory: Any, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    spy: SpyDispatcher | None = None

    def wrap(inner: Dispatcher) -> Dispatcher:
        nonlocal spy
        spy = SpyDispatcher(inner)
        return spy

    app: KeystoneApp = keystone_app_factory(wrap_dispatcher=wrap)
    async with mcp_client(app) as client:
        await client.call_tool("echo__echo", {"payload": "allowed"})
        await client.call_tool("bank__get_balance", {"account": "CHK-001"})
        await client.call_tool("echo__echo", {"payload": 1})  # invalid, never dispatched
        await client.call_tool("echo__missing", {})  # unknown, never dispatched
        await client.call_tool("keystone__whoami", {})  # Keystone's own, decided as virtual

    assert spy is not None
    assert spy.tools == ["echo__echo", "bank__get_balance", "keystone__whoami"]
    assert [d.effect if d else None for d in spy.decisions] == [Effect.ALLOW] * 3
    # The decision comes from the policy engine and not from a stub (KS-406), except for the
    # tools Keystone serves itself, which Cedar has no rule about (KS-603). Those have the source
    # "virtual", and nothing else does.
    for tool, decision in zip(spy.tools, spy.decisions, strict=True):
        assert decision is not None
        if tool.startswith("keystone__"):
            assert decision.source == "virtual" and decision.reasons == ["virtual-tool"]
        else:
            assert decision.source == "policy" and decision.policy_version and decision.reasons
    assert [r["dispatched"] for r in app.audit.records] == [True, True, False, False, True]


@pytest.mark.services
@pytest.mark.phase(1)
@pytest.mark.parametrize("effect", [Effect.DENY, Effect.REQUIRE_APPROVAL])
async def test_i1_a_decision_that_is_not_allow_stops_the_call(
    keystone_app_factory: Any, mcp_client: McpConnect, demo_upstreams: DemoUpstreams, effect: Effect
) -> None:
    spy: SpyDispatcher | None = None

    def wrap(inner: Dispatcher) -> Dispatcher:
        nonlocal spy
        spy = SpyDispatcher(inner)
        return spy

    app: KeystoneApp = keystone_app_factory(
        wrap_dispatcher=wrap, interceptors={"policy": SetsEffect(effect)}
    )
    async with mcp_client(app, user="olivia") as client:  # send_email is high risk: an operator
        result = await client.call_tool(
            "mail__send_email", {"to": "x@acme.test", "subject": "s", "body": "b"}
        )

    assert result.is_error
    assert spy is not None
    assert spy.decisions == []
    assert demo_upstreams.state("mail")["sent"] == []
    assert [r["dispatched"] for r in app.audit.records] == [False]


@pytest.mark.services
@pytest.mark.phase(2)
async def test_i1_a_policy_slot_that_decides_nothing_stops_the_call(
    keystone_app_factory: Any, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    spy: SpyDispatcher | None = None

    def wrap(inner: Dispatcher) -> Dispatcher:
        nonlocal spy
        spy = SpyDispatcher(inner)
        return spy

    app: KeystoneApp = keystone_app_factory(
        wrap_dispatcher=wrap, interceptors={"policy": LeavesDecisionEmpty()}
    )
    async with mcp_client(app, user="olivia") as client:
        result = await client.call_tool("mail__send_email", SEND_ARGS)

    assert result.is_error
    assert texts(result)[0].startswith("[keystone:KS_DENIED] call ")
    assert spy is not None
    assert spy.tools == []
    assert demo_upstreams.state("mail")["sent"] == []
    assert [(r["dispatched"], r["reject_code"]) for r in app.audit.records] == [
        (False, "KS_DENIED")
    ]


@pytest.mark.services
@pytest.mark.phase(2)
async def test_i1_require_approval_dispatches_only_with_an_approval_id(
    keystone_app_factory: Any, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    spy: SpyDispatcher | None = None

    def wrap(inner: Dispatcher) -> Dispatcher:
        nonlocal spy
        spy = SpyDispatcher(inner)
        return spy

    policy = SetsEffect(Effect.REQUIRE_APPROVAL)
    app: KeystoneApp = keystone_app_factory(
        wrap_dispatcher=wrap, interceptors={"policy": policy, "approval": Approves()}
    )
    async with mcp_client(app, user="olivia") as client:
        result = await client.call_tool("mail__send_email", SEND_ARGS)

    assert not result.is_error
    assert spy is not None
    assert [d.effect if d else None for d in spy.decisions] == [Effect.REQUIRE_APPROVAL]
    assert len(demo_upstreams.state("mail")["sent"]) == 1  # type: ignore[arg-type]
