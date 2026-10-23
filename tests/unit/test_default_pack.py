"""KS-407: the shipped policies decide the demo calls the way the plan says."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from keystone.core.types import Effect, Principal, SessionState, ToolRef
from keystone.policy.engine import DEFAULT_DENY, CedarPolicyEngine
from keystone.policy.entities import build_context
from keystone.policy.extractors import extract
from keystone.policy.store import PolicyStore
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.keystone import demo_tools
from tests.fixtures.policies import POLICY_ROOT

ALICE = Principal(tenant_id="acme", user_id="alice", groups=("support",), agent_id="support-agent")
OLIVIA = Principal(
    tenant_id="acme",
    user_id="olivia",
    groups=("operators",),
    agent_id="ops-agent",
    agent_trust="high",
)
BOB = Principal(tenant_id="globex", user_id="bob", agent_id="support-agent")


def demo_tool(upstream: str, name: str, tenant: str = "acme") -> ToolRef:
    """The tool as the compose config describes it: its risk, tags and extractors."""
    override = demo_tools(upstream).get(name)
    fields: dict[str, Any] = {}
    if override is not None:
        fields = {
            "risk": override.risk,
            "tags": frozenset(override.tags or []),
            "extractors": dict(override.extract),
        }
    return make_tool(upstream, name, None, **fields).model_copy(update={"tenant_id": tenant})


@pytest.fixture(scope="module")
def engine() -> CedarPolicyEngine:
    store = PolicyStore(POLICY_ROOT, ["acme", "globex"], include_demo=True)
    store.start()
    return CedarPolicyEngine(store)


def decide(
    engine: CedarPolicyEngine, who: Principal, tool: ToolRef, arguments: Mapping[str, object]
) -> tuple[Effect, list[str]]:
    """The decision for a call, the way the policy slot makes it: the tool's extractors read the
    arguments and the context carries what they found."""
    session = SessionState(session_id="s", principal=who, created_at=make_ctx().received_at)
    context = build_context(session, extract(arguments, tool.extractors))
    decision = engine.evaluate(who, "call_tool", tool, context)
    return decision.effect, decision.reasons


TRANSFER = {"from_account": "CHK-001", "to": "SAV-002"}


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    ("amount", "effect", "reasons"),
    [
        (100, Effect.ALLOW, ["operators-high"]),
        (500, Effect.ALLOW, ["operators-high"]),  # 500 is not over 500
        (500.0, Effect.ALLOW, ["operators-high"]),
        (500.01, Effect.REQUIRE_APPROVAL, ["approve-transfer-over-500"]),
        (500.99, Effect.REQUIRE_APPROVAL, ["approve-transfer-over-500"]),  # `int` would say 500
        (900, Effect.REQUIRE_APPROVAL, ["approve-transfer-over-500"]),
        ("900.75", Effect.REQUIRE_APPROVAL, ["approve-transfer-over-500"]),
        (10**30, Effect.REQUIRE_APPROVAL, ["approve-transfer-over-500"]),
        (float("inf"), Effect.REQUIRE_APPROVAL, ["approve-transfer-over-500"]),
    ],
)
def test_a_transfer_over_500_needs_approval_and_one_up_to_500_does_not(
    engine: CedarPolicyEngine, amount: object, effect: Effect, reasons: list[str]
) -> None:
    tool = demo_tool("bank", "transfer")

    assert decide(engine, OLIVIA, tool, {**TRANSFER, "amount": amount}) == (effect, reasons)


@pytest.mark.phase(4)
def test_a_transfer_whose_amount_cannot_be_read_asks_instead_of_passing(
    engine: CedarPolicyEngine,
) -> None:
    tool = demo_tool("bank", "transfer")

    for arguments in ({**TRANSFER}, {**TRANSFER, "amount": "plenty"}, {**TRANSFER, "amount": None}):
        assert decide(engine, OLIVIA, tool, arguments) == (
            Effect.REQUIRE_APPROVAL,
            ["approve-transfer-over-500"],
        )


@pytest.mark.phase(4)
def test_support_cannot_transfer_whatever_the_amount(engine: CedarPolicyEngine) -> None:
    tool = demo_tool("bank", "transfer")

    for amount in (1, 900):
        assert decide(engine, ALICE, tool, {**TRANSFER, "amount": amount}) == (
            Effect.DENY,
            [DEFAULT_DENY],
        )


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    ("recipient", "effect", "reasons"),
    [
        ("colleague@acme.test", Effect.ALLOW, ["operators-high"]),
        ("COLLEAGUE@ACME.TEST", Effect.ALLOW, ["operators-high"]),
        ("bob@evil.test", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
        ("bob@acme.test.evil.test", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
        ("bob@globex.test", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
        # Not one plain address, so there is no domain, and no domain means ask.
        ("a@evil.test,b@acme.test", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
        ("b@acme.test, a@evil.test", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
        ("Bob <bob@acme.test>", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
        ("no-at-sign", Effect.REQUIRE_APPROVAL, ["external-email-needs-approval"]),
    ],
)
def test_mail_outside_acme_needs_approval(
    engine: CedarPolicyEngine, recipient: str, effect: Effect, reasons: list[str]
) -> None:
    tool = demo_tool("mail", "send_email")
    arguments = {"to": recipient, "subject": "s", "body": "b"}

    assert decide(engine, OLIVIA, tool, arguments) == (effect, reasons)


@pytest.mark.phase(4)
def test_the_mail_rule_applies_to_the_send_tool_only(engine: CedarPolicyEngine) -> None:
    # Without the scope, "no recipient domain" would send every other tool to approval.
    for name in ("list_emails", "read_email"):
        tool = demo_tool("mail", name)
        assert decide(engine, ALICE, tool, {"folder": "inbox"})[0] is Effect.ALLOW, name
    echo = demo_tool("echo", "echo")
    assert decide(engine, ALICE, echo, {"payload": "x"})[0] is Effect.ALLOW


@pytest.mark.phase(4)
def test_the_mail_rule_belongs_to_acme_and_the_transfer_rule_to_the_demo(tmp_path: Path) -> None:
    send = demo_tool("mail", "send_email", tenant="globex")
    operator = BOB.model_copy(update={"groups": ("operators",)})
    arguments = {"to": "x@evil.test", "subject": "s", "body": "b"}
    globex = PolicyStore(POLICY_ROOT, ["acme", "globex"], include_demo=True)
    globex.start()
    without_demo = PolicyStore(POLICY_ROOT, ["acme"], include_demo=False)
    without_demo.start()

    # globex has no mail rule: an operator there sends to anyone.
    assert decide(CedarPolicyEngine(globex), operator, send, arguments) == (
        Effect.ALLOW,
        ["operators-high"],
    )
    # Without the demo pack nothing asks for approval of a transfer.
    transfer = demo_tool("bank", "transfer")
    assert decide(
        CedarPolicyEngine(without_demo), OLIVIA, transfer, {**TRANSFER, "amount": 900}
    ) == (
        Effect.ALLOW,
        ["operators-high"],
    )
