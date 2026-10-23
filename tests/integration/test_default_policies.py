"""KS-407: the default pack validates, and the rules in it do what the demo says."""

import pytest

from keystone.policy.store import load_policies
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.policies import POLICY_ROOT
from tests.fixtures.upstreams import DemoUpstreams

MAIL = {"subject": "Q3", "body": "The numbers are in the reports folder."}


@pytest.mark.phase(4)
def test_default_pack_validates() -> None:
    with_demo = load_policies(POLICY_ROOT, ["acme", "globex"], include_demo=True)
    without = load_policies(POLICY_ROOT, ["acme", "globex"], include_demo=False)

    acme = {(p.id, p.kind) for p in with_demo.tenants["acme"].policies}
    globex = {(p.id, p.kind) for p in with_demo.tenants["globex"].policies}
    base = {
        ("same-tenant-low-medium", "access"),
        ("operators-high", "access"),
        ("admins-critical", "access"),
        ("deny-cross-tenant", "access"),
        # The Rule of Two (KS-705) is every tenant's.
        ("deny-critical-when-tainted", "access"),
        ("rule-of-two", "approval"),
        ("tainted-external-effect", "approval"),
    }
    assert acme == base | {
        ("approve-transfer-over-500", "approval"),
        ("external-email-needs-approval", "approval"),
    }
    assert globex == base | {("approve-transfer-over-500", "approval")}
    # The demo rule is only read when asked for.
    assert {p.id for p in without.policies} >= {"external-email-needs-approval"}
    assert "approve-transfer-over-500" not in {p.id for p in without.policies}
    # Every policy of the pack passed the schema check, and none is a forbid in the approval set.
    assert all(p.effect == "permit" for p in with_demo.policies if p.kind == "approval")


@pytest.mark.services
@pytest.mark.phase(4)
async def test_external_email_requires_approval(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    # Olivia is the one who may send mail at all: send_email is high risk, and support (alice) is
    # refused before the approval rules are asked.
    async with mcp_client(keystone_app, user="olivia") as olivia:
        external = await olivia.call_tool("mail__send_email", {"to": "bob@evil.test", **MAIL})
        internal = await olivia.call_tool("mail__send_email", {"to": "bob@acme.test", **MAIL})
        several = await olivia.call_tool(
            "mail__send_email", {"to": "a@evil.test, b@acme.test", **MAIL}
        )
    async with mcp_client(keystone_app) as alice:
        support = await alice.call_tool("mail__send_email", {"to": "bob@evil.test", **MAIL})

    assert external.is_error and several.is_error and not internal.is_error
    # Nobody decides in this test, so after the wait (a second here) the agent is told the request
    # is pending, with its id (before Phase 6 the approval stub refused it with KS_DENIED).
    for refused in (external, several):
        assert refused.meta is not None
        assert refused.meta["keystone/code"] == "KS_APPROVAL_PENDING"
        assert refused.meta["keystone/approval_id"]
    assert support.meta is not None and support.meta["keystone/reasons"] == ["default-deny"]
    # Only the message to acme.test was sent.
    sent: list[dict[str, str]] = demo_upstreams.state("mail")["sent"]  # type: ignore[assignment]
    assert [m["to"] for m in sent] == ["bob@acme.test"]
    seen = [
        (r["user_id"], r["effect"], tuple(r["reasons"]), r["outcome"], r["dispatched"])
        for r in keystone_app.audit.records
    ]
    assert seen == [
        ("olivia", "require_approval", ("external-email-needs-approval",), "rejected", False),
        ("olivia", "allow", ("operators-high",), "ok", True),
        ("olivia", "require_approval", ("external-email-needs-approval",), "rejected", False),
        ("alice", "deny", ("default-deny",), "rejected", False),
    ]


@pytest.mark.services
@pytest.mark.phase(4)
async def test_a_transfer_over_500_asks_and_nothing_moves_until_it_is_approved(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    transfer = {"from_account": "CHK-001", "to": "SAV-002"}
    async with mcp_client(keystone_app, user="olivia") as olivia:
        big = await olivia.call_tool("bank__transfer", {**transfer, "amount": 900})
        edge = await olivia.call_tool("bank__transfer", {**transfer, "amount": 500})
        cents = await olivia.call_tool("bank__transfer", {**transfer, "amount": 500.5})

    assert big.is_error and cents.is_error and not edge.is_error
    assert len(demo_upstreams.state("bank")["transfers"]) == 1  # type: ignore[arg-type]
    assert [(r["effect"], tuple(r["reasons"])) for r in keystone_app.audit.records] == [
        ("require_approval", ("approve-transfer-over-500",)),
        ("allow", ("operators-high",)),
        ("require_approval", ("approve-transfer-over-500",)),
    ]
