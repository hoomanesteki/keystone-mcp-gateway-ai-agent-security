"""I6: with an empty policy set, every call is denied.

The engine is asked about every kind of caller, tool and action, with the rules empty in the ways
a deployment can end up with: no policy files at all, files that hold only comments, and an
approval set that would approve anything. Nothing may be allowed, and nothing may be sent to
approval either, because an approval permit is only asked after the access set allowed. The
reason is `default-deny`, not `policy-error`: an empty set is a valid set, and it says no.
"""

import itertools
from collections.abc import Callable
from pathlib import Path

import pytest

from keystone.core.types import (
    Effect,
    Principal,
    Risk,
    SessionState,
    ToolRef,
    ToolTag,
)
from keystone.policy.engine import DEFAULT_DENY, CedarPolicyEngine
from keystone.policy.entities import Action, build_context
from keystone.policy.store import PolicyStore
from keystone.settings import PolicySettings
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.policies import permit, write_policies
from tests.fixtures.upstreams import NAMES, DemoUpstreams

TENANTS = ("acme", "globex")
PRINCIPALS = [
    Principal(tenant_id="acme", user_id="alice", groups=("support",), agent_id="support-agent"),
    Principal(
        tenant_id="acme",
        user_id="olivia",
        groups=("operators",),
        agent_id="ops-agent",
        agent_trust="high",
        roles=("approver",),
    ),
    Principal(
        tenant_id="acme",
        user_id="root",
        groups=("admins", "operators", "support"),
        agent_id="ops-agent",
        agent_trust="high",
        roles=("admin",),
    ),
    Principal(tenant_id="globex", user_id="bob", agent_id="support-agent", agent_trust="low"),
]
ACTIONS: tuple[Action, ...] = ("call_tool", "list_tool")
ARGUMENTS: list[dict[str, int | str | bool]] = [
    {},
    {"amount": 900},
    {"recipient_domain": "evil.test", "count": 3, "path": "/etc/passwd"},
]
SESSIONS = [
    (frozenset(), False),
    (frozenset({ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE}), True),
]


def empty_ways(tmp_path: Path) -> dict[str, Path]:
    """Policy roots that hold no rule that could allow anything."""
    nothing = write_policies(tmp_path / "nothing")
    (nothing / "default" / "access").mkdir(parents=True)
    comments = write_policies(
        tmp_path / "comments", {"default/access/base.cedar": "// the rules are being rewritten\n"}
    )
    approves_everything = write_policies(
        tmp_path / "approval-only",
        {
            "default/approval/all.cedar": permit("ask-for-everything"),
            "acme/approval/all.cedar": permit("ask-in-acme"),
        },
    )
    (approves_everything / "default" / "access").mkdir(parents=True)
    return {
        "no files": nothing,
        "only comments": comments,
        "an approval set that asks for everything": approves_everything,
    }


def tools() -> list[ToolRef]:
    found = []
    for risk, tags in itertools.product(Risk, (frozenset(), frozenset({ToolTag.EXTERNAL_EFFECT}))):
        tool = make_tool("bank", f"tool_{risk.value}", risk=risk, tags=tags)
        found.append(tool)
        found.append(tool.model_copy(update={"tenant_id": "globex"}))
    return found


@pytest.mark.phase(4)
def test_i6(tmp_path: Path) -> None:
    asked = 0
    for name, root in empty_ways(tmp_path).items():
        store = PolicyStore(root, TENANTS)
        store.start()
        engine = CedarPolicyEngine(store)
        for principal, tool, action, args, (flags, tainted) in itertools.product(
            PRINCIPALS, tools(), ACTIONS, ARGUMENTS, SESSIONS
        ):
            session = SessionState(
                session_id="s",
                principal=principal,
                flags=set(flags),
                tainted=tainted,
                created_at=make_ctx().received_at,
            )
            call = make_ctx(tool=tool, principal=principal, session=session)
            decision = engine.evaluate(principal, action, tool, build_context(call, args))
            asked += 1

            where = f"{name}: {principal.user_id} {action} {tool.name} in {tool.tenant_id}"
            assert decision.effect is Effect.DENY, where
            assert decision.reasons == [DEFAULT_DENY], where
            assert decision.source == "policy" and decision.policy_version == store.version
    assert asked == 3 * len(PRINCIPALS) * len(tools()) * len(ACTIONS) * len(ARGUMENTS) * len(
        SESSIONS
    )


CALLS: list[tuple[str, dict[str, object]]] = [
    ("echo__echo", {"payload": "x"}),
    ("mail__list_emails", {"folder": "inbox"}),
    ("mail__send_email", {"to": "x@acme.test", "subject": "s", "body": "b"}),
    ("files__read_file", {"path": "README.txt"}),
    ("bank__get_balance", {"account": "CHK-001"}),
    ("bank__transfer", {"from_account": "CHK-001", "to": "SAV-002", "amount": 5}),
]


@pytest.mark.services
@pytest.mark.phase(4)
async def test_i6_through_the_gateway(
    keystone_app_factory: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    tmp_path: Path,
) -> None:
    """The same thing end to end: with no rule that allows anything, an operator and an admin get
    no tools and no call reaches an upstream."""
    root = write_policies(tmp_path / "empty")
    (root / "default" / "access").mkdir(parents=True)
    app = keystone_app_factory(settings={"policy": PolicySettings(root=root)})

    for user in ("alice", "olivia", "root"):
        async with mcp_client(app, user=user) as client:
            assert (await client.list_tools()).tools == []
            for name, arguments in CALLS:
                result = await client.call_tool(name, arguments)
                assert result.is_error, f"{user} called {name}"
                assert result.meta is not None
                assert result.meta["keystone/code"] == "KS_DENIED", f"{user} called {name}"
                assert result.meta["keystone/reasons"] == [DEFAULT_DENY]

    assert all(demo_upstreams.state(name)["calls"] == [] for name in NAMES)
    records = app.audit.records
    assert len(records) == 3 * len(CALLS)
    assert {(r["effect"], r["dispatched"], r["reject_code"]) for r in records} == {
        ("deny", False, "KS_DENIED")
    }
