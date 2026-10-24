"""KS-807: the audit log can be read for one MCP session, which is where the sessions page links."""

from collections.abc import Callable

import pytest

from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.integration.test_admin_api import audit, call, globex_admin

pytestmark = [pytest.mark.phase(8), pytest.mark.services]

Factory = Callable[..., KeystoneApp]


async def test_audit_can_be_read_for_one_session(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(globex=True)
    async with mcp_client(app) as alice, mcp_client(app, user="olivia") as olivia:
        for n in range(3):
            await alice.call_tool("echo__echo", {"payload": str(n)})
        for n in range(2):
            await olivia.call_tool("echo__echo", {"payload": str(n)})
        await alice.call_tool("bank__get_balance", {"account": "CHK-001"})
    app.audit.wait()
    root = fake_idp.token_for("root")
    everything = audit(app, root, limit=200)["items"]
    sessions = {r["user_id"]: r["session_id"] for r in everything}
    assert len(set(sessions.values())) == 2

    alices = audit(app, root, limit=200, session=sessions["alice"])["items"]
    olivias = audit(app, root, limit=200, session=sessions["olivia"])["items"]
    narrowed = audit(app, root, limit=200, session=sessions["alice"], tool="echo__echo")["items"]

    assert {r["user_id"] for r in alices} == {"alice"} and len(alices) == 4
    assert {r["session_id"] for r in alices} == {sessions["alice"]}
    assert {r["user_id"] for r in olivias} == {"olivia"} and len(olivias) == 2
    assert len(narrowed) == 3 and {r["tool_name"] for r in narrowed} == {"echo__echo"}
    # Newest first, as for every search, and pages of it carry on from where the last one ended.
    assert [r["seq"] for r in alices] == sorted((r["seq"] for r in alices), reverse=True)
    page = audit(app, root, session=sessions["alice"], limit=3)
    rest = audit(app, root, session=sessions["alice"], limit=3, cursor=page["next_cursor"])
    assert [r["seq"] for r in page["items"] + rest["items"]] == [r["seq"] for r in alices]


async def test_a_session_nobody_has_or_of_another_tenant_has_no_records(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(globex=True)
    async with mcp_client(app) as alice:
        await alice.call_tool("echo__echo", {"payload": "x"})
    app.audit.wait()
    root = fake_idp.token_for("root")
    session = audit(app, root, limit=1)["items"][0]["session_id"]

    unknown = audit(app, root, session="no-such-session")["items"]
    other_tenant = audit(app, globex_admin(fake_idp), session=session)["items"]
    answer = call(app, "GET", "/audit", root, params={"session": session})

    assert unknown == [] and other_tenant == []
    assert answer.status_code == 200 and len(answer.json()["items"]) == 1
