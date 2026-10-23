"""KS-307: one gateway, two tenants, and neither can see or call the other's tools."""

import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest

from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.upstreams import DemoUpstreams, GlobexFiles

pytestmark = [pytest.mark.phase(3), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
GLOBEX_TOOLS = {"files_globex__list_files", "files_globex__read_file", "files_globex__write_file"}
HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


async def test_bob_lists_only_globex(keystone_app_factory: Factory, mcp_client: McpConnect) -> None:
    app = keystone_app_factory(globex=True)

    async with mcp_client(app, user="bob") as bob:
        bobs = {t.name for t in (await bob.list_tools()).tools}
    async with mcp_client(app, user="olivia") as olivia:  # an operator sees all twelve (KS-406)
        olivias = {t.name for t in (await olivia.list_tools()).tools}

    assert bobs == GLOBEX_TOOLS
    assert len(olivias) == 12 and olivias.isdisjoint(GLOBEX_TOOLS)
    assert {name.partition("__")[0] for name in olivias} == {"mail", "files", "bank", "echo"}


async def test_bob_cannot_call_acme_tool(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(globex=True)

    async with mcp_client(app, user="bob") as bob:
        transfer = await bob.call_tool(
            "bank__transfer", {"from_account": "CHK-001", "to": "SAV-002", "amount": 5}
        )
        balance = await bob.call_tool("bank__get_balance", {"account": "CHK-001"})

    for result in (transfer, balance):
        assert result.is_error
        assert result.meta is not None and result.meta["keystone/code"] == "KS_TOOL_NOT_FOUND"
    assert demo_upstreams.state("bank")["calls"] == []
    assert demo_upstreams.state("bank")["transfers"] == []
    assert [
        (r["tenant_id"], r["user_id"], r["outcome"], r["dispatched"]) for r in app.audit.records
    ] == [
        ("globex", "bob", "rejected", False),
        ("globex", "bob", "rejected", False),
    ]


async def test_alice_cannot_call_a_globex_tool_either(
    keystone_app_factory: Factory, mcp_client: McpConnect, globex_files: GlobexFiles
) -> None:
    app = keystone_app_factory(globex=True)

    async with mcp_client(app, user="alice") as alice:
        result = await alice.call_tool("files_globex__read_file", {"path": "README.txt"})

    assert result.is_error
    assert result.meta is not None and result.meta["keystone/code"] == "KS_TOOL_NOT_FOUND"
    assert globex_files.state()["calls"] == []


async def test_each_tenant_reaches_its_own_drive(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(globex=True)

    async with mcp_client(app, user="bob") as bob:
        drive = await bob.call_tool("files_globex__read_file", {"path": "README.txt"})
        written = await bob.call_tool(
            "files_globex__write_file", {"path": "projects/todo.md", "content": "ship it"}
        )
    async with mcp_client(app, user="alice") as alice:
        shared = await alice.call_tool("files__read_file", {"path": "README.txt"})

    assert "Globex shared drive" in texts(drive)[0]
    assert not written.is_error
    assert "Shared team workspace" in texts(shared)[0]


async def test_an_unknown_tool_and_another_tenants_tool_look_the_same(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(globex=True)

    async with mcp_client(app, user="bob") as bob:
        real_elsewhere = await bob.call_tool("bank__get_balance", {"account": "CHK-001"})
        nowhere = await bob.call_tool("bank__get_balances", {"account": "CHK-001"})

    def shape(text: str, name: str) -> str:
        return text.replace(name, "<name>").split(" call ")[0] + text.split(": ", 1)[1].replace(
            name, "<name>"
        )

    assert shape(texts(real_elsewhere)[0], "bank__get_balance") == shape(
        texts(nowhere)[0], "bank__get_balances"
    )
    for result in (real_elsewhere, nowhere):
        assert result.meta is not None
        assert set(result.meta) == {"keystone/code", "keystone/call_id"}


async def test_a_request_cannot_name_another_tenant(
    keystone_app_factory: Factory, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(globex=True)
    bob = fake_idp.token_for("bob")
    opened = httpx2.post(
        app.url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
                "tenant": "acme",
                "_meta": {"tenant": "acme"},
            },
        },
        headers={
            **HEADERS,
            "authorization": f"Bearer {bob}",
            "x-tenant": "acme",
            "x-tenant-id": "acme",
        },
        timeout=10,
    )
    session = opened.headers["mcp-session-id"]
    sent = {**HEADERS, "authorization": f"Bearer {bob}", "mcp-session-id": session}
    httpx2.post(
        app.url,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=sent,
        timeout=10,
    )

    listed = httpx2.post(
        app.url,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"tenant": "acme", "tenant_id": "acme", "_meta": {"tenant": "acme"}},
        },
        headers={**sent, "x-tenant": "acme", "x-tenant-id": "acme", "x-forwarded-tenant": "acme"},
        timeout=10,
    )

    names = set(tool_names(listed))
    assert names == GLOBEX_TOOLS


def tool_names(response: httpx2.Response) -> list[str]:
    assert response.status_code == 200, response.text
    for line in response.text.splitlines():
        if line.startswith("data:"):
            body: dict[str, Any] = json.loads(line.removeprefix("data:").strip())
            return [tool["name"] for tool in body["result"]["tools"]]
    body = response.json()
    return [tool["name"] for tool in body["result"]["tools"]]


async def test_a_token_for_a_tenant_that_is_not_configured_is_refused(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    # bob is in globex, and this app serves only acme.
    refused = httpx2.post(
        keystone_app.url,
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={**HEADERS, "authorization": f"Bearer {fake_idp.token_for('bob')}"},
        timeout=10,
    )

    assert refused.status_code == 403
    assert refused.json() == {"error": "forbidden", "reason": "unknown_tenant"}
