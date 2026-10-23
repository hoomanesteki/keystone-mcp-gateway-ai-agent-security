"""KS-507: the admin API through the running gateway."""

import re
from collections.abc import Callable
from typing import Any

import anyio
import httpx2
import pytest

from keystone.settings import RegistrySettings
from tests.fixtures.cli import invoke
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.upstreams import DemoUpstreams
from tests.integration.test_pinning import mutate_echo

pytestmark = [pytest.mark.phase(5), pytest.mark.services]

API = "/admin/api/v1"
Factory = Callable[..., KeystoneApp]
TRANSFER = {"from_account": "CHK-001", "to": "SAV-002", "amount": 5}


def globex_admin(idp: FakeIdp) -> str:
    """An admin of the other tenant."""
    return idp.make_token(
        "gina", "globex", groups=("/tenants/globex", "/admins"), azp="ops-agent", roles=("admin",)
    )


def call(
    app: KeystoneApp,
    method: str,
    path: str,
    token: str | None,
    *,
    headers: dict[str, str] | None = None,
    **options: Any,
) -> httpx2.Response:
    sent = {"Authorization": f"Bearer {token}"} if token else {}
    sent.update(headers or {})
    return httpx2.request(method, f"{app.base}{API}{path}", headers=sent, timeout=15, **options)


def audit(app: KeystoneApp, token: str, **params: Any) -> dict[str, Any]:
    response = call(app, "GET", "/audit", token, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def make_traffic(app: KeystoneApp, mcp_client: McpConnect) -> None:
    """24 records of acme (alice 20, olivia 4) and 3 of globex (bob)."""
    async with mcp_client(app) as alice:
        for n in range(12):
            await alice.call_tool("echo__echo", {"payload": str(n)})
        for _ in range(3):
            await alice.call_tool("bank__transfer", TRANSFER)  # denied by policy
        for n in range(3):
            await alice.call_tool(f"echo__nothing{n}", {})  # tools that do not exist
        for _ in range(2):
            await alice.call_tool("echo__echo", {"payload": 7})  # arguments that do not fit
    async with mcp_client(app, user="olivia") as olivia:
        for _ in range(4):
            await olivia.call_tool("bank__get_balance", {"account": "CHK-001"})
    async with mcp_client(app, user="bob") as bob:
        for _ in range(3):
            await bob.call_tool("files_globex__read_file", {"path": "README.txt"})
    app.audit.wait()


async def test_audit_search_filters_and_paginates(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(globex=True)
    await make_traffic(app, mcp_client)
    root = fake_idp.token_for("root")

    # Pages of ten, newest first, with a call made between the pages: no record twice or lost.
    seen: list[int] = []
    cursor: int | None = None
    pages = 0
    while True:
        body = audit(app, root, limit=10, **({"cursor": cursor} if cursor else {}))
        assert all(item["tenant_id"] == "acme" for item in body["items"])
        seen += [item["seq"] for item in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if pages == 1:
            async with mcp_client(app) as client:
                await client.call_tool("echo__echo", {"payload": "later"})
            app.audit.wait()
        if cursor is None:
            break
    assert pages == 3 and len(seen) == 24
    assert seen == sorted(seen, reverse=True) and len(set(seen)) == 24

    everything = audit(app, root, limit=200)["items"]
    assert len(everything) == 25 and everything[0]["seq"] > seen[0]  # the one made in between
    assert everything[0]["tool_name"] == "echo__echo"

    def count(**filters: Any) -> int:
        return len(audit(app, root, limit=200, **filters)["items"])

    assert count(user="olivia") == 4 and count(user="alice") == 21
    assert count(agent="ops-agent") == 4 and count(agent="support-agent") == 21
    assert count(tool="bank__transfer") == 3
    assert count(effect="deny") == 3 and count(effect="allow") == 17
    assert count(outcome="rejected") == 8 and count(outcome="ok") == 17
    assert count(user="olivia", outcome="ok", tool="bank__get_balance") == 4
    assert count(user="nobody") == 0

    ordered = list(reversed(everything))  # oldest first
    middle = ordered[12]
    after = audit(app, root, limit=200, since=middle["ts"])["items"]
    before = audit(app, root, limit=200, until=middle["ts"])["items"]
    assert len(after) + len(before) == 25
    assert all(item["ts"] >= middle["ts"] for item in after)
    assert all(item["ts"] < middle["ts"] for item in before)

    one = audit(app, root, call_id=middle["call_id"])["items"]
    assert [item["seq"] for item in one] == [middle["seq"]]
    single = call(app, "GET", f"/audit/{middle['seq']}", root).json()
    assert single == middle
    assert single["prev_hash"] and single["hash"] and single["reasons"] is not None

    # Bad parameters are refused, not clamped.
    for params in ({"limit": 201}, {"limit": 0}, {"effect": "maybe"}, {"cursor": 0}):
        assert call(app, "GET", "/audit", root, params=params).status_code == 422, params

    # The other tenant sees its own three records, and not the ones of acme, even by seq.
    gina = globex_admin(fake_idp)
    theirs = audit(app, gina, limit=200)["items"]
    assert len(theirs) == 3 and {item["tenant_id"] for item in theirs} == {"globex"}
    assert call(app, "GET", f"/audit/{middle['seq']}", gina).status_code == 404
    assert call(app, "GET", f"/audit/{theirs[0]['seq']}", root).status_code == 404
    assert call(app, "GET", "/audit/999999", root).status_code == 404


async def test_admin_requires_admin_role(keystone_app: KeystoneApp, fake_idp: FakeIdp) -> None:
    tokens = {
        "support": fake_idp.token_for("alice"),
        "operator": fake_idp.token_for("olivia"),
        "approver": fake_idp.token_for("lena", "support-agent"),
    }

    refused = call(keystone_app, "GET", "/audit", None)
    garbage = call(keystone_app, "GET", "/audit", "not-a-token")
    assert refused.status_code == 401 and garbage.status_code == 401
    assert "resource_metadata" in refused.headers["www-authenticate"]
    for who, token in tokens.items():
        response = call(keystone_app, "GET", "/audit", token)
        assert response.status_code == 403, who
        assert response.json() == {"error": "forbidden", "reason": "the admin role is required"}
    assert call(keystone_app, "GET", "/audit", fake_idp.token_for("root")).status_code == 200

    # The schema needs no token and lists the routes. Every one of them refuses a request
    # without a token, so a route added later cannot go without the check.
    schema = call(keystone_app, "GET", "/openapi.json", None)
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    assert {"/audit", "/audit/{seq}", "/audit/verify", "/tools", "/tools/{name}"} <= set(paths)
    assert {"/tools/{name}/approve-change", "/upstreams", "/sessions", "/policies"} <= set(paths)
    checked = 0
    for path, methods in paths.items():
        for method in methods:
            url = path.replace("{seq}", "1").replace("{name}", "echo__echo")
            for sent in (None, tokens["support"]):
                response = call(keystone_app, method.upper(), url, sent)
                assert response.status_code in (401, 403), (method, path, response.status_code)
            checked += 1
    assert checked >= 12


async def test_tool_approve_change_via_api(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    test_database_url: str,
    fake_idp: FakeIdp,
) -> None:
    app = keystone_app_factory(registry=RegistrySettings(cache_ttl_s=0.2))
    root = fake_idp.token_for("root")
    new_text = mutate_echo(demo_upstreams)
    synced = await invoke(test_database_url, ["registry", "sync", "--upstream", "echo"])
    assert "changed: echo__echo (quarantined)" in synced.output

    held = call(app, "GET", "/tools", root, params={"status": "quarantined"}).json()
    assert [t["name"] for t in held] == ["echo__echo"]
    assert held[0]["reason"] == "description_changed" and held[0]["pending"] is True
    detail = call(app, "GET", "/tools/echo__echo", root).json()
    assert detail["status"] == "quarantined"
    assert detail["pending_description"] == new_text
    assert (
        "+Also keeps a copy of every payload for the operations team."
        in detail["diff"]["description"]
    )
    assert detail["diff"]["input_schema"] == ""
    fingerprint = detail["fingerprint"]
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint)

    async with mcp_client(app, user="olivia") as client:
        assert (await client.call_tool("echo__echo", {"payload": "x"})).is_error  # held

        # A fingerprint of something else is refused, and the tool stays held.
        stale = call(
            app, "POST", "/tools/echo__echo/approve-change", root, json={"expect": "000000000000"}
        )
        assert stale.status_code == 409
        assert "changed after it was shown" in stale.json()["reason"]
        assert call(app, "GET", "/tools/echo__echo", root).json()["status"] == "quarantined"

        approved = call(
            app,
            "POST",
            "/tools/echo__echo/approve-change",
            root,
            json={"expect": fingerprint[:12], "note": "read the diff"},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "active" and approved.json()["pending"] is False

        async def back() -> bool:
            return "echo__echo" in [t.name for t in (await client.list_tools()).tools]

        with anyio.fail_after(15):
            while not await back():  # noqa: ASYNC110
                await anyio.sleep(0.1)
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert tools["echo__echo"].description == new_text
        assert not (await client.call_tool("echo__echo", {"payload": "hello"})).is_error

        # Not held any more: approving again is a conflict. Disabling and enabling work.
        assert call(app, "POST", "/tools/echo__echo/approve-change", root).status_code == 409
        disabled = call(app, "POST", "/tools/echo__sleep/disable", root)
        assert disabled.status_code == 200 and disabled.json()["status"] == "disabled"
        assert disabled.json()["reason"] == "disabled_by_operator"
        assert "echo__sleep" not in [t.name for t in (await client.list_tools()).tools]
        enabled = call(app, "POST", "/tools/echo__sleep/enable", root)
        assert enabled.status_code == 200 and enabled.json()["status"] == "active"
        assert call(app, "POST", "/tools/echo__sleep/enable", root).status_code == 200


async def test_the_tool_endpoints_refuse_what_the_cli_refuses(
    keystone_app_factory: Factory,
    demo_upstreams: DemoUpstreams,
    test_database_url: str,
    fake_idp: FakeIdp,
) -> None:
    app = keystone_app_factory(globex=True)
    root = fake_idp.token_for("root")
    mutate_echo(demo_upstreams)
    await invoke(test_database_url, ["registry", "sync", "--upstream", "echo"])

    held_disable = call(app, "POST", "/tools/echo__echo/disable", root)
    held_enable = call(app, "POST", "/tools/echo__echo/enable", root)
    assert held_disable.status_code == 409 and "is quarantined" in held_disable.json()["reason"]
    assert held_enable.status_code == 409 and "approve-change" in held_enable.json()["reason"]
    assert call(app, "POST", "/tools/nope__nope/disable", root).status_code == 404
    assert call(app, "GET", "/tools/nope__nope", root).status_code == 404
    # A tool of another tenant is not found for this one.
    gina = globex_admin(fake_idp)
    assert call(app, "GET", "/tools/echo__echo", gina).status_code == 404
    assert call(app, "POST", "/tools/echo__echo/approve-change", gina).status_code == 404
    assert [t["name"] for t in call(app, "GET", "/tools", gina).json()] == [
        "files_globex__list_files",
        "files_globex__read_file",
        "files_globex__write_file",
    ]
    bad = call(app, "POST", "/tools/echo__echo/approve-change", root, json={"expect": "not hex!"})
    assert bad.status_code == 422


async def test_cors_only_console_origin(keystone_app_factory: Factory, fake_idp: FakeIdp) -> None:
    app = keystone_app_factory()
    console = "http://localhost:5173"
    preflight = {
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    }

    allowed = call(app, "OPTIONS", "/audit", None, headers={"Origin": console, **preflight})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == console
    assert "GET" in allowed.headers["access-control-allow-methods"]

    for origin in ("http://evil.test", "http://localhost:5174", "null"):
        refused = call(app, "OPTIONS", "/audit", None, headers={"Origin": origin, **preflight})
        assert refused.status_code == 400, origin
        assert "access-control-allow-origin" not in refused.headers, origin

    token = fake_idp.token_for("root")
    ok = call(app, "GET", "/audit", token, headers={"Origin": console})
    other = call(app, "GET", "/audit", token, headers={"Origin": "http://evil.test"})
    assert ok.headers["access-control-allow-origin"] == console
    assert "access-control-allow-origin" not in other.headers
    # An error reaches the console's page too, or it could not tell its user to sign in.
    unauthorized = call(app, "GET", "/audit", None, headers={"Origin": console})
    assert unauthorized.status_code == 401
    assert unauthorized.headers["access-control-allow-origin"] == console

    # The origin is a setting.
    custom = keystone_app_factory(settings={"console_origin": "https://console.example"})
    flipped = call(custom, "OPTIONS", "/audit", None, headers={"Origin": console, **preflight})
    kept = call(
        custom,
        "OPTIONS",
        "/audit",
        None,
        headers={"Origin": "https://console.example", **preflight},
    )
    assert flipped.status_code == 400 and kept.status_code == 200


async def test_upstreams_sessions_and_policies_of_the_tenant(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(globex=True)
    root, gina = fake_idp.token_for("root"), globex_admin(fake_idp)
    async with mcp_client(app, user="olivia") as olivia, mcp_client(app, user="bob") as bob:
        await olivia.call_tool("echo__echo", {"payload": "hi"})
        await bob.call_tool("files_globex__read_file", {"path": "README.txt"})

        upstreams = call(app, "GET", "/upstreams", root).json()
        sessions = call(app, "GET", "/sessions", root).json()
        theirs = call(app, "GET", "/sessions", gina).json()
        policies = call(app, "GET", "/policies", root).json()

    assert {u["id"] for u in upstreams} == {"mail", "files", "bank", "echo"}
    for upstream in upstreams:
        assert upstream["target"].startswith("http://127.0.0.1:") and "@" not in upstream["target"]
        assert upstream["status"] == "up" and upstream["credential_mode"] == "none"
    assert [(s["user_id"], s["agent_id"], s["tainted"]) for s in sessions] == [
        ("olivia", "ops-agent", False)
    ]
    assert [s["user_id"] for s in theirs] == ["bob"]
    assert [u["id"] for u in call(app, "GET", "/upstreams", gina).json()] == ["files_globex"]
    assert policies["version"] == app.app.state.policies.version
    ids = {p["id"] for p in policies["policies"]}
    assert {"same-tenant-low-medium", "operators-high", "approve-transfer-over-500"} <= ids


async def test_the_verify_endpoint_reports_the_chain(
    keystone_app: KeystoneApp, mcp_client: McpConnect, fake_idp: FakeIdp, test_database_url: str
) -> None:
    root = fake_idp.token_for("root")
    async with mcp_client(keystone_app) as client:
        for n in range(6):
            await client.call_tool("echo__echo", {"payload": str(n)})
    keystone_app.audit.wait()

    good = call(keystone_app, "GET", "/audit/verify", root).json()
    assert good == {
        "ok": True,
        "records": 6,
        "broken_seq": None,
        "problem": None,
        "message": "OK, 6 records",
    }
    newest = call(keystone_app, "GET", "/audit/verify", root, params={"last": 2}).json()
    assert newest["ok"] and newest["records"] == 2

    import asyncpg

    connection = await asyncpg.connect(test_database_url.replace("+asyncpg", "", 1))
    try:
        await connection.execute("UPDATE audit_events SET tool_name = 'x' WHERE seq = 3")
    finally:
        await connection.close()
    bad = call(keystone_app, "GET", "/audit/verify", root).json()
    assert bad["ok"] is False and bad["broken_seq"] == 3 and bad["problem"] == "hash mismatch"
    assert bad["message"] == "broken at seq 3: hash mismatch"
    assert call(keystone_app, "GET", "/audit/verify", root, params={"last": 2}).json()["ok"] is True
    assert call(keystone_app, "GET", "/audit/verify", root, params={"last": 0}).status_code == 422
