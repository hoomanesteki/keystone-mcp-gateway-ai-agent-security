"""What a call leaves in the audit table, read back from Postgres (the in-memory log and its
`/_dev/audit` route went away with KS-501)."""

from typing import Literal

import httpx
import pytest

from keystone.app import create_app
from keystone.settings import Settings
from tests.fixtures.keystone import KeystoneApp, McpConnect


@pytest.mark.services
@pytest.mark.phase(1)
async def test_the_audit_rows_follow_the_calls(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    assert keystone_app.audit.records == []

    async with mcp_client(keystone_app) as client:
        await client.call_tool("echo__echo", {"payload": "a"})
        await client.call_tool("echo__nothing", {})

    rows = keystone_app.audit.records
    assert [(r["tool_name"], r["outcome"]) for r in rows] == [
        ("echo__echo", "ok"),
        ("echo__nothing", "rejected"),
    ]
    assert [r["seq"] for r in rows] == [1, 2]


@pytest.mark.phase(5)
@pytest.mark.parametrize("env", ["dev", "prod"])
async def test_there_is_no_dev_audit_endpoint(clean_env: None, env: Literal["dev", "prod"]) -> None:
    app = create_app(Settings(env=env, oidc_issuer="https://idp.test/realms/keystone"))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
    ) as client:
        response = await client.get("/_dev/audit")

    assert response.status_code == 404


@pytest.mark.services
@pytest.mark.phase(4)
async def test_the_audit_row_shows_the_decision_and_its_reasons(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:  # alice
        await client.call_tool("echo__echo", {"payload": "a"})
        await client.call_tool(
            "bank__transfer", {"from_account": "CHK-001", "to": "SAV-002", "amount": 5}
        )
        await client.call_tool("echo__nothing", {})

    rows = keystone_app.audit.records

    assert [(r["tool_name"], r["effect"], r["reasons"]) for r in rows] == [
        ("echo__echo", "allow", ["same-tenant-low-medium"]),
        ("bank__transfer", "deny", ["default-deny"]),
        ("echo__nothing", None, []),  # never reached the policy
    ]
