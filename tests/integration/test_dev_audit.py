import httpx
import httpx2
import pytest

from keystone.app import create_app
from keystone.settings import Settings
from tests.fixtures.keystone import KeystoneApp, McpConnect


@pytest.mark.services
@pytest.mark.phase(1)
async def test_the_dev_audit_count_follows_the_calls(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    def audit() -> dict[str, object]:
        body: dict[str, object] = httpx2.get(f"{keystone_app.base}/_dev/audit", timeout=10).json()
        return body

    assert audit() == {"count": 0, "recent": []}

    async with mcp_client(keystone_app) as client:
        await client.call_tool("echo__echo", {"payload": "a"})
        await client.call_tool("echo__nothing", {})

    body = audit()
    recent = body["recent"]
    assert body["count"] == 2
    assert isinstance(recent, list)
    assert [(r["tool"], r["outcome"]) for r in recent] == [
        ("echo__echo", "ok"),
        ("echo__nothing", "rejected"),
    ]


@pytest.mark.phase(1)
async def test_prod_has_no_dev_audit_endpoint(clean_env: None) -> None:
    app = create_app(Settings(env="prod", oidc_issuer="https://idp.test/realms/keystone"))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
    ) as client:
        response = await client.get("/_dev/audit")

    assert response.status_code == 404
