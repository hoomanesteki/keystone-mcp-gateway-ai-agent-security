import httpx
import pytest

from keystone.app import create_app
from keystone.settings import Settings


@pytest.mark.phase(1)
async def test_without_a_principal_the_mcp_endpoint_answers_401(clean_env: None) -> None:
    app = create_app(Settings(env="prod"))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
    ) as client:
        response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        health = await client.get("/healthz")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert health.status_code == 200
