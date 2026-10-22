import httpx
import pytest
from pydantic import SecretStr

from keystone.app import create_app
from keystone.settings import Settings


@pytest.mark.phase(0)
async def test_healthz_is_always_ok(settings: Settings) -> None:
    broken = settings.model_copy(update={"redis_url": SecretStr("redis://127.0.0.1:1/0")})
    transport = httpx.ASGITransport(app=create_app(broken))

    async with httpx.AsyncClient(transport=transport, base_url="http://keystone") as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
