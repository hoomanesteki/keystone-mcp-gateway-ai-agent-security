import asyncio
import time
from collections.abc import AsyncIterator

import httpx
import pytest
from pydantic import SecretStr

from keystone.app import create_app
from keystone.settings import Settings

CLOSED_PORT_REDIS = "redis://127.0.0.1:1/0"


async def get_readyz(settings: Settings) -> httpx.Response:
    transport = httpx.ASGITransport(app=create_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="http://keystone") as client:
        return await client.get("/readyz")


def without_upstreams(response: httpx.Response) -> dict[str, object]:
    body: dict[str, object] = response.json()
    body.pop("upstreams", None)
    return body


@pytest.fixture
async def silent_port() -> AsyncIterator[int]:
    """A TCP server that accepts connections and never answers."""

    async def hold(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(30)
        writer.close()

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()


@pytest.mark.phase(0)
@pytest.mark.services
async def test_readyz_reports_dependencies(settings: Settings) -> None:
    up = await get_readyz(settings)
    assert up.status_code == 200
    # KS-209 added an `upstreams` object. Which upstreams a database holds is not this test's
    # business, so only its type is checked here.
    assert without_upstreams(up) == {
        "status": "ok",
        "dependencies": {"database": "ok", "redis": "ok"},
    }
    assert isinstance(up.json()["upstreams"], dict)

    down = await get_readyz(settings.model_copy(update={"redis_url": SecretStr(CLOSED_PORT_REDIS)}))
    assert down.status_code == 503
    assert without_upstreams(down) == {
        "status": "unavailable",
        "dependencies": {"database": "ok", "redis": "unavailable"},
    }


@pytest.mark.phase(0)
async def test_readyz_gives_up_on_a_hung_dependency(settings: Settings, silent_port: int) -> None:
    hung = settings.model_copy(
        update={
            "database_url": SecretStr(f"postgresql+asyncpg://u:p@127.0.0.1:{silent_port}/db"),
            "redis_url": SecretStr(f"redis://127.0.0.1:{silent_port}/0"),
        }
    )

    started = time.monotonic()
    response = await get_readyz(hung)
    elapsed = time.monotonic() - started

    assert response.status_code == 503
    assert response.json()["dependencies"] == {"database": "unavailable", "redis": "unavailable"}
    assert elapsed < 2.5
