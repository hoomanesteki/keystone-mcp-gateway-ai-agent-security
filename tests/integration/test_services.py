import asyncpg
import pytest
import redis.asyncio

from keystone.settings import Settings


@pytest.mark.phase(0)
@pytest.mark.services
async def test_postgres_and_redis_reachable(clean_env: None) -> None:
    settings = Settings()

    dsn = settings.database_url.get_secret_value().replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn, timeout=5)
    try:
        assert "PostgreSQL 16" in await conn.fetchval("SELECT version()")
    finally:
        await conn.close()

    client = redis.asyncio.Redis.from_url(
        settings.redis_url.get_secret_value(), socket_connect_timeout=5, socket_timeout=5
    )
    try:
        assert await client.ping() is True
        assert (await client.info("server"))["redis_version"].startswith("7.")
    finally:
        await client.aclose()
