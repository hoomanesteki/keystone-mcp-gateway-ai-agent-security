"""KS-992: the Redis pool waits for a connection and does not refuse a burst."""

import asyncio

import pytest
from redis.asyncio import BlockingConnectionPool
from redis.exceptions import ConnectionError as RedisConnectionError

from keystone.gateway.sessions import RedisSessionStore
from keystone.redis_pool import build_redis
from keystone.settings import Settings

pytestmark = pytest.mark.phase(9)


def test_the_pool_is_a_blocking_pool_of_the_configured_size() -> None:
    client = build_redis("redis://localhost:1/0", pool_size=7, pool_timeout_s=1.5)
    pool = client.connection_pool
    assert isinstance(pool, BlockingConnectionPool)
    assert pool.max_connections == 7
    assert pool.timeout == 1.5


def test_defaults_are_at_least_500_connections_and_a_bounded_wait() -> None:
    settings = Settings()
    assert settings.redis_pool_size >= 500
    assert settings.redis_pool_timeout_s == 2.0


def test_the_pool_settings_are_checked() -> None:
    with pytest.raises(ValueError):
        Settings(redis_pool_size=0)
    with pytest.raises(ValueError):
        Settings(redis_pool_timeout_s=0)


@pytest.mark.services
async def test_300_concurrent_session_reads_against_a_pool_of_20_all_succeed(
    test_redis_url: str,
) -> None:
    client = build_redis(test_redis_url, pool_size=20, pool_timeout_s=5.0)
    try:
        store = RedisSessionStore(client, None)
        results = await asyncio.gather(*(store.get(f"s{i}") for i in range(300)))
        assert results == [None] * 300
    finally:
        await client.aclose()


@pytest.mark.services
async def test_a_caller_that_waits_longer_than_the_bound_is_refused(test_redis_url: str) -> None:
    client = build_redis(test_redis_url, pool_size=1, pool_timeout_s=0.2)
    try:
        held = await client.connection_pool.get_connection()
        try:
            with pytest.raises(RedisConnectionError):
                await client.ping()
        finally:
            await client.connection_pool.release(held)
        assert await client.ping()
    finally:
        await client.aclose()
