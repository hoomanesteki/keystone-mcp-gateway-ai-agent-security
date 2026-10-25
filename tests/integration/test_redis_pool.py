"""KS-992: the Redis pool waits for a connection and does not refuse a burst.

These two need a live Redis. The checks on the pool's construction and settings are in
tests/unit/test_redis_pool.py.
"""

import asyncio

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from keystone.gateway.sessions import RedisSessionStore
from keystone.redis_pool import build_redis

pytestmark = [pytest.mark.phase(9), pytest.mark.services]


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
