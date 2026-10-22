"""A Redis client on database 15, emptied before and after each test that asks for it.

Tests use database 15 and the app under test is pointed at it too, so no test reads what another
left behind and a developer's data in database 0 is never touched.
"""

from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import pytest
from redis.asyncio import Redis

from keystone.settings import Settings

TEST_DATABASE = 15


def with_redis_database(url: str, database: int) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{database}"))


@pytest.fixture(scope="session")
def test_redis_url() -> str:
    return with_redis_database(Settings().redis_url.get_secret_value(), TEST_DATABASE)


@pytest.fixture
async def redis(test_redis_url: str) -> AsyncIterator[Redis]:
    assert test_redis_url.endswith(f"/{TEST_DATABASE}"), (
        "refusing to flush a database that is not 15"
    )
    client = Redis.from_url(test_redis_url, decode_responses=True)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()
