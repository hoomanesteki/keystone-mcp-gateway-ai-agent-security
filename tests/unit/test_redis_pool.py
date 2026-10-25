"""KS-992: the Redis pool is a blocking pool of the configured size.

The two tests that run a burst against a live Redis are in tests/integration/test_redis_pool.py.
"""

import pytest
from redis.asyncio import BlockingConnectionPool

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
