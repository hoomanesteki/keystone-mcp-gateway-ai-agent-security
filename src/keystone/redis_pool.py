"""The one Redis client of the gateway.

Sessions, rate limits, budgets, the policy list cache and the approval pub/sub share this pool.
redis-py's default pool refuses the 101st connection with `MaxConnectionsError`, and a burst of
sessions that all make their first call together hit that (KS-992): the call was refused with
"session state is unavailable". A blocking pool makes the extra callers wait for a connection for
a bounded time, and only a caller that waits longer than that fails.
"""

from redis.asyncio import BlockingConnectionPool, Redis


def build_redis(url: str, *, pool_size: int, pool_timeout_s: float) -> Redis:
    pool = BlockingConnectionPool.from_url(
        url, max_connections=pool_size, timeout=pool_timeout_s, decode_responses=True
    )
    return Redis(connection_pool=pool)
