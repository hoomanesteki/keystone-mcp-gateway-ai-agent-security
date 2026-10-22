from collections.abc import Awaitable, Callable
from contextlib import suppress
from urllib.parse import urlsplit

import anyio
import asyncpg
import redis.asyncio
import structlog

from keystone.registry.repo import UpstreamRepo
from keystone.settings import Settings

PROBE_TIMEOUT_S = 1.0

log = structlog.get_logger()


async def check_database(dsn: str) -> bool:
    # asyncpg does not know the SQLAlchemy "+asyncpg" driver suffix.
    plain = dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
    try:
        with anyio.fail_after(PROBE_TIMEOUT_S):
            conn = await asyncpg.connect(plain, timeout=PROBE_TIMEOUT_S)
            try:
                await conn.execute("SELECT 1")
            finally:
                conn.terminate()
    except Exception as exc:
        # Log the type and host only: exception text can contain the DSN.
        log.warning("readyz_probe_failed", dependency="database", error=type(exc).__name__)
        return False
    return True


async def check_redis(url: str) -> bool:
    client = redis.asyncio.Redis.from_url(
        url, socket_connect_timeout=PROBE_TIMEOUT_S, socket_timeout=PROBE_TIMEOUT_S
    )
    try:
        with anyio.fail_after(PROBE_TIMEOUT_S):
            await client.ping()
    except Exception as exc:
        log.warning(
            "readyz_probe_failed",
            dependency="redis",
            host=urlsplit(url).hostname,
            error=type(exc).__name__,
        )
        return False
    finally:
        with suppress(Exception):
            await client.aclose()
    return True


async def check_dependencies(settings: Settings) -> dict[str, bool]:
    """Probe every dependency at once, so the slowest probe sets the latency."""
    results: dict[str, bool] = {}

    async def run(name: str, probe: Callable[[str], Awaitable[bool]], url: str) -> None:
        results[name] = await probe(url)

    async with anyio.create_task_group() as tg:
        tg.start_soon(run, "database", check_database, settings.database_url.get_secret_value())
        tg.start_soon(run, "redis", check_redis, settings.redis_url.get_secret_value())
    return dict(sorted(results.items()))


async def upstream_statuses(upstreams: UpstreamRepo) -> dict[str, str]:
    """Status of every live upstream by id, for /readyz. Empty when the database cannot answer
    in time: /readyz already reports that through its `database` entry."""
    try:
        with anyio.fail_after(PROBE_TIMEOUT_S):
            return {row.id: row.status for row in await upstreams.list(include_disabled=False)}
    except Exception as exc:
        log.warning("readyz_probe_failed", dependency="upstreams", error=type(exc).__name__)
        return {}
