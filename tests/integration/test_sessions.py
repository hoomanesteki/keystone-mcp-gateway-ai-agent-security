"""KS-207: session state in Redis, and the durable row in Postgres."""

import json
from collections.abc import Callable

import anyio
import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import Principal, SessionState, ToolTag
from keystone.db.models import McpSession
from keystone.db.tenants import upsert_tenants
from keystone.gateway.session_repo import SessionRepo
from keystone.gateway.sessions import RedisSessionStore, session_key
from keystone.settings import TenantConfig
from tests.fixtures.calls import OLIVIA
from tests.fixtures.keystone import KeystoneApp, McpConnect

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]


async def rows(sessions: Sessions) -> list[McpSession]:
    async with sessions() as session:
        return list((await session.scalars(select(McpSession).order_by(McpSession.id))).all())


async def store_with_rows(redis: Redis, sessions: Sessions, **options: object) -> RedisSessionStore:
    await upsert_tenants(sessions, [TenantConfig(id="acme", name="Acme Corp")])
    return RedisSessionStore(redis, SessionRepo(sessions), **options)  # type: ignore[arg-type]


async def test_redis_session_roundtrip(redis: Redis, sessionmaker: Sessions) -> None:
    store = await store_with_rows(redis, sessionmaker)

    created = await store.create("s-1", OLIVIA)
    created.flags.add(ToolTag.READS_UNTRUSTED)
    created.tainted = True
    created.call_count = 3
    created.spent_usd = 0.25
    await store.save(created)
    again = await store.get("s-1")

    assert again == created
    assert again is not None and again.principal == OLIVIA
    assert again.flags == {ToolTag.READS_UNTRUSTED} and again.tainted
    assert (again.call_count, again.spent_usd) == (3, 0.25)
    stored = json.loads(await redis.get(session_key("s-1")) or "{}")
    assert stored["session_id"] == "s-1"
    assert stored["principal"]["user_id"] == "olivia"
    assert await store.get("never-seen") is None


async def test_a_second_store_sees_the_state_of_the_first(
    redis: Redis, sessionmaker: Sessions
) -> None:
    # What a restart or a second gateway process would see.
    first = await store_with_rows(redis, sessionmaker)
    state = await first.create("s-1", OLIVIA)
    state.tainted = True
    await first.save(state)

    second = RedisSessionStore(redis, SessionRepo(sessionmaker))

    reloaded = await second.get("s-1")
    assert reloaded is not None and reloaded.tainted is True


async def test_session_ttl_refreshed(redis: Redis, sessionmaker: Sessions) -> None:
    store = await store_with_rows(redis, sessionmaker, ttl_s=10)
    state = await store.create("s-1", OLIVIA)
    assert 9_000 < await redis.pttl(session_key("s-1")) <= 10_000

    await anyio.sleep(1.2)
    aged = await redis.pttl(session_key("s-1"))
    await store.get("s-1")
    after_get = await redis.pttl(session_key("s-1"))
    await anyio.sleep(1.2)
    await store.save(state)
    after_save = await redis.pttl(session_key("s-1"))

    assert aged < 9_000
    assert after_get > 9_500
    assert after_save > 9_500


async def test_the_default_lifetime_is_24_hours(redis: Redis, sessionmaker: Sessions) -> None:
    store = await store_with_rows(redis, sessionmaker)

    await store.create("s-1", OLIVIA)

    assert 86_390 <= await redis.ttl(session_key("s-1")) <= 86_400


async def test_session_row_written(redis: Redis, sessionmaker: Sessions) -> None:
    store = await store_with_rows(redis, sessionmaker)

    state = await store.create("s-1", OLIVIA)
    await store.create("s-1", OLIVIA)  # a second create of the same session adds no row

    [row] = await rows(sessionmaker)
    assert (row.id, row.tenant_id, row.user_id, row.agent_id) == (
        "s-1",
        "acme",
        "olivia",
        "ops-agent",
    )
    assert row.started_at == state.created_at
    assert (row.final_flags, row.tainted) == ([], False)


async def test_creating_a_session_twice_keeps_the_first_state(
    redis: Redis, sessionmaker: Sessions
) -> None:
    store = await store_with_rows(redis, sessionmaker)
    first = await store.create("s-1", OLIVIA)
    first.call_count = 5
    await store.save(first)

    second = await store.create("s-1", Principal(tenant_id="acme", user_id="x", agent_id="y"))

    assert second.call_count == 5 and second.principal == OLIVIA


async def test_the_row_is_touched_at_most_once_a_minute(
    redis: Redis, sessionmaker: Sessions
) -> None:
    now = [100.0]
    store = await store_with_rows(redis, sessionmaker, clock=lambda: now[0])
    state = await store.create("s-1", OLIVIA)
    [created] = await rows(sessionmaker)

    state.flags.add(ToolTag.EXTERNAL_EFFECT)
    now[0] = 130.0
    await store.save(state)  # 30 s after the row was written: no write
    [soon] = await rows(sessionmaker)

    now[0] = 161.0
    state.tainted = True
    await store.save(state)  # 61 s: written, with the flags and the taint it has by now
    [later] = await rows(sessionmaker)

    assert soon.last_seen_at == created.last_seen_at
    assert soon.final_flags == []
    assert later.last_seen_at > created.last_seen_at
    assert later.final_flags == ["external_effect"] and later.tainted is True
    # The live state in Redis was written every time.
    live = await store.get("s-1")
    assert live is not None and live.tainted is True


async def test_a_state_in_redis_that_cannot_be_read_is_a_session_we_have_not_seen(
    redis: Redis, sessionmaker: Sessions
) -> None:
    store = await store_with_rows(redis, sessionmaker)
    await redis.set(session_key("s-1"), "{not json")
    await redis.set(session_key("s-2"), '{"session_id": "s-2"}')

    assert await store.get("s-1") is None
    assert await store.get("s-2") is None


async def test_a_postgres_failure_does_not_stop_a_session(
    redis: Redis, sessionmaker: Sessions
) -> None:
    # The tenant is missing, so the row cannot be written (it references tenants).
    store = RedisSessionStore(redis, SessionRepo(sessionmaker))

    state = await store.create("s-1", OLIVIA)

    assert await store.get("s-1") == state
    assert await rows(sessionmaker) == []


async def test_a_redis_failure_is_raised(sessionmaker: Sessions) -> None:
    broken = Redis.from_url("redis://127.0.0.1:1/15", socket_connect_timeout=0.3)
    store = RedisSessionStore(broken, SessionRepo(sessionmaker))
    try:
        with pytest.raises(RedisError):
            await store.get("s-1")
        with pytest.raises(RedisError):
            await store.create("s-1", OLIVIA)
    finally:
        await broken.aclose()


async def test_the_gateway_writes_the_row_on_the_first_call_of_a_new_session(
    keystone_app: KeystoneApp, mcp_client: McpConnect, redis: Redis, sessionmaker: Sessions
) -> None:
    async with mcp_client(keystone_app) as client:
        await client.call_tool("echo__echo", {"payload": "one"})
        await client.call_tool("echo__echo", {"payload": "two"})
    async with mcp_client(keystone_app) as client:
        await client.call_tool("echo__echo", {"payload": "three"})

    first, second = {r["session_id"] for r in keystone_app.audit.records}, None
    found = await rows(sessionmaker)
    assert {r.id for r in found} == first
    assert len(found) == 2
    assert {(r.tenant_id, r.user_id, r.agent_id) for r in found} == {
        ("acme", "olivia", "ops-agent")
    }
    for row in found:
        state = SessionState.model_validate_json(await redis.get(session_key(row.id)) or "")
        assert state.principal.user_id == "olivia"
    assert second is None


async def test_a_list_before_any_call_stores_nothing(
    keystone_app: KeystoneApp, mcp_client: McpConnect, redis: Redis, sessionmaker: Sessions
) -> None:
    async with mcp_client(keystone_app) as client:
        await client.list_tools()

    assert await rows(sessionmaker) == []
    assert [key async for key in redis.scan_iter("ks:sess:*")] == []


async def test_a_call_is_refused_and_audited_when_the_session_state_cannot_be_read(
    keystone_app_factory: Callable[..., KeystoneApp], mcp_client: McpConnect
) -> None:
    app = keystone_app_factory()

    class Broken:
        async def get(self, session_id: str) -> None:
            raise ConnectionResetError("redis is gone")

        async def create(self, session_id: str, principal: Principal) -> None:
            raise ConnectionResetError("redis is gone")

        async def save(self, state: SessionState) -> None:
            raise ConnectionResetError("redis is gone")

    app.app.state.gateway.sessions = Broken()
    async with mcp_client(app) as client:
        result = await client.call_tool("echo__echo", {"payload": "x"})

    assert result.is_error
    assert result.meta is not None and result.meta["keystone/code"] == "KS_DENIED"
    [record] = app.audit.records
    assert (record["outcome"], record["reject_code"], record["dispatched"]) == (
        "rejected",
        "KS_DENIED",
        False,
    )
