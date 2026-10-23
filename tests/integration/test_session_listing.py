"""KS-507: listing the live sessions of a tenant from Redis."""

import pytest
from redis.asyncio import Redis

from keystone.gateway.sessions import RedisSessionStore, session_key
from tests.fixtures.calls import OLIVIA

pytestmark = [pytest.mark.phase(5), pytest.mark.services]


async def test_a_listing_is_limited_to_the_tenant_and_leaves_the_clocks_alone(
    redis: Redis,
) -> None:
    store = RedisSessionStore(redis, ttl_s=1000)
    other = OLIVIA.model_copy(update={"tenant_id": "globex", "user_id": "bob"})
    await store.create("a", OLIVIA)
    await store.create("b", OLIVIA)
    await store.create("x", other)
    await redis.set(session_key("junk"), "not json", ex=1000)  # an entry that is not a session
    await redis.expire(session_key("a"), 500)

    mine = await store.list_for_tenant("acme", 10)
    theirs = await store.list_for_tenant("globex", 10)
    capped = await store.list_for_tenant("acme", 1)

    assert [s.session_id for s in mine] == ["b", "a"]
    assert [s.session_id for s in theirs] == ["x"]
    assert [s.session_id for s in capped] == ["b"]
    # Looking at a session does not keep it alive.
    assert 0 < await redis.ttl(session_key("a")) <= 500
    assert await store.list_for_tenant("nobody", 10) == []
