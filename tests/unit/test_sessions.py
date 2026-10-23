import pytest

from keystone.gateway.sessions import InMemorySessionStore
from tests.fixtures.calls import OLIVIA


@pytest.mark.phase(1)
async def test_create_then_get_returns_the_same_state() -> None:
    store = InMemorySessionStore()

    created = await store.create("s1", OLIVIA)
    created.call_count = 3
    await store.save(created)

    fetched = await store.get("s1")
    assert fetched is not None
    assert (fetched.session_id, fetched.principal, fetched.call_count) == ("s1", OLIVIA, 3)
    assert await store.get("missing") is None


@pytest.mark.phase(1)
async def test_the_least_recently_used_session_is_dropped_at_the_cap() -> None:
    store = InMemorySessionStore(max_sessions=2)
    await store.create("a", OLIVIA)
    await store.create("b", OLIVIA)
    await store.get("a")  # a is now the most recent

    await store.create("c", OLIVIA)

    assert await store.get("b") is None
    assert await store.get("a") is not None
    assert await store.get("c") is not None


@pytest.mark.phase(5)
async def test_the_sessions_of_one_tenant_are_listed_newest_first() -> None:
    store = InMemorySessionStore()
    other = OLIVIA.model_copy(update={"tenant_id": "globex", "user_id": "bob"})
    await store.create("a", OLIVIA)
    await store.create("x", other)
    await store.create("b", OLIVIA)
    await store.create("c", OLIVIA)
    await store.get("a")  # a was used last

    mine = await store.list_for_tenant("acme", 10)
    theirs = await store.list_for_tenant("globex", 10)
    few = await store.list_for_tenant("acme", 2)

    assert [s.session_id for s in mine] == ["a", "c", "b"]
    assert [s.session_id for s in theirs] == ["x"]
    assert [s.session_id for s in few] == ["a", "c"]
    assert await store.list_for_tenant("nobody", 10) == []
