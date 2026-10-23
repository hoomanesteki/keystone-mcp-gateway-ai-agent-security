"""KS-791: a session changes by merging, never by being written over (ADR-0015).

The rules every store keeps are in `tests/fixtures/session_contract.py`, and the Redis store
runs the same ones in `tests/integration/test_session_merge.py`.
"""

from datetime import UTC, datetime

import pytest

from keystone.core.types import SessionState, ToolTag
from keystone.gateway.sessions import InMemorySessionStore, catch_up, refresh
from tests.fixtures import session_contract as contract
from tests.fixtures.calls import OLIVIA

pytestmark = pytest.mark.phase(7)


async def test_a_stale_copy_saved_late_keeps_the_flag_and_the_taint() -> None:
    await contract.a_stale_copy_saved_late_keeps_the_flag_and_the_taint(InMemorySessionStore())


async def test_flags_are_a_union() -> None:
    await contract.flags_are_a_union(InMemorySessionStore())


async def test_the_taint_is_never_cleared() -> None:
    await contract.the_taint_is_never_cleared(InMemorySessionStore())


async def test_counters_add_up_when_calls_overlap() -> None:
    await contract.counters_add_up_when_calls_overlap(InMemorySessionStore())


async def test_a_save_never_lowers_a_counter() -> None:
    await contract.a_save_never_lowers_a_counter(InMemorySessionStore())


async def test_a_change_returns_the_session_with_what_others_recorded() -> None:
    await contract.a_change_returns_the_session_with_what_others_recorded(InMemorySessionStore())


async def test_a_session_that_is_gone_stays_gone() -> None:
    await contract.a_session_that_is_gone_stays_gone(InMemorySessionStore())


async def test_a_copy_is_a_snapshot() -> None:
    await contract.a_copy_is_a_snapshot(InMemorySessionStore())


async def test_creating_a_session_again_keeps_what_it_has_recorded() -> None:
    await contract.creating_a_session_again_keeps_what_it_has_recorded(InMemorySessionStore())


async def test_nonsense_is_refused_and_changes_nothing() -> None:
    await contract.nonsense_is_refused_and_changes_nothing(InMemorySessionStore())


async def test_a_session_evicted_at_the_cap_is_gone_for_every_change() -> None:
    store = InMemorySessionStore(max_sessions=1)
    await store.create("a", OLIVIA)
    await store.create("b", OLIVIA)  # "a" was the least recently used

    assert await store.add_flags("a", {ToolTag.READS_UNTRUSTED}) is None
    assert await store.get("a") is None
    assert await store.add_flags("b", {ToolTag.READS_UNTRUSTED}) is not None


async def test_a_change_makes_the_session_the_most_recently_used() -> None:
    store = InMemorySessionStore(max_sessions=2)
    await store.create("a", OLIVIA)
    await store.create("b", OLIVIA)

    await store.mark_tainted("a")  # a call of "a" is running
    await store.create("c", OLIVIA)

    assert await store.get("b") is None
    assert await store.get("a") is not None


def state(**fields: object) -> SessionState:
    return SessionState.model_validate(
        {
            "session_id": "s-1",
            "principal": OLIVIA,
            "created_at": datetime(2026, 10, 23, tzinfo=UTC),
            **fields,
        }
    )


def test_catching_up_only_moves_forward() -> None:
    mine = state(flags={ToolTag.READS_UNTRUSTED}, call_count=5, spent_usd=0.5)
    stored = state(flags={ToolTag.READS_SENSITIVE}, tainted=True, call_count=3, spent_usd=0.25)

    catch_up(mine, stored)

    assert mine.flags == {ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE}
    assert mine.tainted is True
    assert (mine.call_count, mine.spent_usd) == (5, 0.5)


def test_catching_up_does_not_clear_what_the_copy_knows() -> None:
    mine = state(flags={ToolTag.EXTERNAL_EFFECT}, tainted=True)

    catch_up(mine, state())

    assert mine.flags == {ToolTag.EXTERNAL_EFFECT} and mine.tainted is True


async def test_a_copy_is_refreshed_from_the_store() -> None:
    store = InMemorySessionStore()
    mine = await store.create("s-1", OLIVIA)
    await store.add_flags("s-1", {ToolTag.READS_UNTRUSTED})
    await store.mark_tainted("s-1")
    await store.incr_calls("s-1", 4)

    await refresh(store, mine)

    assert mine.flags == {ToolTag.READS_UNTRUSTED} and mine.tainted is True
    assert mine.call_count == 4


async def test_a_session_the_store_does_not_know_is_left_as_it_is() -> None:
    # A request with no session id gets a throwaway state that is never stored.
    mine = state(session_id="unbound-1", tainted=True, flags={ToolTag.READS_UNTRUSTED})

    await refresh(InMemorySessionStore(), mine)

    assert mine.tainted is True and mine.flags == {ToolTag.READS_UNTRUSTED}
