"""What every session store does with the changes made to a session (KS-791, ADR-0015).

The in-memory store and the Redis store must answer alike, so the tests of both call these
functions. Each one takes a store with nothing in it and checks one rule.
"""

import math
from typing import Any

import anyio
import pytest

from keystone.core.types import Principal, ToolTag
from keystone.gateway.sessions import SessionStore
from tests.fixtures.calls import OLIVIA

SESSION = "s-1"
UNTRUSTED = ToolTag.READS_UNTRUSTED
SENSITIVE = ToolTag.READS_SENSITIVE
EXTERNAL = ToolTag.EXTERNAL_EFFECT


async def a_stale_copy_saved_late_keeps_the_flag_and_the_taint(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    held = await store.get(SESSION)  # the call that is held for approval starts here
    assert held is not None
    # Another call of the session reads untrusted data and finds an injection in it.
    await store.add_flags(SESSION, {UNTRUSTED})
    await store.mark_tainted(SESSION)

    await store.save(held)  # the held call ends and writes back the copy it started with

    after = await store.get(SESSION)
    assert after is not None
    assert after.flags == {UNTRUSTED}
    assert after.tainted is True


async def flags_are_a_union(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)

    first = await store.add_flags(SESSION, {UNTRUSTED})
    second = await store.add_flags(SESSION, [SENSITIVE, UNTRUSTED])
    nothing = await store.add_flags(SESSION, [])
    # A copy that has seen none of this adds a flag of its own.
    copy = await store.get(SESSION)
    assert copy is not None
    copy.flags = {EXTERNAL}
    await store.save(copy)

    assert first is not None and first.flags == {UNTRUSTED}
    assert second is not None and second.flags == {UNTRUSTED, SENSITIVE}
    assert nothing is not None and nothing.flags == {UNTRUSTED, SENSITIVE}
    final = await store.get(SESSION)
    assert final is not None and final.flags == {UNTRUSTED, SENSITIVE, EXTERNAL}


async def the_taint_is_never_cleared(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    clean = await store.get(SESSION)
    assert clean is not None

    marked = await store.mark_tainted(SESSION)
    again = await store.mark_tainted(SESSION)
    await store.save(clean)  # says "not tainted", and is out of date
    claims_clean = clean.model_copy(update={"tainted": False, "flags": {UNTRUSTED}})
    await store.save(claims_clean)
    await store.add_flags(SESSION, [])
    await store.incr_calls(SESSION)
    await store.add_spend(SESSION, 0.0)
    await store.touch(SESSION)

    assert marked is not None and marked.tainted is True
    assert again is not None and again.tainted is True
    final = await store.get(SESSION)
    assert final is not None and final.tainted is True


async def counters_add_up_when_calls_overlap(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    counted: list[int] = []

    async def count() -> None:
        state = await store.incr_calls(SESSION)
        assert state is not None
        counted.append(state.call_count)

    # Under 100, which is how many connections a Redis client opens at most.
    async with anyio.create_task_group() as group:
        for _ in range(40):
            group.start_soon(count)
            group.start_soon(store.add_spend, SESSION, 0.01)
        group.start_soon(store.incr_calls, SESSION, 5)

    # Every increment saw its own number: none was counted twice and none was lost.
    assert len(set(counted)) == 40
    final = await store.get(SESSION)
    assert final is not None
    assert final.call_count == 45
    assert final.spent_usd == pytest.approx(0.4)


async def a_save_never_lowers_a_counter(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    stale = await store.get(SESSION)
    assert stale is not None
    await store.incr_calls(SESSION, 5)
    await store.add_spend(SESSION, 0.25)

    await store.save(stale)  # counts 0 and 0.0
    after_stale = await store.get(SESSION)
    ahead = stale.model_copy(update={"call_count": 9, "spent_usd": 1.5})
    await store.save(ahead)
    after_ahead = await store.get(SESSION)
    await store.save(stale.model_copy(update={"call_count": 3, "spent_usd": 0.5}))
    after_behind = await store.get(SESSION)

    assert after_stale is not None
    assert (after_stale.call_count, after_stale.spent_usd) == (5, 0.25)
    assert after_ahead is not None
    assert (after_ahead.call_count, after_ahead.spent_usd) == (9, 1.5)
    assert after_behind is not None
    assert (after_behind.call_count, after_behind.spent_usd) == (9, 1.5)


async def a_change_returns_the_session_with_what_others_recorded(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    await store.add_flags(SESSION, {SENSITIVE})  # another call got there first

    merged = await store.add_flags(SESSION, {UNTRUSTED})
    counted = await store.incr_calls(SESSION, 2)
    spent = await store.add_spend(SESSION, 0.1)

    assert merged is not None and merged.flags == {SENSITIVE, UNTRUSTED}
    assert counted is not None and counted.call_count == 2
    assert spent is not None and spent.spent_usd == pytest.approx(0.1)
    assert spent.flags == {SENSITIVE, UNTRUSTED} and spent.principal == OLIVIA


async def a_session_that_is_gone_stays_gone(store: SessionStore) -> None:
    saved = await store.create(SESSION, OLIVIA)

    assert await store.add_flags("nobody", {UNTRUSTED}) is None
    assert await store.mark_tainted("nobody") is None
    assert await store.incr_calls("nobody") is None
    assert await store.add_spend("nobody", 0.5) is None
    await store.touch("nobody")
    await store.save(saved.model_copy(update={"session_id": "nobody", "tainted": True}))

    assert await store.get("nobody") is None


async def a_copy_is_a_snapshot(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    mine = await store.get(SESSION)
    assert mine is not None

    mine.flags.add(UNTRUSTED)
    mine.tainted = True
    mine.call_count = 9

    other = await store.get(SESSION)
    assert other is not None
    assert (other.flags, other.tainted, other.call_count) == (set(), False, 0)


async def creating_a_session_again_keeps_what_it_has_recorded(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)
    await store.add_flags(SESSION, {UNTRUSTED})
    await store.mark_tainted(SESSION)
    await store.incr_calls(SESSION)

    stranger = Principal(tenant_id="acme", user_id="x", agent_id="y")
    again = await store.create(SESSION, stranger)

    assert again.principal == OLIVIA
    assert again.flags == {UNTRUSTED} and again.tainted is True and again.call_count == 1


async def nonsense_is_refused_and_changes_nothing(store: SessionStore) -> None:
    await store.create(SESSION, OLIVIA)

    with pytest.raises(ValueError, match="count"):
        await store.incr_calls(SESSION, -1)
    for dollars in (-0.01, math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="dollars"):
            await store.add_spend(SESSION, dollars)
    unknown: Any = ["not-a-tag"]
    mixed: Any = [UNTRUSTED, "not-a-tag"]
    with pytest.raises(ValueError):
        await store.add_flags(SESSION, unknown)
    with pytest.raises(ValueError):
        await store.add_flags(SESSION, mixed)  # not even the valid one is added

    final = await store.get(SESSION)
    assert final is not None
    assert (final.flags, final.tainted, final.call_count, final.spent_usd) == (set(), False, 0, 0.0)
