"""KS-704: the flags slot remembers what a session has read.

After a call that returned, the tags of its tool go to the session's flags and the call is counted.
Both are recorded with the store's own atomic changes and never by saving a copy (ADR-0015), and
the call's copy is brought up to date with what the store returned.
"""

import pytest

from keystone.core.types import CallContext, Risk, SessionState, ToolRef, ToolResult, ToolTag
from keystone.gateway.interceptors.flags import SessionFlagsInterceptor
from keystone.gateway.sessions import InMemorySessionStore
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool

pytestmark = pytest.mark.phase(7)

SESSION_ID = "session-1"
UNTRUSTED = ToolTag.READS_UNTRUSTED
SENSITIVE = ToolTag.READS_SENSITIVE
EXTERNAL = ToolTag.EXTERNAL_EFFECT

READ_EMAIL = make_tool("mail", "read_email", tags=frozenset({UNTRUSTED, SENSITIVE}))
GET_BALANCE = make_tool("bank", "get_balance", tags=frozenset({SENSITIVE}))
SEND_EMAIL = make_tool("mail", "send_email", risk=Risk.HIGH, tags=frozenset({EXTERNAL}))
LIST_FILES = make_tool("files", "list_files")
OK = ToolResult(content=[{"type": "text", "text": "fine"}])
FAILED = ToolResult(content=[{"type": "text", "text": "no such thing"}], is_error=True)


async def returned(
    store: InMemorySessionStore | None, tool: ToolRef, result: ToolResult = OK
) -> CallContext:
    """A call whose upstream has returned `result`, with the session as the store handed it out."""
    session: SessionState | None = None
    if store is not None:
        session = await store.create(SESSION_ID, OLIVIA)
    ctx = make_ctx({"text": "x"}, tool, session=session)
    ctx.result = result
    ctx.dispatched = True
    return ctx


async def stored(store: InMemorySessionStore) -> SessionState:
    found = await store.get(SESSION_ID)
    assert found is not None
    return found


async def test_the_tags_of_a_read_become_flags_and_the_call_is_counted() -> None:
    store = InMemorySessionStore()
    ctx = await returned(store, READ_EMAIL)

    await SessionFlagsInterceptor(store).after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == ({UNTRUSTED, SENSITIVE}, 1)
    # The call's own copy shows it as well, for the slots after this one.
    assert (ctx.session.flags, ctx.session.call_count) == ({UNTRUSTED, SENSITIVE}, 1)


async def test_flags_accumulate_over_calls_and_each_call_counts() -> None:
    store = InMemorySessionStore()
    slot = SessionFlagsInterceptor(store)

    for tool in (GET_BALANCE, LIST_FILES, READ_EMAIL):
        ctx = make_ctx({"text": "x"}, tool, session=await store.create(SESSION_ID, OLIVIA))
        ctx.result = OK
        await slot.after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == ({UNTRUSTED, SENSITIVE}, 3)


async def test_a_tool_with_no_tag_that_matters_adds_no_flag_and_still_counts() -> None:
    store = InMemorySessionStore()
    ctx = await returned(store, LIST_FILES)

    await SessionFlagsInterceptor(store).after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == (set(), 1)


async def test_only_what_a_session_has_read_is_recorded() -> None:
    # External effect and code execution are read off the tool being called, by the Rule of Two.
    # A session that sent a mail has not read anything untrusted.
    store = InMemorySessionStore()
    code = make_tool("sandbox", "run_python", tags=frozenset({ToolTag.CODE_EXEC, EXTERNAL}))
    for tool in (SEND_EMAIL, code):
        ctx = make_ctx({"text": "x"}, tool, session=await store.create(SESSION_ID, OLIVIA))
        ctx.result = OK
        await SessionFlagsInterceptor(store).after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == (set(), 2)


async def test_an_error_result_adds_no_flags_and_is_not_counted() -> None:
    store = InMemorySessionStore()
    ctx = await returned(store, READ_EMAIL, FAILED)

    await SessionFlagsInterceptor(store).after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == (set(), 0)
    assert ctx.session.flags == set() and ctx.session.call_count == 0


async def test_keystones_own_tools_add_nothing() -> None:
    store = InMemorySessionStore()
    whoami = make_tool("keystone", "whoami", tags=frozenset({UNTRUSTED}))
    ctx = await returned(store, whoami)

    await SessionFlagsInterceptor(store).after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == (set(), 0)


async def test_a_call_without_a_result_adds_nothing() -> None:
    store = InMemorySessionStore()
    ctx = make_ctx({"text": "x"}, READ_EMAIL, session=await store.create(SESSION_ID, OLIVIA))

    await SessionFlagsInterceptor(store).after_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == (set(), 0)


async def test_the_copy_of_the_call_learns_what_other_calls_recorded() -> None:
    store = InMemorySessionStore()
    ctx = await returned(store, GET_BALANCE)
    # While this call ran, another call of the session read an untrusted page and found an
    # injection in it.
    await store.add_flags(SESSION_ID, {UNTRUSTED})
    await store.mark_tainted(SESSION_ID)
    await store.incr_calls(SESSION_ID)

    await SessionFlagsInterceptor(store).after_call(ctx)

    assert ctx.session.flags == {UNTRUSTED, SENSITIVE}
    assert ctx.session.tainted is True
    assert ctx.session.call_count == 2
    after = await stored(store)
    assert (after.flags, after.tainted, after.call_count) == ({UNTRUSTED, SENSITIVE}, True, 2)


async def test_two_calls_that_overlap_are_both_counted() -> None:
    store = InMemorySessionStore()
    first = await returned(store, READ_EMAIL)
    second = await returned(store, GET_BALANCE)  # a copy that has not seen the first
    slot = SessionFlagsInterceptor(store)

    await slot.after_call(first)
    await slot.after_call(second)

    after = await stored(store)
    assert after.call_count == 2 and after.flags == {UNTRUSTED, SENSITIVE}
    assert second.session.call_count == 2  # it counted itself on top of the first


async def test_a_session_the_store_does_not_have_is_changed_in_the_call_alone() -> None:
    # A request with no session id has a throwaway state that is never stored (ADR-0015).
    store = InMemorySessionStore()
    ctx = await returned(None, READ_EMAIL)

    await SessionFlagsInterceptor(store).after_call(ctx)

    assert ctx.session.flags == {UNTRUSTED, SENSITIVE} and ctx.session.call_count == 1
    assert await store.get(ctx.session.session_id) is None


async def test_without_a_store_only_the_copy_of_the_call_changes() -> None:
    ctx = await returned(None, READ_EMAIL)

    await SessionFlagsInterceptor().after_call(ctx)

    assert ctx.session.flags == {UNTRUSTED, SENSITIVE} and ctx.session.call_count == 1


async def test_the_slot_does_nothing_before_the_call() -> None:
    store = InMemorySessionStore()
    ctx = make_ctx({"text": "x"}, READ_EMAIL, session=await store.create(SESSION_ID, OLIVIA))

    await SessionFlagsInterceptor(store).before_call(ctx)

    after = await stored(store)
    assert (after.flags, after.call_count) == (set(), 0)
