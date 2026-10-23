"""KS-791: a session changes by merging, never by being written over (ADR-0015).

Gate 6 found that a call held for approval saved the session it had read before the wait, which
would drop a flag or a taint that a concurrent call recorded in the meantime. These tests hold a
call for approval in the real gateway, record a flag and a taint from a second call, and check
that both are still there when the first call ends. The store tests run the same rules as the
in-memory store (`tests/fixtures/session_contract.py`) against Redis.
"""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import CallContext, Principal, SessionState, ToolTag
from keystone.db.models import McpSession
from keystone.db.tenants import upsert_tenants
from keystone.gateway.session_repo import SessionRepo
from keystone.gateway.sessions import RedisSessionStore, SessionStore, session_key
from keystone.settings import ApprovalSettings, TenantConfig
from tests.fixtures import session_contract as contract
from tests.fixtures.approvals import Approver
from tests.fixtures.calls import OLIVIA
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts

pytestmark = [pytest.mark.phase(7), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
Factory = Callable[..., KeystoneApp]
BIG = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}
UNTRUSTED = ToolTag.READS_UNTRUSTED
SENSITIVE = ToolTag.READS_SENSITIVE


async def rows(sessions: Sessions) -> list[McpSession]:
    async with sessions() as session:
        return list((await session.scalars(select(McpSession).order_by(McpSession.id))).all())


async def with_rows(redis: Redis, sessions: Sessions, **options: Any) -> RedisSessionStore:
    await upsert_tenants(sessions, [TenantConfig(id="acme", name="Acme Corp")])
    return RedisSessionStore(redis, SessionRepo(sessions), **options)


# -- the rules every store keeps


async def test_a_stale_copy_saved_late_keeps_the_flag_and_the_taint(redis: Redis) -> None:
    await contract.a_stale_copy_saved_late_keeps_the_flag_and_the_taint(RedisSessionStore(redis))


async def test_flags_are_a_union(redis: Redis) -> None:
    await contract.flags_are_a_union(RedisSessionStore(redis))


async def test_the_taint_is_never_cleared(redis: Redis) -> None:
    await contract.the_taint_is_never_cleared(RedisSessionStore(redis))


async def test_counters_add_up_when_calls_overlap(redis: Redis) -> None:
    await contract.counters_add_up_when_calls_overlap(RedisSessionStore(redis))


async def test_a_save_never_lowers_a_counter(redis: Redis) -> None:
    await contract.a_save_never_lowers_a_counter(RedisSessionStore(redis))


async def test_a_change_returns_the_session_with_what_others_recorded(redis: Redis) -> None:
    await contract.a_change_returns_the_session_with_what_others_recorded(RedisSessionStore(redis))


async def test_a_session_that_is_gone_stays_gone(redis: Redis) -> None:
    await contract.a_session_that_is_gone_stays_gone(RedisSessionStore(redis))
    assert await redis.keys("ks:*") == [session_key(contract.SESSION)]  # none for "nobody"


async def test_a_copy_is_a_snapshot(redis: Redis) -> None:
    await contract.a_copy_is_a_snapshot(RedisSessionStore(redis))


async def test_creating_a_session_again_keeps_what_it_has_recorded(redis: Redis) -> None:
    await contract.creating_a_session_again_keeps_what_it_has_recorded(RedisSessionStore(redis))


async def test_nonsense_is_refused_and_changes_nothing(redis: Redis) -> None:
    await contract.nonsense_is_refused_and_changes_nothing(RedisSessionStore(redis))


# -- what only Redis can show


async def test_two_gateways_count_together(redis: Redis, test_redis_url: str) -> None:
    # A second process has a connection and a store of its own and no memory of the first.
    other = Redis.from_url(test_redis_url, decode_responses=True)
    try:
        first, second = RedisSessionStore(redis), RedisSessionStore(other)
        await first.create("s-1", OLIVIA)

        async with anyio.create_task_group() as group:
            for _ in range(40):
                group.start_soon(first.incr_calls, "s-1")
                group.start_soon(second.incr_calls, "s-1")
                group.start_soon(second.add_spend, "s-1", 0.01)

        state = await first.get("s-1")
        assert state is not None
        assert state.call_count == 80
        assert state.spent_usd == pytest.approx(0.4)
    finally:
        await other.aclose()


async def test_a_session_is_one_key_that_expires_as_one(redis: Redis) -> None:
    store = RedisSessionStore(redis, ttl_s=10)
    await store.create("s-1", OLIVIA)
    await store.add_flags("s-1", {UNTRUSTED})
    await store.mark_tainted("s-1")
    await store.incr_calls("s-1")

    assert await redis.keys("ks:*") == [session_key("s-1")]
    assert await redis.type(session_key("s-1")) == "hash"
    assert 9_000 < await redis.pttl(session_key("s-1")) <= 10_000


@pytest.mark.parametrize("change", ["flags", "taint", "calls", "spend", "touch", "save"])
async def test_every_change_restarts_the_clock(redis: Redis, change: str) -> None:
    store = RedisSessionStore(redis, ttl_s=10)
    state = await store.create("s-1", OLIVIA)
    await anyio.sleep(1.2)
    assert await redis.pttl(session_key("s-1")) < 9_000

    if change == "flags":
        await store.add_flags("s-1", {UNTRUSTED})
    elif change == "taint":
        await store.mark_tainted("s-1")
    elif change == "calls":
        await store.incr_calls("s-1")
    elif change == "spend":
        await store.add_spend("s-1", 0.1)
    elif change == "touch":
        await store.touch("s-1")
    else:
        await store.save(state)

    assert await redis.pttl(session_key("s-1")) > 9_500


async def test_a_change_to_a_session_that_expired_makes_no_key(redis: Redis) -> None:
    store = RedisSessionStore(redis)
    state = await store.create("s-1", OLIVIA)
    await redis.delete(session_key("s-1"))  # expired, or flushed

    assert await store.add_flags("s-1", {UNTRUSTED}) is None
    assert await store.mark_tainted("s-1") is None
    assert await store.incr_calls("s-1") is None
    assert await store.add_spend("s-1", 0.2) is None
    await store.touch("s-1")
    await store.save(state)

    # A leftover with no owner would come back as someone else's taint if the id were reused.
    assert await redis.keys("ks:*") == []
    assert await store.get("s-1") is None


async def test_a_key_in_the_old_format_is_a_session_we_have_not_seen(
    redis: Redis, sessionmaker: Sessions
) -> None:
    # Before KS-791 a session was a JSON string. Such a key can only be a leftover: the SDK's own
    # sessions end with the process that held them, so nothing asks for it again.
    store = await with_rows(redis, sessionmaker)
    old = SessionState(session_id="s-1", principal=OLIVIA, created_at=datetime.now(UTC))
    await redis.set(session_key("s-1"), old.model_dump_json(), ex=1000)

    assert await store.get("s-1") is None
    assert await store.peek("s-1") is None
    assert await store.list_for_tenant("acme", 10) == []
    assert await store.add_flags("s-1", {UNTRUSTED}) is None
    # The caller makes a new session over it, as it does over any key it cannot read.
    created = await store.create("s-1", OLIVIA)
    assert created.principal == OLIVIA
    assert await redis.type(session_key("s-1")) == "hash"


async def test_a_damaged_session_is_a_session_we_have_not_seen(redis: Redis) -> None:
    store = RedisSessionStore(redis)
    await store.create("s-1", OLIVIA)
    await store.create("s-2", OLIVIA)
    await store.create("s-3", OLIVIA)
    await redis.hset(session_key("s-1"), "principal", "{not json")
    await redis.hdel(session_key("s-2"), "created_at")
    await redis.hset(session_key("s-3"), "flag:an-unknown-tag", "1")

    assert await store.get("s-1") is None
    assert await store.peek("s-2") is None
    # A flag this version does not know (from a newer one) is left out, not a reason to lose
    # the session.
    kept = await store.get("s-3")
    assert kept is not None and kept.flags == set()


async def test_a_redis_failure_is_raised_by_every_change() -> None:
    broken = Redis.from_url("redis://127.0.0.1:1/15", socket_connect_timeout=0.3)
    store = RedisSessionStore(broken)
    try:
        for change in (
            store.add_flags("s-1", {UNTRUSTED}),
            store.mark_tainted("s-1"),
            store.incr_calls("s-1"),
            store.add_spend("s-1", 0.1),
            store.touch("s-1"),
        ):
            with pytest.raises(RedisError):
                await change
    finally:
        await broken.aclose()


# -- the durable row follows the session


async def test_a_flag_and_the_taint_reach_the_row_at_once(
    redis: Redis, sessionmaker: Sessions
) -> None:
    now = [100.0]
    store = await with_rows(redis, sessionmaker, clock=lambda: now[0])
    await store.create("s-1", OLIVIA)
    [created] = await rows(sessionmaker)

    now[0] = 101.0  # a second later: far inside the minute that a touch of the row waits
    await store.add_flags("s-1", {UNTRUSTED})
    [flagged] = await rows(sessionmaker)
    await store.mark_tainted("s-1")
    [tainted] = await rows(sessionmaker)
    await store.add_flags("s-1", {SENSITIVE, UNTRUSTED})
    [more] = await rows(sessionmaker)

    assert created.final_flags == [] and created.tainted is False
    assert flagged.final_flags == ["reads_untrusted"] and flagged.tainted is False
    assert tainted.final_flags == ["reads_untrusted"] and tainted.tainted is True
    assert more.final_flags == ["reads_sensitive", "reads_untrusted"]


async def test_counting_does_not_write_the_row(redis: Redis, sessionmaker: Sessions) -> None:
    store = await with_rows(redis, sessionmaker)
    await store.create("s-1", OLIVIA)
    [before] = await rows(sessionmaker)

    for _ in range(5):
        await store.incr_calls("s-1")
        await store.add_spend("s-1", 0.1)

    [after] = await rows(sessionmaker)
    assert after.last_seen_at == before.last_seen_at


async def test_a_late_write_to_the_row_cannot_clear_a_flag_or_the_taint(
    sessionmaker: Sessions, redis: Redis
) -> None:
    store = await with_rows(redis, sessionmaker)
    state = await store.create("s-1", OLIVIA)
    repo = SessionRepo(sessionmaker)
    later = state.created_at + timedelta(minutes=5)

    await repo.touch("s-1", later, flags=["reads_sensitive", "reads_untrusted"], tainted=True)
    # Two writers, and the one that knows less gets there last.
    await repo.touch("s-1", later - timedelta(minutes=1), flags=["reads_untrusted"], tainted=False)
    await repo.touch("s-1", later - timedelta(minutes=2))

    [row] = await rows(sessionmaker)
    assert row.final_flags == ["reads_sensitive", "reads_untrusted"]
    assert row.tainted is True
    assert row.last_seen_at == later  # and the time does not go back either


async def test_a_postgres_failure_does_not_fail_a_change(redis: Redis) -> None:
    class Unreachable:
        async def insert(self, state: SessionState) -> bool:
            raise ConnectionError("postgres is gone")

        async def touch(self, *args: Any, **kwargs: Any) -> bool:
            raise ConnectionError("postgres is gone")

    store = RedisSessionStore(redis, Unreachable())
    await store.create("s-1", OLIVIA)

    flagged = await store.add_flags("s-1", {UNTRUSTED})
    tainted = await store.mark_tainted("s-1")
    await store.touch("s-1")

    # The live state is in Redis and the call goes on.
    assert flagged is not None and tainted is not None
    kept = await store.get("s-1")
    assert kept is not None and kept.flags == {UNTRUSTED} and kept.tainted is True


async def test_a_slow_postgres_does_not_hold_a_change_up(
    redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Stuck:
        async def insert(self, state: SessionState) -> bool:
            return True

        async def touch(self, *args: Any, **kwargs: Any) -> bool:
            await anyio.sleep(30)
            return True

    monkeypatch.setattr("keystone.gateway.sessions.ROW_TIMEOUT_S", 0.2)
    store = RedisSessionStore(redis, Stuck())
    await store.create("s-1", OLIVIA)
    started = time.monotonic()

    flagged = await store.add_flags("s-1", {UNTRUSTED})

    assert flagged is not None and flagged.flags == {UNTRUSTED}
    assert time.monotonic() - started < 2


# -- the gateway: two calls in one session, one held for approval


class RecordsWhatItReads:
    """Stands in for the Phase 7 slots that flag and taint a session. After a call to
    `echo__echo` it records a flag and a taint, either with the atomic changes of the store or the
    old way, by reading the whole session and saving it back. Either way the call's own copy
    learns it too, as the real slots will do."""

    name = "session_flags"

    def __init__(self, how: str) -> None:
        self.how = how
        self.store: SessionStore | None = None

    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        if ctx.tool.name != "echo__echo":
            return
        store = self.store
        assert store is not None
        session_id = ctx.session.session_id
        if self.how == "atomic":
            await store.add_flags(session_id, {UNTRUSTED})
            await store.mark_tainted(session_id)
        else:
            state = await store.get(session_id)
            assert state is not None
            state.flags.add(UNTRUSTED)
            state.tainted = True
            await store.save(state)
        ctx.session.flags.add(UNTRUSTED)
        ctx.session.tainted = True


class WatchesTheTaint:
    """Takes the budget slot, which runs before the wait and again after it, and notes whether the
    call's copy of the session says tainted each time."""

    name = "budget"

    def __init__(self) -> None:
        self.seen: list[tuple[str, bool]] = []

    async def before_call(self, ctx: CallContext) -> None:
        self.seen.append((ctx.tool.name, ctx.session.tainted))

    async def after_call(self, ctx: CallContext) -> None:
        return None


def holds(seconds: float) -> dict[str, Any]:
    return {"approvals": ApprovalSettings(wait_seconds=seconds, poll_interval_s=0.2)}


async def stored(redis: Redis) -> tuple[str, SessionState]:
    [key] = await redis.keys("ks:sess:*")
    session_id = str(key).removeprefix("ks:sess:")
    state = await RedisSessionStore(redis).peek(session_id)
    assert state is not None
    return session_id, state


@pytest.mark.parametrize("how", ["atomic", "whole"])
async def test_a_call_held_for_approval_keeps_what_another_call_recorded(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    approver: Approver,
    redis: Redis,
    sessionmaker: Sessions,
    how: str,
) -> None:
    recorder = RecordsWhatItReads(how)
    app = keystone_app_factory(settings=holds(20), interceptors={"session_flags": recorder})
    recorder.store = app.app.state.gateway.sessions
    answers: dict[str, Any] = {}

    async with mcp_client(app, user="olivia") as olivia, anyio.create_task_group() as tasks:

        async def transfer() -> None:
            answers["transfer"] = await olivia.call_tool("bank__transfer", BIG)

        tasks.start_soon(transfer)
        await approver.pending()  # the transfer has read its session and is held
        answers["echo"] = await olivia.call_tool("echo__echo", {"payload": "from a stranger"})
        _, during = await stored(redis)
        await approver.approve("go ahead")

    # While the transfer waited, the second call recorded what it read.
    assert not answers["echo"].is_error
    assert during.flags == {UNTRUSTED} and during.tainted is True
    # The transfer was approved and ran, and ended after all of that.
    assert not answers["transfer"].is_error
    assert "completed" in texts(answers["transfer"])[0]
    session_id, after = await stored(redis)
    assert after.flags == {UNTRUSTED} and after.tainted is True
    [row] = await rows(sessionmaker)
    assert row.id == session_id
    if how == "atomic":
        # `save` writes the row once a minute, as it always did. A flag or a taint recorded with
        # the store's own changes is written when it is new.
        assert row.final_flags == ["reads_untrusted"] and row.tainted is True


async def test_a_call_that_waited_is_checked_against_the_session_as_it_is_now(
    keystone_app_factory: Factory, mcp_client: McpConnect, approver: Approver
) -> None:
    recorder, watcher = RecordsWhatItReads("atomic"), WatchesTheTaint()
    app = keystone_app_factory(
        settings=holds(20), interceptors={"session_flags": recorder, "budget": watcher}
    )
    recorder.store = app.app.state.gateway.sessions

    async with mcp_client(app, user="olivia") as olivia, anyio.create_task_group() as tasks:
        tasks.start_soon(olivia.call_tool, "bank__transfer", BIG)
        await approver.pending()
        await olivia.call_tool("echo__echo", {"payload": "from a stranger"})
        await approver.approve("go ahead")

    # The slots ahead of the approval run again once the person has said yes (KS-691). The second
    # time the transfer sees the taint that the echo call recorded while it waited.
    assert [tainted for tool, tainted in watcher.seen if tool == "bank__transfer"] == [False, True]


class Recording:
    """Wraps a store and notes the name of every method called on it."""

    def __init__(self, inner: SessionStore) -> None:
        self._inner = inner
        self.names: list[str] = []

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._inner, name)

        async def call(*args: Any, **kwargs: Any) -> Any:
            self.names.append(name)
            return await method(*args, **kwargs)

        return call


async def test_the_gateway_touches_a_session_when_a_call_ends_and_saves_none(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    spy = Recording(keystone_app.app.state.gateway.sessions)
    keystone_app.app.state.gateway.sessions = spy

    async with mcp_client(keystone_app) as alice:
        await alice.call_tool("echo__echo", {"payload": "one"})
        await alice.call_tool("echo__echo", {"payload": "two"})

    assert spy.names.count("get") == 2
    assert spy.names.count("touch") == 2
    assert "save" not in spy.names


async def test_the_principal_comes_back_whole_after_a_change(redis: Redis) -> None:
    store = RedisSessionStore(redis)
    who = Principal(
        tenant_id="acme", user_id="o", groups=("a", "b"), agent_id="ops-agent", roles=()
    )

    await store.create("s-1", who)
    await store.add_flags("s-1", {UNTRUSTED})

    kept = await store.get("s-1")
    assert kept is not None and kept.principal == who
