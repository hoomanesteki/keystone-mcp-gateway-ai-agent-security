"""Per-session state: flags, taint, call count and spend, keyed by MCP session id (section 3.7).

Live state is in Redis so it survives a restart and can be shared. Postgres holds a durable row for
each session that audit records and the console can point at. `InMemorySessionStore` is the
store for a single process without Redis, and for tests that do not need it.

A session changes by merging, never by being written over (KS-791, ADR-0015). Calls of one session
overlap, and one can be held for approval for minutes, so a copy of the state read at the start of
a call is out of date by the time the call ends. Every change a store accepts can only add
information: flags are a union, the taint can be set and never cleared, and the counters go up.
"""

from __future__ import annotations

import itertools
import math
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol, runtime_checkable

import anyio
import structlog
from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import ResponseError

from keystone.core.types import Principal, SessionState, ToolTag

log = structlog.get_logger()

MAX_SESSIONS = 10_000
SESSION_TTL_S = 24 * 60 * 60
TOUCH_EVERY_S = 60.0
# A write to the durable row is in the path of a call when a flag or the taint is new, so it does
# not get to hold the call up for long. Redis is the live state; the row can catch up later.
ROW_TIMEOUT_S = 2.0
# A listing reads this many keys at a time, and gives up after MAX_SCANNED.
SCAN_BATCH = 200
MAX_SCANNED = 10_000


class SessionStore(Protocol):
    """Where the state of each session lives. Plan section 3.6 has `create`, `get` and `save`;
    the rest came with KS-791 (ADR-0015).

    A copy that `get` returns is a snapshot, and goes out of date the moment another call changes
    the session. Nothing a store does with a copy can make the session know less than it knew:

    - `save` merges the copy in: flags are a union, the taint is set if the copy has it and never
      cleared by one that has not, and a counter is raised to the copy's value when that is higher.
      It does not bring back a session that is gone.
    - `add_flags`, `mark_tainted`, `incr_calls` and `add_spend` change one thing, atomically, and
      return the session as it is afterwards, with whatever other calls recorded. A call counts
      with `incr_calls` and `add_spend`, never by adding to its copy and saving it.
    - `touch` restarts the session's clock and changes nothing else.

    A change to a session that does not exist (it expired, or it was never stored) returns None
    and stores nothing. Arguments that make no sense raise ValueError before anything changes.
    """

    async def create(self, session_id: str, principal: Principal) -> SessionState: ...
    async def get(self, session_id: str) -> SessionState | None: ...
    async def save(self, state: SessionState) -> None: ...
    async def add_flags(self, session_id: str, flags: Iterable[ToolTag]) -> SessionState | None: ...
    async def mark_tainted(self, session_id: str) -> SessionState | None: ...
    async def incr_calls(self, session_id: str, count: int = 1) -> SessionState | None: ...
    async def add_spend(self, session_id: str, usd: float) -> SessionState | None: ...
    async def touch(self, session_id: str) -> None: ...


@runtime_checkable
class SessionDirectory(Protocol):
    """What the admin API needs to list the live sessions of a tenant (KS-507). It is apart from
    `SessionStore`, the contract of plan section 3.6, which a store needs to serve calls and the
    admin API does not."""

    async def list_for_tenant(self, tenant_id: str, limit: int) -> list[SessionState]: ...

    async def peek(self, session_id: str) -> SessionState | None:
        """One session as it is, without restarting its clock. An approver looking at a request
        must not keep the agent's session alive."""
        ...


class SessionRows(Protocol):
    """The durable row behind a session (`SessionRepo`)."""

    async def insert(self, state: SessionState) -> bool: ...
    async def touch(
        self,
        session_id: str,
        at: datetime,
        *,
        flags: Iterable[str] = (),
        tainted: bool = False,
    ) -> bool:
        """Merge into the row: flags are added to the row's, the taint is set and never cleared,
        and `last_seen_at` only moves forward. Returns False when there is no such session."""
        ...


def catch_up(into: SessionState, newer: SessionState) -> None:
    """Bring `into` up to date with `newer`, which is the same session read later. It only ever
    moves forward, the way the store does: flags are added, the taint is set, counters go up. A
    call uses it on its own copy of the session after a change, so that the rest of the call sees
    what other calls recorded in the meantime."""
    into.flags |= newer.flags
    into.tainted = into.tainted or newer.tainted
    into.call_count = max(into.call_count, newer.call_count)
    into.spent_usd = max(into.spent_usd, newer.spent_usd)


async def refresh(store: SessionStore, snapshot: SessionState) -> None:
    """`catch_up` with what the store holds now. A session the store does not know (a request
    with no session id has a throwaway one) is left as it is."""
    stored = await store.get(snapshot.session_id)
    if stored is not None:
        catch_up(snapshot, stored)


def _tags(flags: Iterable[ToolTag | str]) -> list[ToolTag]:
    """The flags as tags, or ValueError: a flag no policy knows is a mistake in the caller, and
    nothing is added if any of them is."""
    return sorted({ToolTag(flag) for flag in flags})


def _calls(count: int) -> int:
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError(f"count must be a whole number of calls, 0 or more, not {count!r}")
    return count


def _dollars(usd: float) -> float:
    if isinstance(usd, bool) or not isinstance(usd, int | float) or not math.isfinite(usd):
        raise ValueError(f"dollars must be a finite number, not {usd!r}")
    if usd < 0:
        raise ValueError(f"dollars must be 0 or more, not {usd!r}")
    return float(usd)


class InMemorySessionStore:
    """The SDK ends idle sessions after 30 minutes but does not tell us, so the store caps its
    own size and drops the least recently used session instead of growing for ever.

    What it hands out is a copy, as Redis does, so a test of a merge here is a test of the same
    thing. Nothing awaits between reading a session and changing it, so each change is atomic for
    the event loop."""

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self._max = max_sessions
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()

    async def create(self, session_id: str, principal: Principal) -> SessionState:
        found = self._sessions.get(session_id)
        if found is None:
            found = SessionState(
                session_id=session_id, principal=principal, created_at=datetime.now(UTC)
            )
            self._sessions[session_id] = found
            while len(self._sessions) > self._max:
                self._sessions.popitem(last=False)
        self._sessions.move_to_end(session_id)
        return found.model_copy(deep=True)

    async def get(self, session_id: str) -> SessionState | None:
        found = self._sessions.get(session_id)
        if found is None:
            return None
        self._sessions.move_to_end(session_id)
        return found.model_copy(deep=True)

    async def save(self, state: SessionState) -> None:
        found = self._sessions.get(state.session_id)
        if found is not None:
            catch_up(found, state)
            self._sessions.move_to_end(state.session_id)

    async def add_flags(self, session_id: str, flags: Iterable[ToolTag]) -> SessionState | None:
        wanted = _tags(flags)
        found = self._use(session_id)
        if found is not None:
            found.flags.update(wanted)
            return found.model_copy(deep=True)
        return None

    async def mark_tainted(self, session_id: str) -> SessionState | None:
        found = self._use(session_id)
        if found is not None:
            found.tainted = True
            return found.model_copy(deep=True)
        return None

    async def incr_calls(self, session_id: str, count: int = 1) -> SessionState | None:
        count = _calls(count)
        found = self._use(session_id)
        if found is not None:
            found.call_count += count
            return found.model_copy(deep=True)
        return None

    async def add_spend(self, session_id: str, usd: float) -> SessionState | None:
        usd = _dollars(usd)
        found = self._use(session_id)
        if found is not None:
            found.spent_usd += usd
            return found.model_copy(deep=True)
        return None

    async def touch(self, session_id: str) -> None:
        self._use(session_id)

    def _use(self, session_id: str) -> SessionState | None:
        """The stored session itself, made the most recently used. Only this class changes it."""
        found = self._sessions.get(session_id)
        if found is not None:
            self._sessions.move_to_end(session_id)
        return found

    async def peek(self, session_id: str) -> SessionState | None:
        found = self._sessions.get(session_id)
        return found.model_copy(deep=True) if found is not None else None

    async def list_for_tenant(self, tenant_id: str, limit: int) -> list[SessionState]:
        """The tenant's sessions, the most recently used first."""
        mine = (s for s in reversed(self._sessions.values()) if s.principal.tenant_id == tenant_id)
        return [s.model_copy(deep=True) for s in itertools.islice(mine, limit)]


SESSION_PREFIX = "ks:sess:"
FLAG_FIELD = "flag:"


def session_key(session_id: str) -> str:
    return f"{SESSION_PREFIX}{session_id}"


# A session is one Redis hash: who it belongs to, and what has happened in it. A flag is a field
# of its own, which is what makes adding one a union; the taint, the call count and the spend are
# one field each. Fields are changed only by the scripts below, so a change is atomic and the
# key's lifetime moves with it. A script decoding and re-encoding a JSON document would turn every
# empty array in it into an object, `"groups": []` among them (checked on Redis 7.4), which is why
# the document is not kept as JSON.

# KEYS[1] the session. ARGV: lifetime in seconds, session id, principal (JSON), created_at, and
# "1" to replace whatever is there. Returns 1 when it made the session and 0 when one was there.
CREATE_SCRIPT = """
if ARGV[5] ~= '1' and redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'session_id', ARGV[2], 'principal', ARGV[3], 'created_at', ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
"""

# KEYS[1] the session. ARGV: lifetime in seconds, "1" to set the taint, calls to add, dollars to
# add, the least call count and the least spend the session may have afterwards, then the flags
# to add. Returns nil when there is no such session, and otherwise {number of flags and taints
# that were new, every field and value}. Counting is an add; a saved copy is a floor.
MERGE_SCRIPT = """
if redis.call('HEXISTS', KEYS[1], 'session_id') == 0 then
  return nil
end
local news = 0
if ARGV[2] == '1' then
  news = news + redis.call('HSETNX', KEYS[1], 'tainted', '1')
end
for i = 7, #ARGV do
  news = news + redis.call('HSETNX', KEYS[1], 'flag:' .. ARGV[i], '1')
end
if tonumber(ARGV[3]) > 0 then
  redis.call('HINCRBY', KEYS[1], 'call_count', ARGV[3])
end
if tonumber(ARGV[4]) > 0 then
  redis.call('HINCRBYFLOAT', KEYS[1], 'spent_usd', ARGV[4])
end
if tonumber(ARGV[5]) > tonumber(redis.call('HGET', KEYS[1], 'call_count') or '0') then
  redis.call('HSET', KEYS[1], 'call_count', ARGV[5])
end
if tonumber(ARGV[6]) > tonumber(redis.call('HGET', KEYS[1], 'spent_usd') or '0') then
  redis.call('HSET', KEYS[1], 'spent_usd', ARGV[6])
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
return {news, redis.call('HGETALL', KEYS[1])}
"""


def _text(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value


def _fields(reply: Mapping[str | bytes, str | bytes] | Sequence[str | bytes]) -> dict[str, str]:
    """The fields of a hash, from a dict (what `hgetall` returns) or from the flat list of field,
    value, field, value... that a script returns."""
    if isinstance(reply, Mapping):
        return {_text(name): _text(value) for name, value in reply.items()}
    items = [_text(item) for item in reply]
    return dict(zip(items[::2], items[1::2], strict=True))


def _decimal(number: float) -> str:
    """A float as plain digits, which is what Redis reads (`repr` can give 1e-07)."""
    return format(Decimal(repr(number)), "f")


def _wrong_type(error: ResponseError) -> bool:
    """The key holds something that is not a hash. A pipeline puts its own words before the
    server's, so the code is looked for and not expected first."""
    return "WRONGTYPE" in str(error)


def _state_from_fields(fields: Mapping[str, str]) -> SessionState:
    """A session from the fields of its hash. Raises KeyError, ValueError or ValidationError when
    they do not describe one. A flag this version does not know is left out."""
    flags: set[ToolTag] = set()
    for name in fields:
        if name.startswith(FLAG_FIELD):
            try:
                flags.add(ToolTag(name.removeprefix(FLAG_FIELD)))
            except ValueError:
                log.warning("session_flag_unknown", flag=name.removeprefix(FLAG_FIELD))
    return SessionState(
        session_id=fields["session_id"],
        principal=Principal.model_validate_json(fields["principal"]),
        flags=flags,
        tainted=fields.get("tainted") == "1",
        call_count=int(fields.get("call_count", "0")),
        spent_usd=float(fields.get("spent_usd", "0")),
        created_at=datetime.fromisoformat(fields["created_at"]),
    )


class RedisSessionStore:
    """Session state as a hash under `ks:sess:{id}`, kept for `ttl_s` after its last use.

    `get` and every change restart the clock, so a session that is in use does not expire and one
    that is abandoned disappears a day later. The Postgres row is written when the session is
    created. A flag or the taint is written to it as soon as it is new, because nothing else would
    carry it there if the session ended soon after. `save` and `touch` move its `last_seen_at`
    forward at most once per `touch_every_s`, so a busy session costs Postgres one write a minute
    and not one per call. The row is merged into as the state is (flags added, taint never
    cleared), so writes that arrive out of order, or from two processes, cannot undo each other.

    A Postgres failure is logged and does not fail the call: the live state is in Redis. A Redis
    failure raises, because flags and taint live there and a call must not run without them.
    """

    def __init__(
        self,
        redis: Redis,
        rows: SessionRows | None = None,
        *,
        ttl_s: int = SESSION_TTL_S,
        touch_every_s: float = TOUCH_EVERY_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._redis = redis
        self._rows = rows
        self._ttl_s = ttl_s
        self._touch_every_s = touch_every_s
        self._clock = clock
        self._create_script = redis.register_script(CREATE_SCRIPT)
        self._merge_script = redis.register_script(MERGE_SCRIPT)
        # session id -> when its row was last written. Bounded like the in-memory store.
        self._touched: OrderedDict[str, float] = OrderedDict()

    async def create(self, session_id: str, principal: Principal) -> SessionState:
        state = SessionState(
            session_id=session_id, principal=principal, created_at=datetime.now(UTC)
        )
        if not await self._make(state, replace=False):
            # Two first calls of one session raced and the other got here first.
            existing = await self.get(session_id)
            if existing is not None:
                return existing
            # A key that is no session we can read. Make a new one over it.
            await self._make(state, replace=True)
        await self._write_row(state)
        self._remember_touch(session_id)
        return state

    async def get(self, session_id: str) -> SessionState | None:
        key = session_key(session_id)
        try:
            # One round trip. The read and the new lifetime need not be one step: a session that
            # expires between them was not going to be read again.
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.hgetall(key)
                pipe.expire(key, self._ttl_s)
                fields, _ = await pipe.execute()
        except ResponseError as error:
            if not _wrong_type(error):
                raise
            log.error("session_state_unreadable", session=session_id)
            return None
        return self._read(session_id, _fields(fields), log_unreadable=True)

    async def peek(self, session_id: str) -> SessionState | None:
        try:
            fields = await self._redis.hgetall(session_key(session_id))
        except ResponseError as error:
            if not _wrong_type(error):
                raise
            return None
        return self._read(session_id, _fields(fields))

    async def list_for_tenant(self, tenant_id: str, limit: int) -> list[SessionState]:
        """The tenant's live sessions, newest first. It scans the keys, so it looks at no more than
        MAX_SCANNED of them, and it reads without restarting a session's clock."""
        found: list[SessionState] = []
        scanned = 0
        async for key in self._redis.scan_iter(match=session_key("*"), count=SCAN_BATCH):
            scanned += 1
            if scanned > MAX_SCANNED:
                break
            session_id = _text(key).removeprefix(SESSION_PREFIX)
            state = await self.peek(session_id)
            if state is not None and state.principal.tenant_id == tenant_id:
                found.append(state)
        found.sort(key=lambda s: s.created_at, reverse=True)
        return found[:limit]

    async def save(self, state: SessionState) -> None:
        merged = await self._merge(
            state.session_id,
            flags=state.flags,
            taint=state.tainted,
            calls_floor=state.call_count,
            spend_floor=state.spent_usd,
        )
        if merged is not None:
            await self._touch_row(merged[0])

    async def add_flags(self, session_id: str, flags: Iterable[ToolTag]) -> SessionState | None:
        return await self._record(await self._merge(session_id, flags=_tags(flags)))

    async def mark_tainted(self, session_id: str) -> SessionState | None:
        return await self._record(await self._merge(session_id, taint=True))

    async def incr_calls(self, session_id: str, count: int = 1) -> SessionState | None:
        merged = await self._merge(session_id, calls=_calls(count))
        return merged[0] if merged is not None else None

    async def add_spend(self, session_id: str, usd: float) -> SessionState | None:
        merged = await self._merge(session_id, spend=_dollars(usd))
        return merged[0] if merged is not None else None

    async def touch(self, session_id: str) -> None:
        merged = await self._merge(session_id)
        if merged is not None:
            await self._touch_row(merged[0])

    async def _make(self, state: SessionState, *, replace: bool) -> bool:
        made = await self._create_script(
            keys=[session_key(state.session_id)],
            args=[
                self._ttl_s,
                state.session_id,
                state.principal.model_dump_json(),
                state.created_at.isoformat(),
                "1" if replace else "0",
            ],
        )
        return bool(made)

    async def _merge(
        self,
        session_id: str,
        *,
        flags: Iterable[ToolTag] = (),
        taint: bool = False,
        calls: int = 0,
        spend: float = 0.0,
        calls_floor: int = 0,
        spend_floor: float = 0.0,
    ) -> tuple[SessionState, bool] | None:
        """Apply the changes in one script. Returns the session afterwards and whether a flag or
        the taint was new, or None when there is no session by that id to change."""
        try:
            reply = await self._merge_script(
                keys=[session_key(session_id)],
                args=[
                    self._ttl_s,
                    "1" if taint else "0",
                    calls,
                    _decimal(spend),
                    calls_floor,
                    _decimal(spend_floor),
                    *(flag.value for flag in flags),
                ],
            )
        except ResponseError as error:
            if not _wrong_type(error):
                raise
            return None
        if reply is None:
            return None
        news, flat = reply
        state = self._read(session_id, _fields(flat), log_unreadable=True)
        return (state, bool(news)) if state is not None else None

    async def _record(self, merged: tuple[SessionState, bool] | None) -> SessionState | None:
        """What `add_flags` and `mark_tainted` do after the change: a flag or taint that is new
        goes to the row at once."""
        if merged is None:
            return None
        state, news = merged
        if news:
            await self._touch_row(state, force=True)
        return state

    @staticmethod
    def _read(
        session_id: str, fields: Mapping[str, str], *, log_unreadable: bool = False
    ) -> SessionState | None:
        if not fields:
            return None
        try:
            return _state_from_fields(fields)
        except (KeyError, ValueError, ValidationError):
            # Not ours or damaged. Treat it as a session we have not seen: the caller creates a
            # new one over it.
            if log_unreadable:
                log.error("session_state_unreadable", session=session_id)
            return None

    async def _touch_row(self, state: SessionState, *, force: bool = False) -> None:
        now = self._clock()
        last = self._touched.get(state.session_id)
        if not force and last is not None and now - last < self._touch_every_s:
            return
        self._remember_touch(state.session_id)
        if self._rows is None:
            return
        try:
            with anyio.fail_after(ROW_TIMEOUT_S):
                await self._rows.touch(
                    state.session_id,
                    datetime.now(UTC),
                    flags=(flag.value for flag in state.flags),
                    tainted=state.tainted,
                )
        except Exception as exc:
            log.warning(
                "session_row_not_touched", session=state.session_id, error=type(exc).__name__
            )

    async def _write_row(self, state: SessionState) -> None:
        if self._rows is None:
            return
        try:
            with anyio.fail_after(ROW_TIMEOUT_S):
                await self._rows.insert(state)
        except Exception as exc:
            log.error("session_row_not_written", session=state.session_id, error=type(exc).__name__)

    def _remember_touch(self, session_id: str) -> None:
        self._touched[session_id] = self._clock()
        self._touched.move_to_end(session_id)
        while len(self._touched) > MAX_SESSIONS:
            self._touched.popitem(last=False)
