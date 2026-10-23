"""Per-session state: flags, taint, call count and spend, keyed by MCP session id (section 3.7).

Live state is in Redis so it survives a restart and can be shared. Postgres holds a durable row for
each session that audit records and the console can point at. `InMemorySessionStore` is the
store for a single process without Redis, and for tests that do not need it.
"""

from __future__ import annotations

import itertools
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

import structlog
from pydantic import ValidationError
from redis.asyncio import Redis

from keystone.core.types import Principal, SessionState

log = structlog.get_logger()

MAX_SESSIONS = 10_000
SESSION_TTL_S = 24 * 60 * 60
TOUCH_EVERY_S = 60.0
# A listing reads this many keys at a time, and gives up after MAX_SCANNED.
SCAN_BATCH = 200
MAX_SCANNED = 10_000


class SessionStore(Protocol):
    async def create(self, session_id: str, principal: Principal) -> SessionState: ...
    async def get(self, session_id: str) -> SessionState | None: ...
    async def save(self, state: SessionState) -> None: ...


@runtime_checkable
class SessionDirectory(Protocol):
    """What the admin API needs to list the live sessions of a tenant (KS-507). It is apart from
    `SessionStore`, which is a contract of plan section 3.6 and does not change."""

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
    ) -> bool: ...


class InMemorySessionStore:
    """The SDK ends idle sessions after 30 minutes but does not tell us, so the store caps its
    own size and drops the least recently used session instead of growing for ever."""

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self._max = max_sessions
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()

    async def create(self, session_id: str, principal: Principal) -> SessionState:
        state = SessionState(
            session_id=session_id, principal=principal, created_at=datetime.now(UTC)
        )
        await self.save(state)
        return state

    async def get(self, session_id: str) -> SessionState | None:
        state = self._sessions.get(session_id)
        if state is not None:
            self._sessions.move_to_end(session_id)
        return state

    async def save(self, state: SessionState) -> None:
        self._sessions[state.session_id] = state
        self._sessions.move_to_end(state.session_id)
        while len(self._sessions) > self._max:
            self._sessions.popitem(last=False)

    async def peek(self, session_id: str) -> SessionState | None:
        return self._sessions.get(session_id)

    async def list_for_tenant(self, tenant_id: str, limit: int) -> list[SessionState]:
        """The tenant's sessions, the most recently used first."""
        mine = (s for s in reversed(self._sessions.values()) if s.principal.tenant_id == tenant_id)
        return list(itertools.islice(mine, limit))


def session_key(session_id: str) -> str:
    return f"ks:sess:{session_id}"


class RedisSessionStore:
    """Session state as JSON under `ks:sess:{id}`, kept for `ttl_s` after its last use.

    `get` and `save` both restart the clock, so a session that is in use does not expire and one
    that is abandoned disappears a day later. The Postgres row is written once, when the session
    is created. `save` moves its `last_seen_at` forward at most once per `touch_every_s`, so a busy
    session costs Postgres one write a minute and not one per call.

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
        # session id -> when its row was last written. Bounded like the in-memory store.
        self._touched: OrderedDict[str, float] = OrderedDict()

    async def create(self, session_id: str, principal: Principal) -> SessionState:
        state = SessionState(
            session_id=session_id, principal=principal, created_at=datetime.now(UTC)
        )
        stored = await self._redis.set(
            session_key(session_id), state.model_dump_json(), ex=self._ttl_s, nx=True
        )
        if not stored:
            # Two first calls of one session raced and the other got here first.
            existing = await self.get(session_id)
            if existing is not None:
                return existing
            await self._redis.set(session_key(session_id), state.model_dump_json(), ex=self._ttl_s)
        await self._write_row(state)
        self._remember_touch(session_id)
        return state

    async def get(self, session_id: str) -> SessionState | None:
        raw = await self._redis.getex(session_key(session_id), ex=self._ttl_s)
        if raw is None:
            return None
        try:
            return SessionState.model_validate_json(raw)
        except ValidationError:
            # Not ours or damaged. Treat it as a session we have not seen: the caller creates a
            # new one over it.
            log.error("session_state_unreadable", session=session_id)
            return None

    async def peek(self, session_id: str) -> SessionState | None:
        raw = await self._redis.get(session_key(session_id))
        if raw is None:
            return None
        try:
            return SessionState.model_validate_json(raw)
        except ValidationError:
            return None

    async def list_for_tenant(self, tenant_id: str, limit: int) -> list[SessionState]:
        """The tenant's live sessions, newest first. It scans the keys, so it looks at no more than
        MAX_SCANNED of them, and it reads without restarting a session's clock."""
        found: list[SessionState] = []
        scanned = 0
        async for key in self._redis.scan_iter(match=session_key("*"), count=SCAN_BATCH):
            scanned += 1
            if scanned > MAX_SCANNED:
                break
            raw = await self._redis.get(key)
            if raw is None:
                continue
            try:
                state = SessionState.model_validate_json(raw)
            except ValidationError:
                continue
            if state.principal.tenant_id == tenant_id:
                found.append(state)
        found.sort(key=lambda s: s.created_at, reverse=True)
        return found[:limit]

    async def save(self, state: SessionState) -> None:
        await self._redis.set(
            session_key(state.session_id), state.model_dump_json(), ex=self._ttl_s
        )
        now = self._clock()
        last = self._touched.get(state.session_id)
        if last is not None and now - last < self._touch_every_s:
            return
        self._remember_touch(state.session_id)
        if self._rows is None:
            return
        try:
            await self._rows.touch(
                state.session_id,
                datetime.now(UTC),
                flags=state.flags,
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
            await self._rows.insert(state)
        except Exception as exc:
            log.error("session_row_not_written", session=state.session_id, error=type(exc).__name__)

    def _remember_touch(self, session_id: str) -> None:
        self._touched[session_id] = self._clock()
        self._touched.move_to_end(session_id)
        while len(self._touched) > MAX_SESSIONS:
            self._touched.popitem(last=False)
