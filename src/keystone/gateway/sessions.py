"""Per-session state, kept in memory until KS-207 moves it to Redis."""

from __future__ import annotations

from collections import OrderedDict
from datetime import UTC, datetime

from keystone.core.types import Principal, SessionState

MAX_SESSIONS = 10_000


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
