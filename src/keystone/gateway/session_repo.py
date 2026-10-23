"""The durable row behind a session (plan section 3.7). Live state is in Redis (KS-207)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import ARRAY, Boolean, DateTime, Text, bindparam, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import SessionState
from keystone.db.models import McpSession
from keystone.db.session import affected


class SessionRepo:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def insert(self, state: SessionState) -> bool:
        """Write the row for a new session. Returns False when it already exists, which happens
        when two first calls of one session race."""
        statement = (
            insert(McpSession)
            .values(
                id=state.session_id,
                tenant_id=state.principal.tenant_id,
                user_id=state.principal.user_id,
                agent_id=state.principal.agent_id,
                started_at=state.created_at,
                last_seen_at=state.created_at,
            )
            .on_conflict_do_nothing(index_elements=[McpSession.id])
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def touch(
        self,
        session_id: str,
        at: datetime,
        *,
        flags: Iterable[str] = (),
        tainted: bool = False,
    ) -> bool:
        """Merge into the row: move `last_seen_at` forward, add the flags to those it has and set
        the taint if it is set. Nothing is ever taken out, so two writers whose calls were
        decided in another order, or a writer that knows less than the row, change nothing that
        was already recorded (KS-791). Returns False when there is no such session."""
        statement = _MERGE.bindparams(
            bindparam("id", session_id, type_=Text),
            bindparam("at", at, type_=DateTime(timezone=True)),
            bindparam("flags", sorted({str(flag) for flag in flags}), type_=ARRAY(Text)),
            bindparam("tainted", tainted, type_=Boolean),
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))


_MERGE = text(
    """
    UPDATE sessions SET
        last_seen_at = GREATEST(last_seen_at, :at),
        final_flags = ARRAY(
            SELECT DISTINCT f FROM unnest(final_flags || :flags) AS t(f) ORDER BY f
        ),
        tainted = tainted OR :tainted
    WHERE id = :id
    """
)
