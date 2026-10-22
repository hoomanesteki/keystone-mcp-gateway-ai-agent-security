"""The durable row behind a session (plan section 3.7). Live state is in Redis (KS-207)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import update
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
        """Move `last_seen_at` forward and keep the flags and taint the session ended with.
        Returns False when there is no such session."""
        statement = (
            update(McpSession)
            .where(McpSession.id == session_id)
            .values(last_seen_at=at, final_flags=sorted(set(flags)), tainted=tainted)
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))
