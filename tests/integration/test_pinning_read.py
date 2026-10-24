"""KS-992: the pinning slot reads a tool's status in one statement, with no transaction."""

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.registry.repo import ToolRepo

pytestmark = [pytest.mark.phase(9), pytest.mark.services]


async def test_the_status_is_read_outside_a_transaction(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    engine = sessionmaker.kw["bind"].sync_engine
    inside: list[bool] = []

    def after(conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-untyped-def]
        inside.append(conn.connection.driver_connection.is_in_transaction())

    event.listen(engine, "after_cursor_execute", after)
    try:
        state = await ToolRepo(sessionmaker).current_state("acme", "no__such_tool")
    finally:
        event.remove(engine, "after_cursor_execute", after)

    assert state is None
    assert inside == [False]  # no BEGIN was sent, and so no ROLLBACK follows
