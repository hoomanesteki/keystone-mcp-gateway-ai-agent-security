from collections.abc import AsyncIterator
from typing import Any, cast

from fastapi import Request
from sqlalchemy import CursorResult, Result
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_engine(url: str) -> AsyncEngine:
    # pool_pre_ping drops connections that Postgres closed while the gateway was idle.
    return create_async_engine(url, pool_pre_ping=True)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    # expire_on_commit=False: handlers return objects after commit, and an async session
    # cannot lazy-load attributes that expired.
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency. The sessionmaker is built at startup in the app lifespan."""
    async with request.app.state.sessionmaker() as session:
        yield session


def affected(result: Result[Any]) -> int:
    """How many rows an INSERT, UPDATE or DELETE touched. SQLAlchemy types `execute` as a plain
    Result, which has no rowcount."""
    return cast("CursorResult[Any]", result).rowcount
