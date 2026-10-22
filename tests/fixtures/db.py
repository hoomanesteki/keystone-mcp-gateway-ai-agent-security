"""Database fixtures: a separate migrated `keystone_test` database, and two ways to isolate tests.

`db` rolls back a transaction, so it only works for code that uses the test's own session.
`clean_db` truncates the tables after the test, for code that writes through its own engine
(the app under test, for example).
"""

import asyncio
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from keystone.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE = "keystone_test"


def with_database(url: str, name: str) -> str:
    return make_url(url).set(database=name).render_as_string(hide_password=False)


def alembic_config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["url"] = url
    config.attributes["configure_logging"] = False
    return config


async def _recreate_database(admin_url: str, name: str, *, create: bool) -> None:
    dsn = admin_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    conn = await asyncpg.connect(dsn, timeout=10)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        if create:
            await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


def recreate_database(admin_url: str, name: str) -> None:
    asyncio.run(_recreate_database(admin_url, name, create=True))


def drop_database(admin_url: str, name: str) -> None:
    asyncio.run(_recreate_database(admin_url, name, create=False))


@pytest.fixture(scope="session")
def test_database_url() -> Iterator[str]:
    """Create `keystone_test` next to the configured database and migrate it once per run."""
    admin_url = Settings().database_url.get_secret_value()
    url = with_database(admin_url, TEST_DATABASE)
    recreate_database(admin_url, TEST_DATABASE)
    # Alembic's async env.py starts its own event loop, so this must run outside one.
    command.upgrade(alembic_config(url), "head")
    yield url
    drop_database(admin_url, TEST_DATABASE)


@pytest.fixture
async def db(test_database_url: str) -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(test_database_url, poolclass=NullPool)
    async with engine.connect() as connection:
        outer = await connection.begin()
        session = AsyncSession(
            bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield session
        finally:
            await session.close()
            await outer.rollback()
    await engine.dispose()


@pytest.fixture
async def clean_db(test_database_url: str) -> AsyncIterator[None]:
    async def truncate() -> None:
        engine = create_async_engine(test_database_url, poolclass=NullPool)
        async with engine.begin() as connection:
            tables = (
                await connection.execute(
                    text(
                        "SELECT tablename FROM pg_tables "
                        "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
                    )
                )
            ).scalars()
            names = ", ".join(f'"{name}"' for name in tables)
            if names:
                await connection.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        await engine.dispose()

    await truncate()
    yield
    await truncate()
