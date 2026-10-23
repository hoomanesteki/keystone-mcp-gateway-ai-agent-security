import asyncio
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from alembic import command
from fastapi import Depends
from pydantic import SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from keystone.app import create_app
from keystone.db.models import Tenant
from keystone.db.session import get_session
from keystone.settings import Settings
from tests.fixtures.db import (
    alembic_config,
    drop_database,
    recreate_database,
    with_database,
)

pytestmark = [pytest.mark.phase(0), pytest.mark.services]


def test_migrations_up_down(clean_env: None) -> None:
    """Upgrade then downgrade on an empty database. Sync on purpose: alembic starts its own loop."""
    admin_url = Settings().database_url.get_secret_value()
    url = with_database(admin_url, "keystone_migrations_test")
    recreate_database(admin_url, "keystone_migrations_test")
    try:
        config = alembic_config(url)

        command.upgrade(config, "head")
        assert asyncio.run(table_names(url)) == {
            "alembic_version",
            "tenants",
            "upstreams",
            "tools",
            "sessions",
            "credentials",
            "policy_versions",
        }

        command.downgrade(config, "base")
        assert asyncio.run(table_names(url)) == {"alembic_version"}

        command.upgrade(config, "head")
        assert "tenants" in asyncio.run(table_names(url))
        command.downgrade(config, "0001")
        assert asyncio.run(table_names(url)) == {"alembic_version", "tenants"}
    finally:
        drop_database(admin_url, "keystone_migrations_test")


def test_models_match_the_migrations(test_database_url: str) -> None:
    """The migrations are written by hand, so a model change without one shows up here."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from keystone.db.models import Base

    async def differences() -> list[object]:
        engine = create_async_engine(test_database_url, poolclass=NullPool)
        try:
            async with engine.connect() as connection:

                def compare(sync_connection: object) -> list[object]:
                    context = MigrationContext.configure(sync_connection)  # type: ignore[arg-type]
                    return list(compare_metadata(context, Base.metadata))

                return await connection.run_sync(compare)
        finally:
            await engine.dispose()

    assert asyncio.run(differences()) == []


async def table_names(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            rows = await connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
            return set(rows.scalars())
    finally:
        await engine.dispose()


async def write_and_count(db: AsyncSession) -> int:
    db.add(Tenant(id="shared-id", name="Written by one test"))
    await db.flush()
    return await db.scalar(select(func.count()).select_from(Tenant)) or 0


async def test_db_fixture_isolation(db: AsyncSession, test_database_url: str) -> None:
    assert await write_and_count(db) == 1

    # A second connection sees nothing: the row exists only inside this test's transaction.
    other = create_async_engine(test_database_url, poolclass=NullPool)
    try:
        async with other.connect() as connection:
            visible = await connection.scalar(text("SELECT count(*) FROM tenants"))
    finally:
        await other.dispose()
    assert visible == 0


async def test_db_fixture_isolation_second_writer(db: AsyncSession) -> None:
    # Same primary key as the test above. It would fail with a unique violation if that
    # test's row had been committed.
    assert await write_and_count(db) == 1


def tenant_settings(tmp_path: Path, test_database_url: str, tenants_yaml: str) -> Settings:
    config = tmp_path / "keystone.yaml"
    config.write_text(tenants_yaml)
    return Settings(
        env="test",
        config_path=config,
        database_url=SecretStr(test_database_url),
        oidc_issuer="http://idp.test/realms/keystone",
    )


async def test_config_tenants_upserted(
    tmp_path: Path, clean_env: None, clean_db: None, db: AsyncSession, test_database_url: str
) -> None:
    settings = tenant_settings(
        tmp_path,
        test_database_url,
        "tenants:\n  - {id: acme, name: Acme Corp}\n  - {id: globex, name: Globex}\n",
    )

    app = create_app(settings)
    async with app.router.lifespan_context(app):
        pass

    rows = (await db.execute(select(Tenant.id, Tenant.name).order_by(Tenant.id))).all()
    assert [tuple(row) for row in rows] == [("acme", "Acme Corp"), ("globex", "Globex")]


async def test_tenant_upsert_updates_names_without_duplicates(
    tmp_path: Path, clean_env: None, clean_db: None, db: AsyncSession, test_database_url: str
) -> None:
    for name in ("Acme Corp", "Acme Corporation"):
        settings = tenant_settings(
            tmp_path, test_database_url, f"tenants:\n  - {{id: acme, name: {name}}}\n"
        )
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            pass

    rows = (await db.execute(select(Tenant.id, Tenant.name))).all()
    assert [tuple(row) for row in rows] == [("acme", "Acme Corporation")]


async def test_get_session_dependency_serves_a_session(
    clean_env: None, test_database_url: str
) -> None:
    app = create_app(
        Settings(
            env="test",
            database_url=SecretStr(test_database_url),
            oidc_issuer="http://idp.test/realms/keystone",
        )
    )

    @app.get("/probe")
    async def probe(session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, int]:
        return {"value": await session.scalar(text("SELECT 41 + 1")) or 0}

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://keystone") as client:
            response = await client.get("/probe")

    assert response.json() == {"value": 42}
