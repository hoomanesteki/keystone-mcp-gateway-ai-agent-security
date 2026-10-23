import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from typer.testing import CliRunner

from keystone.admin.cli import app as cli
from keystone.settings import Settings
from tests.fixtures.db import drop_database, recreate_database, with_database

SCRATCH = "keystone_cli_migrate"


async def tables(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            rows = await connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
            return set(rows.scalars())
    finally:
        await engine.dispose()


@pytest.mark.phase(2)
@pytest.mark.services
@pytest.mark.usefixtures("clean_env")
def test_db_upgrade_creates_the_schema_and_can_run_twice() -> None:
    admin_url = Settings().database_url.get_secret_value()
    url = with_database(admin_url, SCRATCH)
    recreate_database(admin_url, SCRATCH)
    try:
        runner = CliRunner()
        first = runner.invoke(cli, ["db", "upgrade"], env={"KEYSTONE_DATABASE_URL": url})
        second = runner.invoke(cli, ["db", "upgrade"], env={"KEYSTONE_DATABASE_URL": url})

        assert (first.exit_code, second.exit_code) == (0, 0), first.output + second.output
        expected = {"tenants", "upstreams", "tools", "sessions", "credentials"}
        assert expected <= asyncio.run(tables(url))
    finally:
        drop_database(admin_url, SCRATCH)
