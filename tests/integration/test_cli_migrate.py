import asyncio
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import asyncpg
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from typer.testing import CliRunner

from keystone.admin.cli import app as cli
from keystone.db.roles import APP_ROLE, DEV_APP_PASSWORD
from keystone.settings import Settings
from tests.fixtures.db import drop_database, recreate_database, with_database

SCRATCH = "keystone_cli_migrate"
# The image compose and CI already run, so nothing is pulled.
POSTGRES_IMAGE = "postgres:16.15"


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


def asyncpg_dsn(url: str, **parts: Any) -> str:
    return make_url(url).set(drivername="postgresql", **parts).render_as_string(hide_password=False)


async def ping(dsn: str) -> None:
    connection = await asyncpg.connect(dsn, timeout=5)
    await connection.close()


async def role_exists(url: str) -> bool:
    connection = await asyncpg.connect(asyncpg_dsn(url), timeout=10)
    try:
        row = await connection.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", APP_ROLE)
        return row == 1
    finally:
        await connection.close()


async def app_role_logs_in_with(url: str, password: str) -> bool:
    dsn = asyncpg_dsn(url, username=APP_ROLE, password=password)
    try:
        connection = await asyncpg.connect(dsn, timeout=10)
    except asyncpg.InvalidPasswordError:
        return False
    await connection.close()
    return True


@pytest.fixture
def fresh_postgres(docker_client: Any) -> Iterator[str]:
    """The owner's URL of an empty cluster in a throwaway container. Roles belong to the cluster,
    and the shared compose cluster always has keystone_app, so only a new cluster reaches the
    branch of migration 0006 that creates it."""
    container = docker_client.containers.run(
        POSTGRES_IMAGE,
        detach=True,
        environment={
            "POSTGRES_USER": "owner",
            "POSTGRES_PASSWORD": "owner-pw",
            "POSTGRES_DB": "keystone",
        },
        ports={"5432/tcp": None},
        labels={"keystone.test": "cli-migrate"},
    )
    try:
        container.reload()
        port = container.ports["5432/tcp"][0]["HostPort"]
        url = f"postgresql+asyncpg://owner:owner-pw@127.0.0.1:{port}/keystone"
        # The image serves TCP only once its init is done, so a connection means ready.
        deadline = time.monotonic() + 60
        while True:
            try:
                asyncio.run(ping(asyncpg_dsn(url)))
                break
            except (OSError, asyncpg.PostgresError) as error:
                if time.monotonic() > deadline:
                    raise AssertionError(f"postgres did not come up: {error!r}") from None
                time.sleep(0.5)
        yield url
    finally:
        container.remove(force=True)


@pytest.mark.phase(5)
@pytest.mark.docker
@pytest.mark.usefixtures("clean_env")
def test_a_prod_env_from_the_yaml_file_alone_stops_the_app_role_migration(
    fresh_postgres: str, tmp_path: Path
) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("env: prod\n")
    env = {"KEYSTONE_CONFIG": str(config), "KEYSTONE_DATABASE_URL": fresh_postgres}
    runner = CliRunner()

    refused = runner.invoke(cli, ["db", "upgrade"], env=env)

    assert refused.exit_code == 1, refused.output
    assert "error: set KEYSTONE_APP_DB_PASSWORD" in refused.output
    assert not isinstance(refused.exception, RuntimeError)  # an error line, not a traceback
    assert asyncio.run(role_exists(fresh_postgres)) is False

    # With a password of its own the migration runs, and the public one does not open the role.
    done = runner.invoke(
        cli, ["db", "upgrade"], env={**env, "KEYSTONE_APP_DB_PASSWORD": "prod-only-secret"}
    )

    assert done.exit_code == 0, done.output
    assert asyncio.run(app_role_logs_in_with(fresh_postgres, "prod-only-secret")) is True
    assert asyncio.run(app_role_logs_in_with(fresh_postgres, DEV_APP_PASSWORD)) is False
