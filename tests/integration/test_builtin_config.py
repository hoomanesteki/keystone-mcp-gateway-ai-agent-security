"""KS-802 and KS-803: built-in and containerized upstreams reach the database from the config."""

import json

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.db.tenants import upsert_tenants
from keystone.registry.config import UpstreamConfig, apply_config_upstreams
from keystone.registry.repo import UpstreamRepo
from keystone.settings import TenantConfig
from tests.fixtures.cli import invoke

pytestmark = [pytest.mark.phase(8), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
ACME = TenantConfig(id="acme", name="Acme Corp")
SANDBOX = UpstreamConfig(id="sandbox", tenant="acme", transport="builtin")


async def test_a_builtin_upstream_is_stored_when_this_process_serves_it(
    sessionmaker: Sessions,
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)

    report = await apply_config_upstreams(repo, [SANDBOX], ["acme"], builtins={"sandbox"})

    [row] = await repo.list()
    assert (report.upserted, report.skipped) == (["sandbox"], [])
    assert (row.id, row.tenant_id, row.transport, row.source) == (
        "sandbox",
        "acme",
        "builtin",
        "config",
    )
    assert (row.url, row.command, row.image) == (None, None, None)


async def test_turning_the_sandbox_off_disables_the_upstream_that_was_stored(
    sessionmaker: Sessions,
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)
    await apply_config_upstreams(repo, [SANDBOX], ["acme"], builtins={"sandbox"})
    await repo.set_status("sandbox", "up")

    off = await apply_config_upstreams(repo, [SANDBOX], ["acme"], builtins=())

    row = await repo.get("sandbox")
    assert row is not None and row.status == "disabled"
    assert (off.skipped, off.disabled) == (["sandbox"], ["sandbox"])


async def test_turning_it_back_on_brings_the_upstream_back(sessionmaker: Sessions) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)
    await apply_config_upstreams(repo, [SANDBOX], ["acme"], builtins={"sandbox"})
    await apply_config_upstreams(repo, [SANDBOX], ["acme"], builtins=())

    await apply_config_upstreams(repo, [SANDBOX], ["acme"], builtins={"sandbox"})

    row = await repo.get("sandbox")
    assert row is not None and row.status == "unknown"


async def test_a_containerized_upstream_is_stored_with_its_image_and_command(
    sessionmaker: Sessions,
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)
    echoc = UpstreamConfig(
        id="echoc",
        tenant="acme",
        transport="container_stdio",
        image="keystone-echo-stdio:dev",
        command=["python", "-m", "examples.upstreams.echo_server", "--transport", "stdio"],
    )

    await apply_config_upstreams(repo, [echoc], ["acme"])

    row = await repo.get("echoc")
    assert row is not None
    assert (row.transport, row.image) == ("container_stdio", "keystone-echo-stdio:dev")
    assert row.command == echoc.command


async def test_the_database_refuses_a_transport_it_does_not_know(sessionmaker: Sessions) -> None:
    from sqlalchemy import text

    await upsert_tenants(sessionmaker, [ACME])

    async with sessionmaker() as session:
        with pytest.raises(Exception, match="ck_upstreams_transport"):
            await session.execute(
                text(
                    "INSERT INTO upstreams (id, tenant_id, transport) "
                    "VALUES ('odd', 'acme', 'carrier_pigeon')"
                )
            )


async def test_cli_adds_a_containerized_upstream(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> None:
    await upsert_tenants(sessionmaker, [ACME])

    added = await invoke(
        test_database_url,
        [
            "upstream",
            "add",
            "echoc",
            "--tenant",
            "acme",
            "--transport",
            "container_stdio",
            "--image",
            "keystone-echo-stdio:dev",
            "--",
            "python",
            "-m",
            "examples.upstreams.echo_server",
            "--transport",
            "stdio",
        ],
    )
    listed = await invoke(test_database_url, ["upstream", "list", "--json"])

    assert added.exit_code == 0, added.output
    [row] = json.loads(listed.output)
    assert row["transport"] == "container_stdio"
    assert row["target"].startswith("image keystone-echo-stdio:dev python -m")


@pytest.mark.parametrize(
    "args",
    [
        ["--transport", "container_stdio"],
        ["--transport", "container_stdio", "--image", "--privileged"],
    ],
)
async def test_cli_needs_a_real_image_for_a_containerized_upstream(
    clean_env: None, test_database_url: str, sessionmaker: Sessions, args: list[str]
) -> None:
    await upsert_tenants(sessionmaker, [ACME])

    refused = await invoke(
        test_database_url, ["upstream", "add", "echoc", "--tenant", "acme", *args]
    )

    assert refused.exit_code != 0
    assert await UpstreamRepo(sessionmaker).get("echoc") is None
