"""KS-203: `keystone registry sync` and `keystone upstream sync`."""

import json
from typing import Any

import anyio
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from typer.testing import CliRunner

from keystone.admin.cli import app as cli
from keystone.core.types import Risk
from keystone.db.tenants import upsert_tenants
from keystone.registry.config import UpstreamConfig, apply_config_upstreams
from keystone.registry.repo import ToolRepo, UpstreamRepo
from keystone.settings import TenantConfig
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
DEAD = "http://127.0.0.1:1/mcp"


async def invoke(url: str, args: list[str], **env: str) -> Any:
    environment = {"KEYSTONE_DATABASE_URL": url, "KEYSTONE_ALLOW_PRIVATE_UPSTREAMS": "true", **env}
    return await anyio.to_thread.run_sync(lambda: CliRunner().invoke(cli, args, env=environment))


async def seed(sessions: Sessions, demo: DemoUpstreams, **urls: str) -> None:
    await upsert_tenants(sessions, [TenantConfig(id="acme", name="Acme Corp")])
    entries = [
        UpstreamConfig(id=name, tenant="acme", url=urls.get(name, demo.url(name)))
        for name in ("mail", "bank", *urls)
    ]
    unique = list({e.id: e for e in entries}.values())
    await apply_config_upstreams(UpstreamRepo(sessions), unique, ["acme"], allow_private=True)


async def test_registry_sync_reads_every_upstream(
    clean_env: None, test_database_url: str, sessionmaker: Sessions, demo_upstreams: DemoUpstreams
) -> None:
    await seed(sessionmaker, demo_upstreams)

    result = await invoke(test_database_url, ["registry", "sync"])

    assert result.exit_code == 0, result.output
    rows = {line.split()[0]: line.split() for line in result.output.splitlines()[1:]}
    assert rows["bank"] == ["bank", "3", "0", "0", "0", "ok"]
    assert rows["mail"] == ["mail", "3", "0", "0", "0", "ok"]
    assert len(await ToolRepo(sessionmaker).list_by_tenant("acme")) == 6
    assert {u.id: u.status for u in await UpstreamRepo(sessionmaker).list()} == {
        "bank": "up",
        "mail": "up",
    }

    again = await invoke(test_database_url, ["registry", "sync", "--json"])
    reports = {r["upstream_id"]: r for r in json.loads(again.output)}
    assert len(reports["mail"]["unchanged"]) == 3
    assert reports["mail"]["created"] == []


async def test_a_dead_upstream_makes_the_exit_code_1_and_leaves_the_others_synced(
    clean_env: None, test_database_url: str, sessionmaker: Sessions, demo_upstreams: DemoUpstreams
) -> None:
    await seed(sessionmaker, demo_upstreams, bank=DEAD)

    result = await invoke(test_database_url, ["registry", "sync"])

    assert result.exit_code == 1, result.output
    assert "error: KS_UPSTREAM_ERROR" in result.output
    mail = await UpstreamRepo(sessionmaker).get("mail")
    bank = await UpstreamRepo(sessionmaker).get("bank")
    assert mail is not None and mail.status == "up" and mail.last_error is None
    assert bank is not None and bank.last_error is not None and bank.last_sync_at is None
    names = [t.name for t in await ToolRepo(sessionmaker).list_by_tenant("acme")]
    assert names and all(n.startswith("mail__") for n in names)


async def test_sync_one_upstream_by_either_command(
    clean_env: None, test_database_url: str, sessionmaker: Sessions, demo_upstreams: DemoUpstreams
) -> None:
    await seed(sessionmaker, demo_upstreams)

    by_option = await invoke(test_database_url, ["registry", "sync", "--upstream", "mail"])
    by_name = await invoke(test_database_url, ["upstream", "sync", "bank"])
    unknown = await invoke(test_database_url, ["registry", "sync", "--upstream", "ghost"])

    assert by_option.exit_code == by_name.exit_code == 0
    assert "mail" in by_option.output and "bank" not in by_option.output
    assert "bank" in by_name.output and "mail" not in by_name.output
    assert unknown.exit_code == 1
    assert "there is no such upstream" in unknown.output


async def test_the_command_applies_the_overrides_from_the_config_file(
    clean_env: None,
    test_database_url: str,
    sessionmaker: Sessions,
    demo_upstreams: DemoUpstreams,
    tmp_path: Any,
) -> None:
    await seed(sessionmaker, demo_upstreams)
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "tenants:\n  - {id: acme, name: Acme Corp}\n"
        "upstreams:\n"
        f"  - id: mail\n    tenant: acme\n    url: '{demo_upstreams.url('mail')}'\n"
        "    tools:\n      send_email: {risk: high, tags: [external_effect]}\n"
    )

    result = await invoke(test_database_url, ["registry", "sync"], KEYSTONE_CONFIG=str(config))

    assert result.exit_code == 0, result.output
    send = await ToolRepo(sessionmaker).get("acme", "mail__send_email")
    read = await ToolRepo(sessionmaker).get("acme", "mail__read_email")
    assert send is not None and read is not None
    assert (send.risk, send.tags) == (Risk.HIGH.value, ["external_effect"])
    assert read.risk == Risk.MEDIUM.value


async def test_sync_with_nothing_registered_says_so(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> None:
    result = await invoke(test_database_url, ["registry", "sync"])

    assert result.exit_code == 0
    assert "no upstreams to sync" in result.output
