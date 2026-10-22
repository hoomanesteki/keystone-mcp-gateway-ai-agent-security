"""KS-202: config upstreams reach the database at startup, and the CLI manages the others."""

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.app import create_app
from keystone.db.tenants import upsert_tenants
from keystone.registry.config import ConfigError, UpstreamConfig, apply_config_upstreams
from keystone.registry.repo import UpstreamRepo, UpstreamSpec
from keystone.settings import Settings, TenantConfig
from tests.fixtures.cli import invoke
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import NAMES, DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
ACME = TenantConfig(id="acme", name="Acme Corp")
GLOBEX = TenantConfig(id="globex", name="Globex")


def entry(
    upstream_id: str, url: str = "http://127.0.0.1:1/mcp", tenant: str = "acme"
) -> UpstreamConfig:
    return UpstreamConfig(id=upstream_id, tenant=tenant, url=url)


@pytest.fixture
def start_keystone(
    clean_env: None,
    test_database_url: str,
    sessionmaker: Sessions,
    test_redis_url: str,
    redis: Redis,
) -> Iterator[Callable[[list[UpstreamConfig]], ServerThread]]:
    """Start the whole app on the test database with the given upstreams."""
    started: list[ServerThread] = []

    def start(upstreams: list[UpstreamConfig]) -> ServerThread:
        settings = Settings(
            env="test",
            database_url=SecretStr(test_database_url),
            redis_url=SecretStr(test_redis_url),
            tenants=[ACME],
            upstreams=upstreams,
            allow_private_upstreams=True,
        )
        thread = ServerThread(create_app(settings)).start()
        started.append(thread)
        return thread

    yield start
    for thread in started:
        if thread.server.started:
            thread.stop()


def from_demo(demo: DemoUpstreams, names: tuple[str, ...] = NAMES) -> list[UpstreamConfig]:
    return [entry(name, demo.url(name)) for name in names]


async def statuses(sessions: Sessions) -> dict[str, str]:
    return {row.id: row.status for row in await UpstreamRepo(sessions).list()}


async def test_config_upstreams_loaded(
    start_keystone: Callable[[list[UpstreamConfig]], ServerThread],
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    start_keystone(from_demo(demo_upstreams))

    rows = {row.id: row for row in await UpstreamRepo(sessionmaker).list()}
    assert set(rows) == set(NAMES)
    for name, row in rows.items():
        assert (row.tenant_id, row.transport, row.source) == ("acme", "http", "config")
        assert row.url == demo_upstreams.url(name)
        assert row.status != "disabled"


async def test_removed_upstream_disabled(
    start_keystone: Callable[[list[UpstreamConfig]], ServerThread],
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    first = start_keystone(from_demo(demo_upstreams))
    first.stop()

    start_keystone(from_demo(demo_upstreams, ("mail", "files", "bank")))

    found = await statuses(sessionmaker)
    assert found["echo"] == "disabled"
    assert {found[name] for name in ("mail", "files", "bank")}.isdisjoint({"disabled"})
    # The row is kept: audit records still name it.
    assert (await UpstreamRepo(sessionmaker).get("echo")) is not None


async def test_an_upstream_that_returns_to_the_file_is_enabled_again(
    start_keystone: Callable[[list[UpstreamConfig]], ServerThread],
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    start_keystone(from_demo(demo_upstreams, ("mail", "echo"))).stop()
    start_keystone(from_demo(demo_upstreams, ("mail",))).stop()
    assert (await statuses(sessionmaker))["echo"] == "disabled"

    start_keystone(from_demo(demo_upstreams, ("mail", "echo")))

    assert (await statuses(sessionmaker))["echo"] != "disabled"


async def test_a_cli_upstream_is_not_disabled_by_a_restart(
    start_keystone: Callable[[list[UpstreamConfig]], ServerThread],
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)

    await repo.upsert(
        UpstreamSpec(id="scratch", tenant_id="acme", url="http://127.0.0.1:1/mcp", source="cli")
    )

    start_keystone(from_demo(demo_upstreams, ("mail",)))

    assert (await statuses(sessionmaker))["scratch"] != "disabled"


async def test_a_config_the_registry_cannot_use_stops_startup_and_writes_nothing(
    sessionmaker: Sessions,
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)
    good = entry("mail", "http://93.184.216.34/mcp")
    bad = entry("bank", "http://169.254.169.254/mcp")

    with pytest.raises(ConfigError, match="bank"):
        await apply_config_upstreams(repo, [good, bad], ["acme"], allow_private=False)

    assert await repo.list() == []


async def test_private_urls_are_accepted_when_allowed(sessionmaker: Sessions) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)
    private = [entry("mail", "http://10.0.0.5/mcp"), entry("bank", "http://169.254.169.254/")]

    report = await apply_config_upstreams(repo, private, ["acme"], allow_private=True)

    assert report.upserted == ["mail", "bank"]


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (UpstreamConfig(id="mail", url="http://93.184.216.34/"), "needs a tenant"),
        (entry("mail", tenant="initech"), "tenant 'initech'"),
        (UpstreamConfig(id="mail", tenant="acme"), "needs a url"),
        (UpstreamConfig(id="mail", tenant="acme", transport="stdio"), "needs a command"),
        (entry("mail", "ftp://93.184.216.34/"), "http or https"),
    ],
)
async def test_each_unusable_entry_is_named(
    sessionmaker: Sessions, config: UpstreamConfig, message: str
) -> None:
    await upsert_tenants(sessionmaker, [ACME])

    with pytest.raises(ConfigError, match=message):
        await apply_config_upstreams(
            UpstreamRepo(sessionmaker), [config], ["acme"], allow_private=False
        )


async def test_duplicate_ids_and_foreign_tenants_are_refused(sessionmaker: Sessions) -> None:
    await upsert_tenants(sessionmaker, [ACME, GLOBEX])
    repo = UpstreamRepo(sessionmaker)
    mail = entry("mail", "http://93.184.216.34/")

    with pytest.raises(ConfigError, match="listed twice"):
        await apply_config_upstreams(repo, [mail, mail], ["acme"], allow_private=False)

    await apply_config_upstreams(repo, [mail], ["acme", "globex"], allow_private=False)
    stolen = entry("mail", "http://93.184.216.34/", tenant="globex")
    with pytest.raises(ConfigError, match="already belongs to another tenant"):
        await apply_config_upstreams(repo, [stolen], ["acme", "globex"], allow_private=False)


async def test_builtin_upstreams_are_not_stored(sessionmaker: Sessions) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    repo = UpstreamRepo(sessionmaker)
    sandbox = UpstreamConfig(id="sandbox", tenant="acme", transport="builtin")

    report = await apply_config_upstreams(repo, [sandbox], ["acme"])

    assert (report.skipped, await repo.list()) == (["sandbox"], [])


async def test_cli_add_list_remove(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> None:
    await upsert_tenants(sessionmaker, [ACME])

    added = await invoke(
        test_database_url,
        ["upstream", "add", "scratch", "--tenant", "acme", "--url", "http://127.0.0.1:9/mcp"],
    )
    listed = await invoke(test_database_url, ["upstream", "list"])
    as_json = await invoke(test_database_url, ["upstream", "list", "--json"])

    assert added.exit_code == 0, added.output
    assert "added upstream scratch" in added.output
    assert listed.exit_code == 0, listed.output
    [line] = [x for x in listed.output.splitlines() if x.startswith("scratch")]
    assert line.split()[:5] == ["scratch", "acme", "http", "unknown", "cli"]
    assert "http://127.0.0.1:9/mcp" in line
    [row] = json.loads(as_json.output)
    assert (row["id"], row["source"], row["last_sync_at"]) == ("scratch", "cli", None)

    removed = await invoke(test_database_url, ["upstream", "remove", "scratch"])
    after = await invoke(test_database_url, ["upstream", "list"])
    everything = await invoke(test_database_url, ["upstream", "list", "--all"])

    assert removed.exit_code == 0, removed.output
    assert "no upstreams registered" in after.output
    assert "disabled" in everything.output
    # The row is kept, so a call it served can still be traced.
    assert (await UpstreamRepo(sessionmaker).get("scratch")) is not None

    again = await invoke(
        test_database_url,
        ["upstream", "add", "scratch", "--tenant", "acme", "--url", "http://127.0.0.1:9/mcp"],
    )
    assert again.exit_code == 0, again.output
    assert (await statuses(sessionmaker))["scratch"] == "unknown"


async def test_cli_add_refuses_a_private_url_unless_allowed(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> None:
    await upsert_tenants(sessionmaker, [ACME])

    for url in ("http://169.254.169.254/", "http://10.0.0.5/mcp", "http://[::1]:8080/mcp"):
        refused = await invoke(
            test_database_url,
            ["upstream", "add", "scratch", "--tenant", "acme", "--url", url],
            KEYSTONE_ALLOW_PRIVATE_UPSTREAMS="false",
        )
        assert refused.exit_code == 1, refused.output
        assert "url refused" in refused.output

    assert await UpstreamRepo(sessionmaker).list() == []


async def test_cli_uses_the_only_configured_tenant_and_reports_a_missing_one(
    clean_env: None, test_database_url: str, sessionmaker: Sessions, tmp_path: Any
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    config = tmp_path / "keystone.yaml"
    config.write_text("tenants:\n  - {id: acme, name: Acme Corp}\n")
    args = ["upstream", "add", "scratch", "--url", "http://127.0.0.1:9/mcp"]

    without = await invoke(test_database_url, args)
    with_config = await invoke(test_database_url, args, KEYSTONE_CONFIG=str(config))
    unknown = await invoke(
        test_database_url,
        ["upstream", "add", "other", "--url", "http://127.0.0.1:9/mcp", "--tenant", "initech"],
    )

    assert without.exit_code == 1
    assert "pass --tenant" in without.output
    assert with_config.exit_code == 0, with_config.output
    assert unknown.exit_code == 1
    assert "no tenant 'initech'" in unknown.output


async def test_cli_will_not_change_a_config_upstream(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> None:
    await upsert_tenants(sessionmaker, [ACME])
    await apply_config_upstreams(
        UpstreamRepo(sessionmaker),
        [entry("mail", "http://127.0.0.1:1/mcp")],
        ["acme"],
        allow_private=True,
    )

    removed = await invoke(test_database_url, ["upstream", "remove", "mail"])
    replaced = await invoke(
        test_database_url,
        ["upstream", "add", "mail", "--tenant", "acme", "--url", "http://127.0.0.1:2/mcp"],
    )

    for result in (removed, replaced):
        assert result.exit_code == 1
        assert "config file" in result.output
    row = await UpstreamRepo(sessionmaker).get("mail")
    assert row is not None
    assert (row.status, row.source, row.url) == ("unknown", "config", "http://127.0.0.1:1/mcp")


async def test_cli_rejects_a_bad_id_and_a_missing_upstream(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> None:
    await upsert_tenants(sessionmaker, [ACME])

    bad_id = await invoke(
        test_database_url,
        ["upstream", "add", "Bad__Id", "--tenant", "acme", "--url", "http://127.0.0.1:9/mcp"],
    )
    missing = await invoke(test_database_url, ["upstream", "remove", "ghost"])
    no_url = await invoke(test_database_url, ["upstream", "add", "scratch", "--tenant", "acme"])

    assert [r.exit_code for r in (bad_id, missing, no_url)] == [1, 1, 1]
    assert "invalid upstream id" in bad_id.output
    assert "no upstream 'ghost'" in missing.output
    assert "needs --url" in no_url.output


async def test_cli_says_when_the_database_is_unreachable(clean_env: None) -> None:
    result = await invoke(
        "postgresql+asyncpg://nobody:secretpw@127.0.0.1:1/none", ["upstream", "list"]
    )

    assert result.exit_code == 1
    assert "cannot use the database" in result.output
    assert "secretpw" not in result.output
