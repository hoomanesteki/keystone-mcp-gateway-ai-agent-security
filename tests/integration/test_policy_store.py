"""KS-403: policies are loaded from files, versioned, and reloaded without a gap in the rules."""

import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from typer.testing import CliRunner

from keystone.admin.cli import app as cli
from keystone.core.canonical import sha256_hex
from keystone.policy.store import PolicyLoadError, PolicyStore
from keystone.settings import PolicySettings
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.policies import (
    POLICY_ROOT,
    copy_pack,
    forbid,
    permit,
    reload_policies,
    write_policies,
)

pytestmark = [pytest.mark.phase(4), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
Sessions = async_sessionmaker[AsyncSession]


def own_policies(tmp_path: Path) -> Path:
    return copy_pack(tmp_path)


def start(factory: Factory, root: Path, **options: Any) -> KeystoneApp:
    return factory(settings={"policy": PolicySettings(root=root), **options})


def reload_as(app: KeystoneApp, token: str | None) -> httpx2.Response:
    return reload_policies(app.base, token)


async def recorded(sessions: Sessions) -> list[str]:
    async with sessions() as session:
        rows = await session.execute(text("SELECT version FROM policy_versions ORDER BY loaded_at"))
        return list(rows.scalars())


def test_loads_default_and_tenant_policies(tmp_path: Path) -> None:
    root = own_policies(tmp_path)
    write_policies(
        root,
        {
            "acme/approval/mail.cedar": permit("acme-asks-for-mail"),
            "globex/access/readonly.cedar": forbid("globex-no-writes"),
        },
        schema=None,
    )

    first = PolicyStore(root, ["acme", "globex"])
    loaded = first.start()
    restarted = PolicyStore(root, ["globex", "acme"]).start()  # a new process, tenants in any order

    acme = {p.id for p in loaded.tenants["acme"].policies}
    globex = {p.id for p in loaded.tenants["globex"].policies}
    shared = {
        "same-tenant-low-medium",
        "operators-high",
        "admins-critical",
        "deny-cross-tenant",
        # The Rule of Two (KS-705) is every tenant's.
        "deny-critical-when-tainted",
        "rule-of-two",
        "tainted-external-effect",
        "untrusted-then-external-effect",  # KS-991
    }
    assert acme == shared | {"acme-asks-for-mail"}
    assert globex == shared | {"globex-no-writes"}
    assert len(loaded.version) == 64
    assert restarted.version == loaded.version  # stable across restarts


def test_policy_without_id_rejected(tmp_path: Path) -> None:
    root = own_policies(tmp_path)
    (root / "acme" / "access").mkdir(parents=True)
    (root / "acme" / "access" / "team.cedar").write_text(
        permit("fine") + "forbid (principal, action, resource) when { false };\n"
    )

    with pytest.raises(PolicyLoadError) as raised:
        PolicyStore(root, ["acme"]).start()

    [problem] = raised.value.problems
    assert problem.startswith("acme/access/team.cedar: policy 2 (a forbid) has no @id")
    assert "audit log names the policies" in problem


async def test_an_app_does_not_start_on_a_policy_set_with_a_problem(
    keystone_app_factory: Factory, tmp_path: Path
) -> None:
    root = own_policies(tmp_path)
    (root / "default" / "access" / "broken.cedar").write_text("permit (principal")

    with pytest.raises(PolicyLoadError, match=r"default/access/broken\.cedar"):
        start(keystone_app_factory, root)


async def test_serve_prints_every_problem_and_exits(
    clean_env: None, tmp_path: Path, test_database_url: str, fake_idp: FakeIdp
) -> None:
    root = own_policies(tmp_path)
    (root / "default" / "access" / "a.cedar").write_text("permit (principal")
    (root / "acme" / "approval" / "b.cedar").write_text(forbid("a-forbid"))
    environment = {
        "KEYSTONE_ENV": "test",
        "KEYSTONE_DATABASE_URL": test_database_url,
        "KEYSTONE_OIDC_ISSUER": fake_idp.issuer,
        "KEYSTONE_POLICY__ROOT": str(root),
        "KEYSTONE_TENANTS": '[{"id": "acme", "name": "Acme"}]',
    }

    try:
        result = await anyio.to_thread.run_sync(
            lambda: CliRunner().invoke(cli, ["serve", "--port", "0"], env=environment)
        )
    finally:
        # `serve` configures logging to write to the stream it was given, which is the runner's
        # and is closed by now. Later tests log through the default configuration.
        structlog.reset_defaults()

    assert result.exit_code == 1
    assert "the policies cannot be loaded" in result.output
    assert "default/access/a.cedar: " in result.output
    assert 'acme/approval/b.cedar: "a-forbid" is a forbid' in result.output


async def test_invalid_reload_keeps_previous_version(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    fake_idp: FakeIdp,
    tmp_path: Path,
) -> None:
    root = own_policies(tmp_path)
    app = start(keystone_app_factory, root)
    token = fake_idp.token_for("root")
    before = reload_as(app, token)
    assert before.status_code == 200 and before.json()["changed"] is False, before.text
    version = before.json()["version"]

    (root / "default" / "access" / "base.cedar").write_text("permit (principal, action")
    refused = reload_as(app, token)

    assert refused.status_code == 422
    body = refused.json()
    assert body["error"] == "invalid_policies"
    assert body["version"] == version  # the version in force did not move
    assert [e.split(":")[0] for e in body["errors"]] == ["default/access/base.cedar"]
    assert app.app.state.policies.version == version
    async with mcp_client(app) as client:  # and calls still work
        result = await client.call_tool("echo__echo", {"payload": "still served"})
    assert texts(result) == ["still served"]
    # Fixing the file brings the same version back, without a restart.
    shutil.copyfile(POLICY_ROOT / "default/access/base.cedar", root / "default/access/base.cedar")
    assert reload_as(app, token).json() == {
        "version": version,
        "previous": version,
        "changed": False,
    }


async def test_version_changes_on_edit(
    keystone_app_factory: Factory, fake_idp: FakeIdp, tmp_path: Path, sessionmaker: Sessions
) -> None:
    root = own_policies(tmp_path)
    app = start(keystone_app_factory, root)
    token = fake_idp.token_for("root")
    first = app.app.state.policies.version
    base = root / "default" / "access" / "base.cedar"
    original = base.read_text()

    base.write_text(original + "\n" + permit("extra-permit", "context.hour_utc < 20"))
    edited = reload_as(app, token)
    base.write_text(original)
    restored = reload_as(app, token)

    assert edited.status_code == 200
    assert edited.json()["changed"] is True and edited.json()["previous"] == first
    second = edited.json()["version"]
    assert second != first
    assert restored.json() == {"version": first, "previous": second, "changed": True}
    assert await recorded(sessions=sessionmaker) == [first, second]  # each version once


async def test_the_version_row_keeps_every_file_it_was_made_of(
    keystone_app_factory: Factory, tmp_path: Path, sessionmaker: Sessions
) -> None:
    root = own_policies(tmp_path)
    app = start(keystone_app_factory, root)

    async with sessionmaker() as session:
        row = (
            await session.execute(text("SELECT version, files, loaded_at FROM policy_versions"))
        ).one()

    assert row.version == app.app.state.policies.version
    files = {f["path"]: f for f in row.files}
    assert files["default/access/base.cedar"]["content"] == (
        (root / "default/access/base.cedar").read_text()
    )
    assert files["schema.cedarschema"]["sha256"] == sha256_hex(
        (root / "schema.cedarschema").read_bytes()
    )
    assert row.loaded_at is not None


async def test_a_restart_on_the_same_files_records_nothing_new(
    keystone_app_factory: Factory, tmp_path: Path, sessionmaker: Sessions
) -> None:
    root = own_policies(tmp_path)
    first = start(keystone_app_factory, root)
    version = first.app.state.policies.version
    first.thread.stop()

    second = start(keystone_app_factory, root)

    assert second.app.state.policies.version == version
    assert await recorded(sessions=sessionmaker) == [version]


async def test_reload_needs_a_token_and_the_admin_role(
    keystone_app_factory: Factory, fake_idp: FakeIdp, tmp_path: Path
) -> None:
    app = start(keystone_app_factory, own_policies(tmp_path))

    nothing = reload_as(app, None)
    garbage = reload_as(app, "not-a-token")
    expired = reload_as(app, fake_idp.token_for("root", exp_in=-600))
    support = reload_as(app, fake_idp.token_for("alice"))
    operator = reload_as(app, fake_idp.token_for("olivia"))
    approver = reload_as(app, fake_idp.token_for("lena"))
    elsewhere = reload_as(app, fake_idp.token_for("bob"))
    root_user = reload_as(app, fake_idp.token_for("root"))

    assert nothing.status_code == 401
    assert nothing.headers["www-authenticate"].startswith("Bearer resource_metadata=")
    assert nothing.json() == {"error": "unauthorized", "reason": "no_credentials"}
    assert garbage.status_code == 401 and garbage.json()["error"] == "invalid_token"
    assert expired.status_code == 401 and expired.json()["reason"] == "expired"
    for denied in (support, operator, approver):
        assert denied.status_code == 403
        assert denied.json() == {"error": "forbidden", "reason": "the admin role is required"}
    assert elsewhere.status_code == 403
    assert root_user.status_code == 200


async def test_the_admin_may_come_through_a_client_that_is_not_a_listed_agent(
    keystone_app_factory: Factory, fake_idp: FakeIdp, tmp_path: Path
) -> None:
    app = start(keystone_app_factory, own_policies(tmp_path))

    # keystone-cli is how the admin CLI signs in, and it is not under `agents`.
    through_cli = reload_as(app, fake_idp.token_for("root", agent="keystone-cli"))
    through_agent = reload_as(app, fake_idp.token_for("root", agent="ops-agent"))
    # The MCP endpoint still refuses an unlisted agent: only the admin API relaxes that rule.
    mcp = httpx2.post(
        app.url,
        headers={
            "Authorization": f"Bearer {fake_idp.token_for('root', agent='keystone-cli')}",
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        timeout=30,
    )

    assert through_cli.status_code == 200 and through_agent.status_code == 200
    assert mcp.status_code == 403 and mcp.json()["reason"] == "unknown_agent"


async def test_the_cli_reloads_and_reports(
    keystone_app_factory: Factory, fake_idp: FakeIdp, tmp_path: Path
) -> None:
    root = own_policies(tmp_path)
    app = start(keystone_app_factory, root)
    token = fake_idp.token_for("root", agent="keystone-cli")
    base = root / "default" / "access" / "base.cedar"
    original = base.read_text()

    def run(*args: str, **env: str) -> Any:
        return CliRunner().invoke(cli, ["policy", "reload", "--url", app.base, *args], env=env)

    async def invoke(*args: str, **env: str) -> Any:
        return await anyio.to_thread.run_sync(lambda: run(*args, **env))

    unchanged = await invoke("--token", token)
    base.write_text(original + "\n" + permit("one-more", "context.hour_utc < 20"))
    changed = await invoke(KEYSTONE_ADMIN_TOKEN=token)  # the token from the environment
    base.write_text("permit (")
    refused = await invoke("--token", token)
    no_token = await invoke()
    wrong = await invoke("--token", fake_idp.token_for("alice"))
    nowhere = await anyio.to_thread.run_sync(
        lambda: CliRunner().invoke(
            cli, ["policy", "reload", "--url", "http://127.0.0.1:1", "--token", token]
        )
    )

    assert unchanged.exit_code == 0 and "(unchanged)" in unchanged.output
    assert changed.exit_code == 0 and "(changed)" in changed.output
    assert refused.exit_code == 1
    assert "the new policies were refused" in refused.output
    assert "stays in force" in refused.output
    assert "default/access/base.cedar: " in refused.output
    assert no_token.exit_code == 1 and "no token" in no_token.output
    assert wrong.exit_code == 1 and "answered 403" in wrong.output
    assert nowhere.exit_code == 1 and "cannot reach Keystone" in nowhere.output
    assert token not in refused.output + no_token.output + wrong.output + nowhere.output
