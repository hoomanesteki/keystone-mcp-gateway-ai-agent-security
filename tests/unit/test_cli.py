from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog
from alembic.config import Config
from alembic.script import ScriptDirectory
from typer.testing import CliRunner

import keystone.admin.cli as cli_module
from keystone import __version__
from keystone.admin.cli import app

runner = CliRunner()


@pytest.mark.phase(0)
def test_version_command_prints_the_package_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.phase(0)
def test_help_lists_serve() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "serve" in result.output


@pytest.fixture
def logging_restored() -> Iterator[None]:
    # `serve` configures logging for the whole process, pointing it at the captured stdout of
    # this test. Without a reset, a later test that logs writes to a file that is closed.
    yield
    structlog.reset_defaults()


@pytest.mark.phase(3)
@pytest.mark.usefixtures("logging_restored")
def test_serve_refuses_to_start_without_an_issuer(clean_env: None) -> None:
    result = runner.invoke(app, ["serve"], env={"KEYSTONE_ENV": "test"})

    assert result.exit_code == 1
    assert "oidc_issuer" in result.output


@pytest.mark.phase(3)
@pytest.mark.usefixtures("logging_restored")
def test_serve_refuses_to_start_with_authentication_off_in_prod(clean_env: None) -> None:
    result = runner.invoke(
        app, ["serve"], env={"KEYSTONE_ENV": "prod", "KEYSTONE_AUTH__MODE": "none"}
    )

    assert result.exit_code == 1
    assert "auth.mode none is only allowed when env is dev or test" in result.output


@pytest.fixture
def app_role_decisions(monkeypatch: pytest.MonkeyPatch) -> list[Config]:
    """`alembic.command.upgrade` replaced by the one decision migration 0006 makes without a
    database: the password of keystone_app, from the config the CLI built. Returns the configs
    it was given."""
    seen: list[Config] = []

    def decide(config: Config, revision: str) -> None:
        seen.append(config)
        ScriptDirectory.from_config(config).get_revision("0006").module.password(config)

    monkeypatch.setattr(cli_module.command, "upgrade", decide)
    return seen


@pytest.mark.phase(5)
def test_db_upgrade_refuses_the_dev_app_password_when_the_yaml_file_says_prod(
    tmp_path: Path, clean_env: None, app_role_decisions: list[Config]
) -> None:
    # Every other production guard reads settings.env, which the YAML file may set. The migration
    # that creates keystone_app must decide from the same value, or a deployment that is prod in
    # the YAML alone gets the role with the public development password.
    config = tmp_path / "keystone.yaml"
    config.write_text("env: prod\n")

    result = runner.invoke(app, ["db", "upgrade"], env={"KEYSTONE_CONFIG": str(config)})

    assert result.exit_code == 1
    assert "error: set KEYSTONE_APP_DB_PASSWORD" in result.output
    assert not isinstance(result.exception, RuntimeError)  # an error line, not a traceback
    assert [c.attributes["env"] for c in app_role_decisions] == ["prod"]


@pytest.mark.phase(5)
def test_db_upgrade_hands_the_migrations_the_env_and_the_url(
    tmp_path: Path, clean_env: None, app_role_decisions: list[Config]
) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("env: prod\n")
    url = "postgresql+asyncpg://owner:pw@db.test/keystone"
    env = {
        "KEYSTONE_CONFIG": str(config),
        "KEYSTONE_MIGRATE_DATABASE_URL": url,
        "KEYSTONE_APP_DB_PASSWORD": "a-secret-of-its-own",
    }

    result = runner.invoke(app, ["db", "upgrade"], env=env)

    assert result.exit_code == 0, result.output
    assert "database is up to date" in result.output
    [given] = app_role_decisions
    assert (given.attributes["env"], given.attributes["url"]) == ("prod", url)


@pytest.mark.phase(5)
@pytest.mark.usefixtures("logging_restored")
def test_serve_migrate_stops_with_an_error_when_a_migration_refuses(
    tmp_path: Path,
    clean_env: None,
    monkeypatch: pytest.MonkeyPatch,
    app_role_decisions: list[Config],
) -> None:
    monkeypatch.setattr(cli_module, "create_app", lambda settings: object())

    def not_served(*args: Any, **kwargs: Any) -> None:
        pytest.fail("the gateway started although the migration refused")

    monkeypatch.setattr(cli_module.uvicorn, "run", not_served)
    config = tmp_path / "keystone.yaml"
    config.write_text("env: prod\noidc_issuer: https://idp.test/realms/keystone\n")

    result = runner.invoke(app, ["serve", "--migrate"], env={"KEYSTONE_CONFIG": str(config)})

    assert result.exit_code == 1
    assert "error: set KEYSTONE_APP_DB_PASSWORD" in result.output
    assert not isinstance(result.exception, RuntimeError)
