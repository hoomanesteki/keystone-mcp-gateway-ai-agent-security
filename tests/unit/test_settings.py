from pathlib import Path

import pytest

from keystone.settings import Settings

pytestmark = pytest.mark.usefixtures("clean_env")


@pytest.mark.phase(0)
def test_env_overrides_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("log_level: debug\nenv: test\n")
    monkeypatch.setenv("KEYSTONE_CONFIG", str(config))
    monkeypatch.setenv("KEYSTONE_LOG_LEVEL", "warning")

    settings = Settings()

    assert settings.log_level == "WARNING"
    assert settings.env == "test"
    assert settings.config_path == config


@pytest.mark.phase(0)
def test_defaults_point_at_the_compose_ports() -> None:
    settings = Settings()

    assert settings.env == "dev"
    assert settings.config_path is None
    assert settings.database_url.get_secret_value() == (
        "postgresql+asyncpg://keystone:keystone@localhost:55432/keystone"
    )
    assert settings.redis_url.get_secret_value() == "redis://localhost:56379/0"


@pytest.mark.phase(0)
def test_urls_are_secret_strings() -> None:
    settings = Settings()

    assert "keystone:keystone" not in repr(settings)
    assert "keystone:keystone" not in settings.model_dump_json()


@pytest.mark.phase(0)
def test_unknown_yaml_sections_are_ignored(tmp_path: Path) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("upstreams:\n  - id: mail\nagents:\n  support-agent: {trust: standard}\n")

    assert Settings(config_path=config).env == "dev"


@pytest.mark.phase(0)
def test_missing_config_file_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_CONFIG", str(tmp_path / "nope.yaml"))

    with pytest.raises(FileNotFoundError, match=r"nope\.yaml"):
        Settings()


@pytest.mark.phase(0)
def test_invalid_env_value_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_ENV", "staging")

    with pytest.raises(ValueError, match="env"):
        Settings()


@pytest.mark.phase(1)
@pytest.mark.parametrize("env", ["dev", "test"])
def test_dev_and_test_get_the_phase_1_dev_principal(env: str) -> None:
    principal = Settings(env=env).dev_principal  # type: ignore[arg-type]

    assert principal is not None
    assert (principal.tenant_id, principal.user_id, principal.agent_id) == (
        "acme",
        "olivia",
        "ops-agent",
    )
    assert principal.groups == ("operators",)


@pytest.mark.phase(1)
def test_prod_has_no_dev_principal_and_refuses_one() -> None:
    assert Settings(env="prod").dev_principal is None

    with pytest.raises(ValueError, match="dev_principal"):
        Settings(
            env="prod",
            dev_principal={"tenant_id": "acme", "user_id": "x", "agent_id": "y"},  # type: ignore[arg-type]
        )


@pytest.mark.phase(1)
def test_upstreams_load_from_yaml(tmp_path: Path) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "upstreams:\n"
        "  - {id: mail, tenant: acme, url: 'http://mail-mcp:8101/mcp'}\n"
        "  - {id: sandbox, tenant: acme, transport: builtin}\n"
    )

    settings = Settings(config_path=config)

    assert [(u.id, u.transport, u.url) for u in settings.upstreams] == [
        ("mail", "http", "http://mail-mcp:8101/mcp"),
        ("sandbox", "builtin", None),
    ]


@pytest.mark.phase(1)
@pytest.mark.parametrize("bad", ["Mail", "ma__il", "mail_", "1mail", "m", "ma-il"])
def test_upstream_ids_follow_the_naming_rules(bad: str) -> None:
    with pytest.raises(ValueError, match="upstream id"):
        Settings(upstreams=[{"id": bad}])  # type: ignore[list-item]


@pytest.mark.phase(1)
def test_allowed_hosts_default_to_loopback() -> None:
    assert Settings().allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]


@pytest.mark.phase(1)
def test_allowed_hosts_and_dev_principal_come_from_json_env_vars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEYSTONE_ALLOWED_HOSTS", '["keystone:*", "localhost:*"]')
    monkeypatch.setenv(
        "KEYSTONE_DEV_PRINCIPAL",
        '{"tenant_id": "globex", "user_id": "quinn", "agent_id": "support-agent"}',
    )

    settings = Settings()

    assert settings.allowed_hosts == ["keystone:*", "localhost:*"]
    assert settings.dev_principal is not None
    assert (settings.dev_principal.tenant_id, settings.dev_principal.user_id) == ("globex", "quinn")
