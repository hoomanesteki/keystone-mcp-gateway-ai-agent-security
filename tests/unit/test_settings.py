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
