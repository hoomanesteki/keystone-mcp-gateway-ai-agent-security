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
    # Since KS-304 the dev principal exists only when authentication is turned off.
    principal = Settings(env=env, auth={"mode": "none"}).dev_principal  # type: ignore[arg-type]

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
    monkeypatch.setenv("KEYSTONE_AUTH__MODE", "none")
    monkeypatch.setenv(
        "KEYSTONE_DEV_PRINCIPAL",
        '{"tenant_id": "globex", "user_id": "quinn", "agent_id": "support-agent"}',
    )

    settings = Settings()

    assert settings.allowed_hosts == ["keystone:*", "localhost:*"]
    assert settings.dev_principal is not None
    assert (settings.dev_principal.tenant_id, settings.dev_principal.user_id) == ("globex", "quinn")


@pytest.mark.phase(2)
def test_private_upstreams_are_refused_unless_the_switch_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Settings().allow_private_upstreams is False

    monkeypatch.setenv("KEYSTONE_ALLOW_PRIVATE_UPSTREAMS", "true")

    assert Settings().allow_private_upstreams is True


@pytest.mark.phase(2)
def test_registry_timings_have_defaults_and_come_from_env_or_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    defaults = Settings().registry
    assert (defaults.sync_interval_s, defaults.sync_timeout_s, defaults.cache_ttl_s) == (
        300.0,
        20.0,
        2.0,
    )

    config = tmp_path / "keystone.yaml"
    config.write_text("registry:\n  sync_interval_s: 60\n  cache_ttl_s: 1\n")
    monkeypatch.setenv("KEYSTONE_CONFIG", str(config))
    monkeypatch.setenv("KEYSTONE_REGISTRY__SYNC_INTERVAL_S", "5")

    registry = Settings().registry

    assert (registry.sync_interval_s, registry.cache_ttl_s, registry.sync_timeout_s) == (
        5.0,
        1.0,
        20.0,
    )


@pytest.mark.phase(2)
def test_a_misspelled_registry_key_is_an_error() -> None:
    with pytest.raises(ValueError, match="sync_inteval_s"):
        Settings(registry={"sync_inteval_s": 5})  # type: ignore[arg-type]


@pytest.mark.phase(2)
def test_tool_overrides_load_from_yaml_and_typos_fail(tmp_path: Path) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "upstreams:\n"
        "  - id: mail\n"
        "    tenant: acme\n"
        "    url: http://mail-mcp:8101/mcp\n"
        "    tools:\n"
        "      send_email: {risk: high, tags: [external_effect], extract: {to: '$.to'}}\n"
    )

    [mail] = Settings(config_path=config).upstreams

    override = mail.tools["send_email"]
    assert (override.risk, override.tags, override.extract) == (
        "high",
        ["external_effect"],
        {"to": "$.to"},
    )
    with pytest.raises(ValueError, match="risk"):
        Settings(
            upstreams=[{"id": "mail", "tools": {"x": {"risk": "severe"}}}]  # type: ignore[list-item]
        )
    with pytest.raises(ValueError, match="tool"):
        Settings(upstreams=[{"id": "mail", "tool": {}}])  # type: ignore[list-item]


@pytest.mark.phase(3)
def test_auth_none_refused_outside_dev() -> None:
    assert Settings(env="dev", auth={"mode": "none"}).auth.mode == "none"  # type: ignore[arg-type]
    assert Settings(env="test", auth={"mode": "none"}).auth.mode == "none"  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"auth\.mode"):
        Settings(env="prod", auth={"mode": "none"})  # type: ignore[arg-type]


@pytest.mark.phase(3)
def test_auth_none_is_refused_in_prod_when_it_comes_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEYSTONE_ENV", "prod")
    monkeypatch.setenv("KEYSTONE_AUTH__MODE", "none")

    with pytest.raises(ValueError, match=r"auth\.mode"):
        Settings()


@pytest.mark.phase(3)
@pytest.mark.parametrize("env", ["dev", "test", "prod"])
def test_authentication_is_on_by_default_and_there_is_no_dev_principal(env: str) -> None:
    settings = Settings(env=env)  # type: ignore[arg-type]

    assert settings.auth.mode == "oidc"
    assert settings.dev_principal is None


@pytest.mark.phase(3)
def test_a_dev_principal_needs_authentication_to_be_off() -> None:
    principal = {"tenant_id": "acme", "user_id": "x", "agent_id": "y"}

    with pytest.raises(ValueError, match="dev_principal"):
        Settings(env="dev", dev_principal=principal)  # type: ignore[arg-type]
    chosen = Settings(env="dev", auth={"mode": "none"}, dev_principal=principal)  # type: ignore[arg-type]
    assert chosen.dev_principal is not None and chosen.dev_principal.user_id == "x"


@pytest.mark.phase(3)
def test_oidc_settings_have_defaults_and_come_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    defaults = Settings()
    assert (defaults.oidc_issuer, defaults.oidc_discovery_url, defaults.public_base_url) == (
        None,
        None,
        None,
    )
    assert defaults.oidc_audience == "keystone"

    monkeypatch.setenv("KEYSTONE_OIDC_ISSUER", "http://localhost:8180/realms/keystone")
    monkeypatch.setenv(
        "KEYSTONE_OIDC_DISCOVERY_URL",
        "http://keycloak:8080/realms/keystone/.well-known/openid-configuration",
    )
    monkeypatch.setenv("KEYSTONE_OIDC_AUDIENCE", "gateway")
    monkeypatch.setenv("KEYSTONE_PUBLIC_BASE_URL", "https://keystone.example.test/")

    settings = Settings()

    assert settings.oidc_issuer == "http://localhost:8180/realms/keystone"
    assert (settings.oidc_discovery_url or "").startswith("http://keycloak:8080/")
    assert settings.oidc_audience == "gateway"
    assert settings.public_base_url == "https://keystone.example.test"  # no trailing slash


@pytest.mark.phase(3)
@pytest.mark.parametrize("field", ["oidc_issuer", "oidc_discovery_url", "public_base_url"])
@pytest.mark.parametrize("value", ["localhost:8180", "ftp://idp.test/realm", "http://", "/realm"])
def test_urls_must_be_http_or_https(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        Settings(**{field: value})  # type: ignore[arg-type]


@pytest.mark.phase(3)
def test_master_keys_are_a_secret_that_settings_never_print(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = "FpAPqO9j92_C-qEbO6vqkdH2olOR4ZHKzRqM7OhjSE0="
    assert Settings().master_keys is None

    monkeypatch.setenv("KEYSTONE_MASTER_KEYS", f"{key},another")
    settings = Settings()

    assert settings.master_keys is not None
    assert settings.master_keys.get_secret_value() == f"{key},another"
    assert key not in repr(settings) and key not in settings.model_dump_json()


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    ("env", "configured", "expected"),
    [
        ("dev", None, False),
        ("test", None, True),
        ("prod", None, True),
        ("dev", True, True),
        ("prod", False, False),
    ],
)
def test_the_audit_log_fails_closed_unless_env_is_dev(
    env: str, configured: bool | None, expected: bool
) -> None:
    from keystone.settings import AuditSettings

    settings = Settings(env=env, audit=AuditSettings(fail_closed=configured))  # type: ignore[arg-type]

    assert settings.audit_fail_closed is expected


@pytest.mark.phase(5)
def test_audit_fail_closed_comes_from_the_environment_and_the_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("audit:\n  fail_closed: false\n")

    assert Settings(env="prod", config_path=config).audit_fail_closed is False

    monkeypatch.setenv("KEYSTONE_AUDIT__FAIL_CLOSED", "true")
    assert Settings(env="dev", config_path=config).audit_fail_closed is True


@pytest.mark.phase(5)
def test_the_otlp_endpoint_is_off_by_default_and_must_be_a_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Settings().otlp_endpoint is None
    monkeypatch.setenv("KEYSTONE_OTLP_ENDPOINT", "http://jaeger:4318")
    assert Settings().otlp_endpoint == "http://jaeger:4318"
    monkeypatch.setenv("KEYSTONE_OTLP_ENDPOINT", "jaeger:4318")
    with pytest.raises(ValueError, match="otlp_endpoint"):
        Settings()
