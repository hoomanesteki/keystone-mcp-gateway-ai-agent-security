from pathlib import Path
from typing import Any

import pytest
import yaml

from keystone.settings import Settings

pytestmark = pytest.mark.usefixtures("clean_env")

ROOT = Path(__file__).resolve().parents[2]


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


@pytest.mark.phase(9)
def test_the_yaml_can_come_as_text_in_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # What the ECS task gets: the file's text as a secret environment variable, no file.
    monkeypatch.setenv(
        "KEYSTONE_CONFIG_YAML",
        "log_level: debug\n"
        "env: test\n"
        "upstreams:\n"
        "  - {id: mail, tenant: acme, url: 'http://mail-mcp:8101/mcp'}\n",
    )
    monkeypatch.setenv("KEYSTONE_LOG_LEVEL", "warning")

    settings = Settings()

    assert settings.env == "test"
    assert settings.log_level == "WARNING", "the environment still wins over the YAML"
    assert [(u.id, u.url) for u in settings.upstreams] == [("mail", "http://mail-mcp:8101/mcp")]
    assert settings.config_path is None


@pytest.mark.phase(9)
def test_an_empty_inline_yaml_is_the_same_as_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_CONFIG_YAML", "")

    assert Settings().upstreams == []


@pytest.mark.phase(9)
def test_inline_yaml_must_be_a_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_CONFIG_YAML", "- mail\n- files\n")

    with pytest.raises(ValueError, match="YAML mapping"):
        Settings()


@pytest.mark.phase(9)
def test_a_file_and_inline_yaml_together_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("env: test\n")
    monkeypatch.setenv("KEYSTONE_CONFIG", str(config))
    monkeypatch.setenv("KEYSTONE_CONFIG_YAML", "env: dev\n")

    with pytest.raises(ValueError, match="not both"):
        Settings()

    # An explicit path is a choice of the caller (the tests make it), and stands.
    assert Settings(config_path=config).env == "test"


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


def classifications(path: Path) -> dict[str, dict[str, Any]]:
    """Upstream id -> tool name -> its risk and tags. A price or an extractor is not a
    classification: the example prices a tool to show the shape, and compose does not."""
    config = yaml.safe_load(path.read_text())
    return {
        entry["id"]: {
            name: {key: override.get(key) for key in ("risk", "tags")}
            for name, override in entry.get("tools", {}).items()
        }
        for entry in config["upstreams"]
    }


@pytest.mark.phase(4)
def test_the_example_config_classifies_every_tool_the_compose_config_does() -> None:
    """The example is what a deployment copies, and it points at the same demo servers as the
    compose stack. A tool it leaves out is medium risk with no tags: anyone may call it and the
    Rule of Two never sees it, where the compose config tags it. The two must not decide the same
    call differently."""
    example = classifications(ROOT / "keystone.example.yaml")
    compose = classifications(ROOT / "deploy" / "keystone.compose.yaml")

    for upstream_id, tools in compose.items():
        for name, classified in tools.items():
            if upstream_id in example:
                assert example[upstream_id].get(name) == classified, (upstream_id, name)
    # Globex's drive is the same server as acme's, so its tools are what acme's are.
    assert example["files_globex"] == example["files"] != {}


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
def test_the_key_set_max_age_defaults_to_ten_minutes_and_must_be_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Settings().oidc_jwks_max_age_s == 600.0

    monkeypatch.setenv("KEYSTONE_OIDC_JWKS_MAX_AGE_S", "90")
    assert Settings().oidc_jwks_max_age_s == 90.0
    with pytest.raises(ValueError):
        Settings(oidc_jwks_max_age_s=0)


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


@pytest.mark.phase(5)
def test_the_console_origin_defaults_to_the_dev_console_and_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Settings().console_origin == "http://localhost:5173"
    monkeypatch.setenv("KEYSTONE_CONSOLE_ORIGIN", "https://console.example/")
    assert Settings().console_origin == "https://console.example"
    monkeypatch.setenv("KEYSTONE_CONSOLE_ORIGIN", "https://console.example:8443")
    assert Settings().console_origin == "https://console.example:8443"


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "value",
    [
        "localhost:5173",
        "ftp://console.example",
        "https://console.example/app",
        "https://user:pw@console.example",
        "https://console.example?x=1",
        "https://console.example#top",
        "*",
        "",
    ],
)
def test_the_console_origin_must_be_an_origin(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_CONSOLE_ORIGIN", value)

    with pytest.raises(ValueError, match="console_origin"):
        Settings()


@pytest.mark.phase(6)
def test_approval_settings_have_defaults_and_come_from_env_or_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    defaults = Settings().approvals
    assert (defaults.wait_seconds, defaults.ttl_seconds) == (60, 900)
    assert (defaults.sweep_interval_s, defaults.poll_interval_s) == (30, 2)

    config = tmp_path / "keystone.yaml"
    config.write_text("approvals:\n  wait_seconds: 20\n  ttl_seconds: 600\n")
    assert Settings(config_path=config).approvals.wait_seconds == 20

    monkeypatch.setenv("KEYSTONE_APPROVALS__WAIT_SECONDS", "1.5")
    monkeypatch.setenv("KEYSTONE_APPROVALS__SWEEP_INTERVAL_S", "0.25")
    settings = Settings(config_path=config)
    assert (settings.approvals.wait_seconds, settings.approvals.ttl_seconds) == (1.5, 600)
    assert settings.approvals.sweep_interval_s == 0.25


@pytest.mark.phase(6)
@pytest.mark.parametrize(
    "bad",
    [
        {"wait_seconds": -1},
        {"wait_seconds": 301},
        {"ttl_seconds": 0},
        {"sweep_interval_s": 0},
        {"poll_interval_s": 0},
        {"wait_secnods": 5},  # a misspelled key must fail, not quietly do nothing
    ],
)
def test_approval_settings_are_checked(bad: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="approvals"):
        Settings(approvals=bad)  # type: ignore[arg-type]


@pytest.mark.phase(6)
def test_the_config_cannot_define_an_upstream_called_keystone(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="reserved"):
        Settings(upstreams=[{"id": "keystone", "tenant": "acme"}])  # type: ignore[list-item]

    config = tmp_path / "keystone.yaml"
    config.write_text(
        "upstreams:\n  - {id: keystone, tenant: acme, transport: http, url: 'http://x.test/mcp'}\n"
    )
    with pytest.raises(ValueError, match="reserved"):
        Settings(config_path=config)


@pytest.mark.phase(6)
def test_the_webhook_settings_are_checked_and_the_slack_address_is_a_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from keystone.settings import ApprovalSettings

    defaults = ApprovalSettings()
    assert (defaults.webhook_url, defaults.slack_webhook_url) == (None, None)
    assert defaults.webhook_backoff_s == [1.0, 2.0, 4.0]

    slack = "https://hooks.slack.test/services/T000/B000/not-for-display"
    monkeypatch.setenv("KEYSTONE_APPROVALS__WEBHOOK_URL", "https://hooks.example.test/keystone")
    monkeypatch.setenv("KEYSTONE_APPROVALS__SLACK_WEBHOOK_URL", slack)
    settings = Settings()

    assert settings.approvals.webhook_url == "https://hooks.example.test/keystone"
    assert settings.approvals.slack_webhook_url is not None
    assert settings.approvals.slack_webhook_url.get_secret_value() == slack
    assert "not-for-display" not in repr(settings) + settings.model_dump_json()


@pytest.mark.phase(6)
@pytest.mark.parametrize(
    "bad",
    [
        {"webhook_url": "hooks.example.test/keystone"},
        {"webhook_url": "ftp://hooks.example.test/keystone"},
        {"slack_webhook_url": "not a url"},
        {"webhook_backoff_s": [1, -1]},
        {"webhook_backoff_s": [301]},
        {"webhook_backoff_s": [1] * 11},
    ],
)
def test_a_webhook_setting_that_cannot_work_is_refused(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="approvals"):
        Settings(approvals=bad)  # type: ignore[arg-type]


@pytest.mark.phase(6)
def test_a_secret_put_in_the_yaml_is_refused_and_not_repeated(tmp_path: Path) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text("approvals:\n  webhook_secret: a-secret-that-must-not-be-echoed\n")

    with pytest.raises(ValueError) as refused:
        Settings(config_path=config)

    assert "webhook_secret" in str(refused.value)
    assert "must-not-be-echoed" not in str(refused.value)
