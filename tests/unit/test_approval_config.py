"""KS-604: what stops Keystone from starting with approval notifications that cannot work."""

from collections.abc import Mapping

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from keystone.app import create_app
from keystone.approvals.notifier import WEBHOOK_SECRET_ENV, ApprovalConfigError
from keystone.settings import ApprovalSettings, Settings

pytestmark = pytest.mark.phase(6)

ISSUER = "http://idp.test/realms/keystone"
HOOK = "https://hooks.example.test/keystone"
SECRET = "webhook-secret-for-the-test"


def settings(**approvals: object) -> Settings:
    return Settings(
        env="test",
        oidc_issuer=ISSUER,
        master_keys=SecretStr(Fernet.generate_key().decode()),
        approvals=ApprovalSettings.model_validate(approvals),
    )


def build(configured: Settings, environ: Mapping[str, str]) -> object:
    return create_app(configured, environ=environ)


def test_a_webhook_without_its_secret_in_the_environment_stops_startup() -> None:
    with pytest.raises(ApprovalConfigError, match=WEBHOOK_SECRET_ENV):
        build(settings(webhook_url=HOOK), {})
    with pytest.raises(ApprovalConfigError, match=WEBHOOK_SECRET_ENV):
        build(settings(webhook_url=HOOK), {WEBHOOK_SECRET_ENV: ""})


def test_a_webhook_with_its_secret_in_the_environment_starts() -> None:
    app = build(settings(webhook_url=HOOK), {WEBHOOK_SECRET_ENV: SECRET})

    assert app is not None


def test_a_slack_address_alone_starts_and_needs_no_secret() -> None:
    assert build(settings(slack_webhook_url="https://hooks.slack.test/services/x"), {}) is not None


def test_notifications_without_master_keys_stop_startup() -> None:
    without_keys = Settings(
        env="test",
        oidc_issuer=ISSUER,
        approvals=ApprovalSettings(webhook_url=HOOK),
    )

    with pytest.raises(ApprovalConfigError, match="KEYSTONE_MASTER_KEYS"):
        build(without_keys, {WEBHOOK_SECRET_ENV: SECRET})


def test_nothing_configured_means_no_notifier() -> None:
    app = create_app(settings(), environ={})

    assert app.state.approvals is not None  # the service exists, with the master keys


def test_the_test_client_waits_longer_than_the_app_holds_a_call() -> None:
    from types import SimpleNamespace

    from tests.fixtures.keystone import PATIENCE_S, hold_time

    configured = Settings(env="test", approvals=ApprovalSettings(wait_seconds=42))
    app = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=configured)))

    assert hold_time(app) == 42
    assert PATIENCE_S + hold_time(app) > 42
    assert hold_time(object()) == 0  # not a Keystone app: nothing is held
