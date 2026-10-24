"""KS-806 settings: what the config of the LLM proxy accepts, and what stops startup."""

from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from keystone.app import create_app
from keystone.identity.vault import VaultError
from keystone.metering.pricing import PricingError
from keystone.registry.naming import LLM_UPSTREAM_IDS, check_upstream_id, is_reserved
from keystone.settings import LlmProviderSettings, LlmProxySettings, Settings, TenantConfig

pytestmark = pytest.mark.phase(8)

IDP = "http://idp.test/realms/keystone"
# Made when the tests start and never written anywhere, like the master key of the app fixtures.
MASTER_KEY = Fernet.generate_key().decode()


def tenants(*ids: str) -> list[TenantConfig]:
    return [TenantConfig(id=i, name=i.title()) for i in ids]


def settings(*, proxy: dict[str, Any] | None = None, ids: tuple[str, ...] = ("acme",)) -> Settings:
    return Settings(
        env="test",
        oidc_issuer=IDP,
        tenants=tenants(*ids),
        llm_proxy=LlmProxySettings(**(proxy or {})),
    )


def test_the_proxy_is_off_until_the_config_turns_it_on() -> None:
    config = Settings(env="test", oidc_issuer=IDP).llm_proxy

    assert config.enabled is False and config.tenant is None
    # The addresses and key variables of the two real providers are the defaults, so that turning
    # the proxy on for a real provider needs a price list and a key and no more.
    assert config.anthropic.base_url == "https://api.anthropic.com"
    assert config.anthropic.api_key_env == "ANTHROPIC_API_KEY"
    assert config.openai.base_url == "https://api.openai.com"
    assert config.openai.api_key_env == "OPENAI_API_KEY"
    assert config.allow_unpriced is False and config.pricing_file == Path("pricing.yaml")
    assert config.timeout_s == 600


def test_the_one_tenant_of_the_config_owns_the_provider_keys_unless_another_is_named() -> None:
    only = settings(proxy={"enabled": True})
    named = settings(proxy={"enabled": True, "tenant": "globex"}, ids=("acme", "globex"))

    assert only.llm_proxy.tenant == "acme"
    assert named.llm_proxy.tenant == "globex"


def test_with_several_tenants_the_config_must_say_whose_keys_they_are() -> None:
    with pytest.raises(ValidationError, match=r"llm_proxy\.tenant must name the tenant"):
        settings(proxy={"enabled": True}, ids=("acme", "globex"))

    with pytest.raises(ValidationError, match="'nobody' is not in `tenants`"):
        settings(proxy={"enabled": True, "tenant": "nobody"})


def test_a_proxy_that_is_off_asks_nothing_of_the_tenants() -> None:
    assert settings(proxy={"tenant": "nobody"}, ids=("acme", "globex")).llm_proxy.enabled is False


@pytest.mark.parametrize(
    "url",
    ["ftp://api.example.com", "api.example.com", "https://", "https://user:pw@api.example.com"],
)
def test_a_provider_address_is_a_plain_http_or_https_url(url: str) -> None:
    with pytest.raises(ValidationError, match="base_url"):
        LlmProviderSettings(base_url=url)


def test_a_provider_address_drops_a_trailing_slash_and_keeps_its_path() -> None:
    assert LlmProviderSettings(base_url="https://gateway.example.com/openai/").base_url == (
        "https://gateway.example.com/openai"
    )
    with pytest.raises(ValidationError, match="query"):
        LlmProviderSettings(base_url="https://api.example.com/v1?key=1")


def test_a_key_comes_from_a_variable_that_is_not_keystones_own() -> None:
    assert LlmProviderSettings(base_url="http://x.test", api_key_env=None).api_key_env is None
    for name in ("two words", "9LIVES", "KEYSTONE_MASTER_KEYS", "keystone_database_url"):
        with pytest.raises(ValidationError):
            LlmProviderSettings(base_url="http://x.test", api_key_env=name)


def test_the_limits_of_a_request_are_bounded() -> None:
    options: list[dict[str, Any]] = [
        {"max_body_bytes": 10},
        {"timeout_s": 0},
        {"default_max_tokens": 0},
    ]
    for option in options:
        with pytest.raises(ValidationError):
            LlmProxySettings(**option)


def test_an_unknown_setting_is_an_error_and_not_ignored() -> None:
    with pytest.raises(ValidationError, match="extra"):
        LlmProxySettings(allow_unpriced_models=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="extra"):
        LlmProviderSettings(base_url="http://x.test", api_key="sk-oops")  # type: ignore[call-arg]


def test_the_provider_ids_cannot_be_used_for_a_tool_server() -> None:
    for upstream_id in sorted(LLM_UPSTREAM_IDS):
        assert is_reserved(upstream_id)
        with pytest.raises(ValueError, match="reserved for the provider keys"):
            check_upstream_id(upstream_id)
    # The message about Keystone's own tools stays what it was.
    with pytest.raises(ValueError, match="reserved for Keystone's own tools"):
        check_upstream_id("keystone")


def test_an_app_with_the_proxy_on_needs_the_master_key_for_the_provider_keys() -> None:
    config = settings(proxy={"enabled": True})

    with pytest.raises(VaultError, match=r"llm_proxy is enabled.*KEYSTONE_MASTER_KEYS"):
        create_app(config)


def test_an_app_with_the_proxy_on_needs_a_price_list_it_can_read(tmp_path: Path) -> None:
    config = settings(proxy={"enabled": True, "pricing_file": tmp_path / "pricing.yaml"})
    config.master_keys = SecretStr(MASTER_KEY)

    with pytest.raises(PricingError, match=r"cannot be read.*pricing\.example\.yaml"):
        create_app(config)

    (tmp_path / "pricing.yaml").write_text("models: {}\n")
    with pytest.raises(PricingError, match="lists no model"):
        create_app(config)


def test_an_app_with_the_proxy_off_has_no_routes_for_it() -> None:
    app = create_app(Settings(env="test", oidc_issuer=IDP, tenants=tenants("acme")))

    # Not entered as a context manager: that would run the lifespan, which needs the database.
    answer = TestClient(app).post("/llm/anthropic/v1/messages", json={"model": "m"})

    assert answer.status_code == 404
