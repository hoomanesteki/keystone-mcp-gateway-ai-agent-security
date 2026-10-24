"""KS-804 to KS-806 in the compose files: the limits that the smokes and the browser test never
meet, and the fake model API that the LLM proxy is pointed at."""

from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from keystone.metering.pricing import PriceList
from keystone.settings import Settings

pytestmark = pytest.mark.phase(8)

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
CONFIG = yaml.safe_load((ROOT / "deploy" / "keystone.compose.yaml").read_text())


def test_the_compose_limits_are_set_and_generous() -> None:
    environment = COMPOSE["services"]["keystone"]["environment"]
    settings = Settings(**CONFIG, env="test")

    assert (
        settings.rate_limits.per_tenant is not None and settings.rate_limits.per_agent is not None
    )
    # The busiest script makes a few hundred calls, most of them in a minute or two. These allow
    # many times that, at once and every second.
    assert settings.rate_limits.per_tenant.capacity >= 1000
    assert settings.rate_limits.per_agent.capacity >= 500
    assert float(environment["KEYSTONE_RATE_LIMITS__PER_USER__CAPACITY"].split(":-")[1][:-1]) >= 300
    assert (
        float(environment["KEYSTONE_RATE_LIMITS__PER_USER__REFILL_PER_S"].split(":-")[1][:-1]) >= 50
    )
    # No limit on a single tool unless a deployment wants one.
    assert settings.rate_limits.per_tool is None


def test_the_smoke_can_tighten_the_limit_of_one_user_through_the_environment() -> None:
    environment = COMPOSE["services"]["keystone"]["environment"]

    assert environment["KEYSTONE_RATE_LIMITS__PER_USER__CAPACITY"].startswith(
        "${KEYSTONE_RATE_LIMIT_USER_CAPACITY:-"
    )
    assert environment["KEYSTONE_RATE_LIMITS__PER_USER__REFILL_PER_S"].startswith(
        "${KEYSTONE_RATE_LIMIT_USER_REFILL:-"
    )


def test_the_compose_budgets_are_the_ones_the_smoke_needs() -> None:
    settings = Settings(**CONFIG, env="test")

    by_scope = {(b.scope, b.scope_id): b for b in settings.budgets}
    lena = by_scope[("user", "lena")]
    assert (lena.tenant, lena.window, lena.limit_usd) == ("acme", "day", Decimal("0.03"))
    assert by_scope[("tenant", "acme")].limit_usd >= 10
    echo = next(u for u in settings.upstreams if u.id == "echostd")
    assert echo.tools["echo"].cost_per_call_usd == 0.01
    # The tools the tests of the demo upstreams read from this file stay free.
    for upstream in settings.upstreams:
        if upstream.id in ("mail", "files", "bank", "echo", "files_globex"):
            assert all(not t.cost_per_call_usd for t in upstream.tools.values()), upstream.id


def test_the_compose_llm_proxy_is_pointed_at_the_fake_service_and_its_key() -> None:
    proxy = Settings(**CONFIG, env="test").llm_proxy
    services = COMPOSE["services"]
    fake, keystone = services["fake-llm"], services["keystone"]

    assert proxy.enabled and proxy.tenant == "acme"
    # The address in the config is the service name and the port the server listens on.
    assert fake["command"][-2:] == ["--port", "8199"]
    assert proxy.anthropic.base_url == proxy.openai.base_url == "http://fake-llm:8199"
    assert fake["ports"] == ["${FAKE_LLM_PORT:-8199}:8199"]
    # The key the fake wants and the key Keystone sends are one variable with one default.
    variable = proxy.anthropic.api_key_env
    assert variable == proxy.openai.api_key_env == "FAKE_LLM_API_KEY"
    assert fake["environment"]["FAKE_LLM_API_KEY"] == keystone["environment"][variable]
    assert keystone["depends_on"]["fake-llm"] == {"condition": "service_healthy"}


def test_the_price_list_the_config_names_is_the_fake_one_that_is_mounted() -> None:
    proxy = Settings(**CONFIG, env="test").llm_proxy
    mounts = dict(
        reversed(volume.split(":")[:2]) for volume in COMPOSE["services"]["keystone"]["volumes"]
    )

    assert mounts[str(proxy.pricing_file)] == "./pricing.compose.yaml"
    prices = PriceList.load(ROOT / "deploy" / "pricing.compose.yaml")
    assert prices.match("fake-model") is not None
    assert not proxy.allow_unpriced
