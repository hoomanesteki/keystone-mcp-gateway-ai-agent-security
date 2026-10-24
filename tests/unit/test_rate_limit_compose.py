"""KS-804 in the compose files: limits that the smoke scripts and the browser test never meet."""

from pathlib import Path

import pytest
import yaml

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
