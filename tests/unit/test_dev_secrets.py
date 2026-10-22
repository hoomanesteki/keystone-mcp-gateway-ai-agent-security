"""The development credentials are labeled, long enough to matter, and the same everywhere.

`.env.example` is what scripts read. `deploy/docker-compose.yml` repeats each value as the default
of a `${NAME:-default}`, so a plain `docker compose up` works without a `.env` file. These tests
fail when the two drift apart.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_TEXT = (ROOT / "deploy" / "docker-compose.yml").read_text()
COMPOSE: dict[str, Any] = yaml.safe_load(COMPOSE_TEXT)
DEFAULT = re.compile(r"\$\{([A-Z][A-Z0-9_]*):-([^}]*)\}")
SECRET_SUFFIXES = ("_PASSWORD", "_SECRET", "_API_KEY")


def env_example() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (ROOT / ".env.example").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            values[name] = value
    return values


def realm_placeholders() -> set[str]:
    text = (ROOT / "deploy" / "keycloak" / "realm-keystone.json").read_text()
    return set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", text))


@pytest.mark.phase(3)
def test_the_credentials_are_labeled_as_development_only() -> None:
    text = (ROOT / ".env.example").read_text()
    banner = text.index("DEVELOPMENT ONLY")

    for name in env_example():
        if name.endswith(SECRET_SUFFIXES) or name == "KEYSTONE_MASTER_KEYS":
            assert text.index(f"\n{name}=") > banner, f"{name} is above the development-only note"


@pytest.mark.phase(3)
def test_compose_defaults_equal_the_values_in_env_example() -> None:
    example = env_example()
    seen: dict[str, set[str]] = {}
    for name, default in DEFAULT.findall(COMPOSE_TEXT):
        seen.setdefault(name, set()).add(default)

    shared = set(seen) & set(example)
    assert {"KEYCLOAK_PORT", "ALICE_PASSWORD", "SUPPORT_AGENT_SECRET"} <= shared
    for name in sorted(shared):
        assert seen[name] == {example[name]}, f"{name}: compose and .env.example disagree"


@pytest.mark.phase(3)
def test_every_realm_placeholder_has_a_value_and_reaches_keycloak() -> None:
    example = env_example()
    environment = COMPOSE["services"]["keycloak"]["environment"]

    for name in sorted(realm_placeholders()):
        assert example.get(name), f"{name} is not in .env.example"
        assert environment.get(name, "").startswith(f"${{{name}:-"), f"{name} is not passed on"


@pytest.mark.phase(3)
def test_development_secrets_are_long_enough_for_the_log_scrubber() -> None:
    # The scrubber ignores values shorter than 8 characters, so a short key would leak.
    for name, value in env_example().items():
        if name.endswith(SECRET_SUFFIXES):
            assert len(value) >= 8, name


@pytest.mark.phase(3)
def test_the_dev_master_key_is_a_valid_fernet_key() -> None:
    keys = env_example()["KEYSTONE_MASTER_KEYS"].split(",")

    assert keys
    for key in keys:
        Fernet(key.encode())


@pytest.mark.phase(3)
def test_keycloak_state_is_not_kept_in_a_volume() -> None:
    # Realm import only runs when the realm does not exist. Because the dev database lives in
    # the container, `make reset` (and `make down`) discard it and the next `make up` imports
    # the edited file. A named volume would keep the old realm.
    keycloak = COMPOSE["services"]["keycloak"]

    assert keycloak["volumes"] == ["./keycloak:/opt/keycloak/data/import:ro"]
    assert not any("keycloak" in name for name in COMPOSE.get("volumes", {}))


@pytest.mark.phase(3)
def test_keycloak_issues_one_issuer_for_every_address() -> None:
    environment = COMPOSE["services"]["keycloak"]["environment"]

    assert environment["KC_HOSTNAME"] == "http://localhost:${KEYCLOAK_PORT:-8180}"
    assert environment["KC_HOSTNAME_BACKCHANNEL_DYNAMIC"] == "true"
    ports = COMPOSE["services"]["keycloak"]["ports"]
    assert ports == ["${KEYCLOAK_PORT:-8180}:8080"], json.dumps(ports)
