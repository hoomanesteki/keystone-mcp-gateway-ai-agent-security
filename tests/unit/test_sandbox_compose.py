"""KS-801 and KS-802 in the compose files: the socket, the image and the upstream."""

from pathlib import Path

import pytest
import yaml

from keystone.sandbox.builtin_upstream import sandbox_registered
from keystone.settings import Settings

pytestmark = pytest.mark.phase(8)

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "deploy" / "docker-compose.yml"
COMPOSE = yaml.safe_load(COMPOSE_FILE.read_text())
SOCKET = "/var/run/docker.sock:/var/run/docker.sock"


def test_keystone_gets_the_docker_socket_and_the_comment_says_where_that_is_acceptable() -> None:
    keystone = COMPOSE["services"]["keystone"]

    assert SOCKET in keystone["volumes"]
    # The socket is root on the host. The comment next to it says so, and says where it is fine.
    lines = COMPOSE_FILE.read_text().splitlines()
    at = next(i for i, line in enumerate(lines) if SOCKET in line)
    nearby = " ".join(lines[max(0, at - 8) : at]).lower()
    assert "local and single-host use only" in nearby
    assert "root" in nearby


def test_the_socket_is_the_only_thing_of_the_host_that_keystone_gets_to_write() -> None:
    keystone = COMPOSE["services"]["keystone"]

    mounts = {volume.split(":")[0] for volume in keystone["volumes"]}
    # The config and the policies are read-only; no directory of the host is mounted to write to.
    assert mounts == {"./keystone.compose.yaml", "../policies", "/var/run/docker.sock"}
    for volume in keystone["volumes"]:
        if volume != SOCKET:
            assert volume.endswith(":ro"), volume


def test_keystone_runs_as_itself_and_joins_the_group_of_the_socket() -> None:
    keystone = COMPOSE["services"]["keystone"]

    assert "user" not in keystone and not keystone.get("privileged")
    assert keystone["group_add"] == ["${DOCKER_SOCKET_GID:-0}"]


def test_the_image_is_built_by_a_service_that_has_nothing_to_do_but_exit() -> None:
    image = COMPOSE["services"]["sandbox-image"]

    assert image["image"] == "keystone-sandbox-python:dev"
    assert image["build"]["dockerfile"] == "Dockerfile.python"
    assert image["network_mode"] == "none" and image["read_only"] is True
    assert image["restart"] == "no"
    depends = COMPOSE["services"]["keystone"]["depends_on"]
    assert depends["sandbox-image"] == {"condition": "service_completed_successfully"}


def test_the_switch_is_passed_to_keystone_and_defaults_to_on() -> None:
    environment = COMPOSE["services"]["keystone"]["environment"]

    assert environment["KEYSTONE_SANDBOX_ENABLED"] == "${KEYSTONE_SANDBOX_ENABLED:-true}"


def test_the_compose_config_registers_the_sandbox_for_acme() -> None:
    config = yaml.safe_load((ROOT / "deploy" / "keystone.compose.yaml").read_text())

    settings = Settings(**config, env="test")

    [sandbox] = [u for u in settings.upstreams if u.id == "sandbox"]
    assert (sandbox.tenant, sandbox.transport) == ("acme", "builtin")
    assert sandbox_registered(settings) is True
    assert sandbox_registered(Settings(**config, env="test", sandbox_enabled=False)) is False


def test_the_sandbox_image_is_not_the_keystone_image_and_has_its_own_user() -> None:
    dockerfile = (ROOT / "deploy" / "sandbox" / "Dockerfile.python").read_text()

    assert "FROM python:3.12.15-slim-trixie" in dockerfile
    assert "numpy==" in dockerfile and "pandas==" in dockerfile
    assert "--no-cache-dir" in dockerfile and "rm -rf /var/lib/apt/lists" in dockerfile
    assert "USER 10001:10001" in dockerfile
    # Nothing of Keystone goes into the image that runs strangers' code.
    assert "COPY" not in dockerfile
