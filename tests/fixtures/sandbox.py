"""A Docker client, the sandbox image and a runner, for the tests marked `docker` (KS-801).

These tests need a daemon and the image from `deploy/sandbox/Dockerfile.python` (`make
sandbox-image` builds it). Without them a test is skipped and says why, so that a laptop without
Docker can still run the suite. CI and `make gate` set KEYSTONE_REQUIRE_DOCKER=1, and then a missing
daemon or image fails the test: a skip there would be a gate that passed without running the
sandbox.
"""

import contextlib
import os
import time
from collections.abc import Callable, Iterator
from typing import Any, NoReturn

import docker
import pytest
from docker.errors import DockerException, ImageNotFound

from keystone.sandbox.runner import CALL_LABEL, SANDBOX_LABEL, SandboxRunner

# The label `docker run` puts on a containerized stdio server (gateway/upstreams.py).
CONTAINER_LABEL = "keystone.container_stdio"

IMAGE = os.environ.get("KEYSTONE_SANDBOX_IMAGE", "keystone-sandbox-python:dev")
# The demo echo and probe servers as a stdio image (examples/upstreams/Dockerfile.echo, KS-803).
ECHO_IMAGE = "keystone-echo-stdio:dev"


def docker_required() -> bool:
    return os.environ.get("KEYSTONE_REQUIRE_DOCKER") == "1"


def unavailable(reason: str) -> NoReturn:
    """Skip the test, or fail it where Docker is promised."""
    if docker_required():
        pytest.fail(f"{reason} (KEYSTONE_REQUIRE_DOCKER=1)")
    pytest.skip(reason)


@pytest.fixture(scope="session")
def docker_client() -> Any:
    try:
        client = docker.from_env(timeout=30)
        client.ping()
    except (DockerException, OSError) as error:
        unavailable(f"no Docker daemon to talk to ({type(error).__name__})")
    return client


@pytest.fixture(scope="session")
def sandbox_image(docker_client: Any) -> str:
    try:
        docker_client.images.get(IMAGE)
    except ImageNotFound:
        unavailable(f"the sandbox image {IMAGE} is not built; run `make sandbox-image`")
    return IMAGE


@pytest.fixture(scope="session")
def echo_image(docker_client: Any) -> str:
    try:
        docker_client.images.get(ECHO_IMAGE)
    except ImageNotFound:
        unavailable(f"the image {ECHO_IMAGE} is not built; run `make echo-image`")
    return ECHO_IMAGE


@pytest.fixture
def runner(docker_client: Any, sandbox_image: str) -> SandboxRunner:
    return SandboxRunner(docker_client)


@pytest.fixture(autouse=True)
def _no_sandbox_container_is_left(request: pytest.FixtureRequest) -> Iterator[None]:
    """A test that used Docker leaves no container of Keystone's behind, even when it failed."""
    yield
    if "docker_client" not in request.fixturenames:
        return
    client = request.getfixturevalue("docker_client")
    for label in (SANDBOX_LABEL, CONTAINER_LABEL):
        for container in client.containers.list(all=True, filters={"label": f"{label}=1"}):
            with contextlib.suppress(DockerException):
                container.remove(force=True, v=True)


def containers_of(client: Any, call_id: str) -> list[Any]:
    """Every container, running or not, that carries this call id."""
    labelled = {"label": f"{CALL_LABEL}={call_id}"}
    found: list[Any] = client.containers.list(all=True, filters=labelled)
    return found


def wait_until(condition: Callable[[], Any], seconds: float = 15.0) -> Any:
    """The first truthy value `condition` returns within `seconds`, or None."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.05)
    return None
