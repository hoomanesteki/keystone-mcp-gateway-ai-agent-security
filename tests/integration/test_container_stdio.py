"""KS-803: a stdio MCP server that runs in a container, through the running gateway.

Keystone starts it with `docker run -i` (no network, a read-only root, no capabilities, 256 MB, 64
processes, user 10001) and talks to it over the pipe. They need the image from
examples/upstreams/Dockerfile.echo (`make echo-image`).
"""

from collections.abc import Callable
from typing import Any

import anyio
import httpx2
import pytest

from keystone.registry.config import UpstreamConfig
from keystone.settings import RegistrySettings
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.sandbox import CONTAINER_LABEL, list_containers, wait_until

pytestmark = [pytest.mark.phase(8), pytest.mark.services, pytest.mark.docker]

Factory = Callable[..., KeystoneApp]
API = "/admin/api/v1"
MEBIBYTE = 1024 * 1024
PROBE = ["python", "-m", "examples.upstreams.probe_server", "--transport", "stdio"]


def container_upstream(image: str, name: str = "echoc", **options: Any) -> UpstreamConfig:
    return UpstreamConfig(
        id=name, tenant="acme", transport="container_stdio", image=image, **options
    )


def running(docker_client: Any) -> list[Any]:
    return list_containers(docker_client, f"{CONTAINER_LABEL}=1")


async def test_container_stdio_list_and_call(
    keystone_app_factory: Factory, mcp_client: McpConnect, echo_image: str
) -> None:
    app = keystone_app_factory(
        registry=RegistrySettings(cache_ttl_s=0),
        settings={"upstreams": [container_upstream(echo_image)]},
    )

    async with mcp_client(app) as client:
        listed = {t.name for t in (await client.list_tools()).tools}
        answer = await client.call_tool("echoc__echo", {"payload": "from a container"})

    assert {"echoc__echo", "echoc__sleep", "echoc__fail"} <= listed
    assert answer.is_error is False
    assert texts(answer) == ["from a container"]
    app.audit.wait()
    record = next(r for r in app.audit.records if r["tool_name"] == "echoc__echo")
    assert (record["outcome"], record["dispatched"]) == ("ok", True)


async def test_container_stdio_has_no_network(
    keystone_app_factory: Factory, mcp_client: McpConnect, echo_image: str
) -> None:
    app = keystone_app_factory(
        settings={"upstreams": [container_upstream(echo_image, "probe", command=PROBE)]},
    )

    async with mcp_client(app) as client:
        answer = await client.call_tool("probe__connect", {"host": "1.1.1.1", "port": 80})
        lookup = await client.call_tool("probe__connect", {"host": "example.com", "port": 80})

    assert "cannot connect to 1.1.1.1:80" in texts(answer)[0]
    assert "Network is unreachable" in texts(answer)[0]
    assert "cannot connect to example.com:80" in texts(lookup)[0]


async def test_the_container_has_every_flag_of_the_plan(
    keystone_app_factory: Factory, echo_image: str, docker_client: Any
) -> None:
    keystone_app_factory(settings={"upstreams": [container_upstream(echo_image)]})

    found = await anyio.to_thread.run_sync(lambda: wait_until(lambda: running(docker_client)))

    assert found, "the container never appeared"
    [container] = found
    info = docker_client.api.inspect_container(container.id)
    host, config = info["HostConfig"], info["Config"]
    assert host["NetworkMode"] == "none"
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges"]
    assert (host["Memory"], host["MemorySwap"]) == (256 * MEBIBYTE, 256 * MEBIBYTE)
    assert host["PidsLimit"] == 64
    assert config["User"] == "10001"
    assert config["Labels"][CONTAINER_LABEL] == "1"
    assert host["Privileged"] is False
    assert host["AutoRemove"] is True  # --rm
    assert not [m for m in info["Mounts"] if m["Type"] != "tmpfs"]
    assert config["Image"] == echo_image


async def test_a_bridge_network_is_given_only_when_the_config_says_so(
    keystone_app_factory: Factory, echo_image: str, docker_client: Any
) -> None:
    keystone_app_factory(settings={"upstreams": [container_upstream(echo_image, network="bridge")]})

    found = await anyio.to_thread.run_sync(lambda: wait_until(lambda: running(docker_client)))

    assert found
    assert docker_client.api.inspect_container(found[0].id)["HostConfig"]["NetworkMode"] == "bridge"


async def test_the_container_gets_the_configured_environment_and_none_of_keystones(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    echo_image: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEYSTONE_MASTER_KEYS_IN_THE_PARENT", "must-not-arrive")
    app = keystone_app_factory(
        settings={
            "upstreams": [
                container_upstream(echo_image, "probe", command=PROBE, env={"GREETING": "hello"})
            ]
        },
    )

    async with mcp_client(app) as client:
        names = texts(await client.call_tool("probe__environment", {}))[0].split(",")
        greeting = texts(await client.call_tool("probe__environment", {"name": "GREETING"}))[0]

    assert greeting == "hello"
    assert "GREETING" in names
    assert not [n for n in names if n.startswith(("KEYSTONE", "DOCKER"))]


async def test_the_container_is_removed_when_keystone_stops(
    keystone_app_factory: Factory, echo_image: str, docker_client: Any
) -> None:
    app = keystone_app_factory(settings={"upstreams": [container_upstream(echo_image)]})
    appeared = await anyio.to_thread.run_sync(lambda: wait_until(lambda: running(docker_client)))
    assert appeared

    app.thread.stop()

    gone = await anyio.to_thread.run_sync(
        lambda: wait_until(lambda: not running(docker_client), 30)
    )
    assert gone, "the container is still running after Keystone stopped"


async def test_an_image_that_is_not_built_is_an_upstream_that_failed_to_sync(
    keystone_app_factory: Factory, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(
        settings={"upstreams": [container_upstream("keystone-no-such-image:0")]},
    )

    response = httpx2.get(
        f"{app.base}{API}/upstreams",
        headers={"Authorization": f"Bearer {fake_idp.token_for('root')}"},
        timeout=15,
    )

    [upstream] = response.json()
    assert upstream["transport"] == "container_stdio"
    assert upstream["target"] == "image keystone-no-such-image:0"
    assert upstream["last_error"]
    assert "keystone-no-such-image" not in upstream["last_error"]
