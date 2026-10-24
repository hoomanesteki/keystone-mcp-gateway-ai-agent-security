"""KS-803 without Docker: how a containerized stdio upstream is configured and how its `docker run`
is written."""

from pathlib import Path
from typing import Any, cast

import anyio
import pytest

from keystone.gateway.upstreams import (
    StdioUpstreamClient,
    UpstreamDirectory,
    UpstreamTarget,
    container_command,
    container_environment,
    directory_client_factory,
)
from keystone.registry.config import (
    ConfigError,
    UpstreamConfig,
    apply_config_upstreams,
    container_networks,
    stdio_environments,
)
from keystone.settings import Settings

pytestmark = pytest.mark.phase(8)


def flags(argv: list[str]) -> dict[str, str | None]:
    """The options of a docker run, as {flag: value}, up to the image."""
    found: dict[str, str | None] = {}
    index = 2  # after "docker run"
    while index < len(argv) and argv[index].startswith("-"):
        flag = argv[index]
        takes_value = flag not in ("--rm", "-i", "--read-only")
        found[flag] = argv[index + 1] if takes_value else None
        index += 2 if takes_value else 1
    return found


def test_the_command_carries_every_flag_of_the_plan() -> None:
    argv = container_command("keystone-echo-stdio:dev", ["python", "-m", "srv"], [], "none")

    assert argv[:2] == ["docker", "run"]
    assert flags(argv) == {
        "--rm": None,
        "-i": None,
        "--pull": "never",
        "--network": "none",
        "--read-only": None,
        "--cap-drop": "ALL",
        "--security-opt": "no-new-privileges",
        "--memory": "256m",
        "--memory-swap": "256m",
        "--pids-limit": "64",
        "--user": "10001",
        "--label": "keystone.container_stdio=1",
    }
    assert argv[-4:] == ["keystone-echo-stdio:dev", "python", "-m", "srv"]


def test_the_environment_goes_in_by_name_and_its_values_stay_off_the_command_line() -> None:
    argv = container_command("img:1", ["srv"], ["B_NAME", "A_NAME"], "none")

    assert argv[argv.index("-e") :][:4] == ["-e", "A_NAME", "-e", "B_NAME"]
    assert "s3cret" not in " ".join(argv)


def test_a_bridge_network_is_only_what_the_config_asked_for() -> None:
    assert flags(container_command("img:1", [], [], "bridge"))["--network"] == "bridge"
    assert flags(container_command("img:1", [], [], "none"))["--network"] == "none"


def test_a_server_with_no_command_runs_the_image_as_it_is() -> None:
    assert container_command("img:1", [], [], "none")[-1] == "img:1"


def test_nothing_of_keystones_environment_reaches_docker_but_the_daemon_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEYSTONE_MASTER_KEYS", "k")
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    assert container_environment({"TOKEN": "t"}) == {"TOKEN": "t"}

    monkeypatch.setenv("DOCKER_HOST", "tcp://docker.test:2375")
    assert container_environment({"TOKEN": "t"}) == {
        "TOKEN": "t",
        "DOCKER_HOST": "tcp://docker.test:2375",
    }


async def test_the_factory_makes_a_stdio_client_that_runs_docker() -> None:
    directory = UpstreamDirectory()
    directory.update(
        {
            "echoc": UpstreamTarget(
                transport="container_stdio",
                command=("python", "-m", "srv"),
                image="keystone-echo-stdio:dev",
                env=(("GREETING", "hi"),),
                network="bridge",
            )
        }
    )
    factory = directory_client_factory(directory)

    async with anyio.create_task_group() as group:
        client = factory("echoc", {}, group)
        assert isinstance(client, StdioUpstreamClient)
        argv = list(client.command)
        group.cancel_scope.cancel()

    assert argv[:2] == ["docker", "run"]
    assert flags(argv)["--network"] == "bridge"
    assert "GREETING" in argv and "hi" not in argv
    assert argv[-4:] == ["keystone-echo-stdio:dev", "python", "-m", "srv"]


async def test_a_container_target_without_an_image_is_not_served() -> None:
    directory = UpstreamDirectory()
    directory.update({"echoc": UpstreamTarget(transport="container_stdio")})
    factory = directory_client_factory(directory)

    async with anyio.create_task_group() as group:
        with pytest.raises(ValueError, match="not served"):
            factory("echoc", {}, group)
        group.cancel_scope.cancel()


def test_a_containerized_upstream_loads_from_yaml(tmp_path: Path) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "upstreams:\n"
        "  - id: echoc\n"
        "    tenant: acme\n"
        "    transport: container_stdio\n"
        "    image: keystone-echo-stdio:dev\n"
        "    command: [python, -m, examples.upstreams.echo_server, --transport, stdio]\n"
        "    env: {ECHO_POISONED: '0'}\n"
        "    network: bridge\n"
        "  - {id: quiet, tenant: acme, transport: container_stdio, image: 'img:1'}\n"
    )

    settings = Settings(config_path=config)

    [echo, quiet] = settings.upstreams
    assert (echo.transport, echo.image, echo.network) == (
        "container_stdio",
        "keystone-echo-stdio:dev",
        "bridge",
    )
    assert (quiet.network, quiet.command) == ("none", None)
    assert stdio_environments(settings.upstreams) == {"echoc": {"ECHO_POISONED": "0"}}
    assert container_networks(settings.upstreams) == {"echoc": "bridge", "quiet": "none"}


@pytest.mark.parametrize("image", ["--privileged", "-v", " img", "img with space", ""])
def test_an_image_cannot_be_read_as_an_option(image: str) -> None:
    with pytest.raises(ValueError, match="image"):
        UpstreamConfig(id="echoc", tenant="acme", transport="container_stdio", image=image)


def test_the_network_is_none_or_bridge() -> None:
    with pytest.raises(ValueError, match="network"):
        UpstreamConfig(
            id="echoc",
            tenant="acme",
            transport="container_stdio",
            image="img:1",
            network="host",  # type: ignore[arg-type]
        )


async def problems(*upstreams: UpstreamConfig, tenants: tuple[str, ...] = ("acme",)) -> str:
    with pytest.raises(ConfigError) as raised:
        # No repository is needed: the problems are found before anything is written.
        await apply_config_upstreams(cast("Any", None), list(upstreams), tenants)
    return str(raised.value)


async def test_a_container_upstream_needs_an_image() -> None:
    message = await problems(UpstreamConfig(id="echoc", tenant="acme", transport="container_stdio"))

    assert "echoc" in message and "needs an image" in message


async def test_an_image_belongs_to_a_container_upstream_only() -> None:
    message = await problems(
        UpstreamConfig(id="echostd", tenant="acme", transport="stdio", command=["x"], image="img:1")
    )

    assert "image" in message and "container_stdio" in message


async def test_a_container_upstream_has_no_url_and_no_headers() -> None:
    message = await problems(
        UpstreamConfig(
            id="echoc",
            tenant="acme",
            transport="container_stdio",
            image="img:1",
            url="http://x/mcp",
            credential_mode="static",
            credential_env={"X-Api-Key": "SOME_KEY"},
        )
    )

    assert "url" in message and "credential_env" in message


async def test_docker_variables_cannot_be_handed_to_the_container() -> None:
    message = await problems(
        UpstreamConfig(
            id="echoc",
            tenant="acme",
            transport="container_stdio",
            image="img:1",
            env={"DOCKER_HOST": "tcp://evil.test:2375"},
        )
    )

    assert "DOCKER_HOST" in message


async def test_a_builtin_upstream_must_be_one_that_exists() -> None:
    message = await problems(UpstreamConfig(id="tools", tenant="acme", transport="builtin"))

    assert "no built-in upstream named 'tools'" in message and "sandbox" in message


async def test_a_builtin_upstream_needs_a_tenant_that_is_listed() -> None:
    nobody = await problems(UpstreamConfig(id="sandbox", transport="builtin"))
    stranger = await problems(UpstreamConfig(id="sandbox", tenant="initech", transport="builtin"))

    assert "needs a tenant" in nobody
    assert "initech" in stranger and "not in `tenants`" in stranger
