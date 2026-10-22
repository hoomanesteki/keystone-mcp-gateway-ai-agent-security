import sys
from pathlib import Path

import pytest

from keystone.gateway.upstreams import clean_launch
from keystone.registry.config import UpstreamConfig, stdio_environments
from keystone.settings import Settings


@pytest.mark.phase(2)
def test_the_launcher_keeps_path_and_the_configured_names_and_nothing_else() -> None:
    params = clean_launch(["python", "-m", "server", "--transport", "stdio"], {"B": "2", "A": "1"})

    assert params.command == sys.executable
    assert params.args[:3] == ["-I", "-S", "-c"]
    keep, *command = params.args[4:]
    assert keep == "PATH,A,B"
    assert command == ["python", "-m", "server", "--transport", "stdio"]
    assert params.env == {"A": "1", "B": "2"}


@pytest.mark.phase(2)
def test_a_configured_path_is_kept_once_and_values_stay_off_the_command_line() -> None:
    params = clean_launch(["server"], {"PATH": "/opt/bin", "TOKEN": "s3cret-value"})

    assert params.args[4] == "PATH,TOKEN"
    assert "s3cret-value" not in " ".join(params.args) and "/opt/bin" not in " ".join(params.args)


@pytest.mark.phase(2)
@pytest.mark.parametrize("name", ["KEYSTONE_MASTER_KEYS", "keystone_database_url", "KEYSTONE_X"])
def test_keystones_own_settings_cannot_be_handed_to_an_upstream(name: str) -> None:
    with pytest.raises(ValueError, match="Keystone's own setting"):
        UpstreamConfig(id="echostd", transport="stdio", command=["x"], env={name: "v"})


@pytest.mark.phase(2)
@pytest.mark.parametrize("name", ["", "1ABC", "A-B", "A B", "A=B"])
def test_environment_names_must_be_valid(name: str) -> None:
    with pytest.raises(ValueError, match="not a valid environment variable name"):
        UpstreamConfig(id="echostd", transport="stdio", command=["x"], env={name: "v"})


@pytest.mark.phase(2)
def test_a_stdio_upstream_loads_from_yaml(tmp_path: Path) -> None:
    config = tmp_path / "keystone.yaml"
    config.write_text(
        "upstreams:\n"
        "  - id: echostd\n"
        "    tenant: acme\n"
        "    transport: stdio\n"
        "    command: [python, -m, examples.upstreams.echo_server, --transport, stdio]\n"
        "    env: {ECHO_POISONED: '0'}\n"
        "  - {id: mail, tenant: acme, url: 'http://mail-mcp:8101/mcp'}\n"
    )

    settings = Settings(config_path=config)

    [echo, mail] = settings.upstreams
    assert echo.transport == "stdio"
    assert echo.command == [
        "python",
        "-m",
        "examples.upstreams.echo_server",
        "--transport",
        "stdio",
    ]
    assert stdio_environments(settings.upstreams) == {"echostd": {"ECHO_POISONED": "0"}}
    assert mail.env == {} and mail.command is None
