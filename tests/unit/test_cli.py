import pytest
from typer.testing import CliRunner

from keystone import __version__
from keystone.admin.cli import app

runner = CliRunner()


@pytest.mark.phase(0)
def test_version_command_prints_the_package_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.phase(0)
def test_help_lists_serve() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "serve" in result.output
