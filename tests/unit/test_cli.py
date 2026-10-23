from collections.abc import Iterator

import pytest
import structlog
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


@pytest.fixture
def logging_restored() -> Iterator[None]:
    # `serve` configures logging for the whole process, pointing it at the captured stdout of
    # this test. Without a reset, a later test that logs writes to a file that is closed.
    yield
    structlog.reset_defaults()


@pytest.mark.phase(3)
@pytest.mark.usefixtures("logging_restored")
def test_serve_refuses_to_start_without_an_issuer(clean_env: None) -> None:
    result = runner.invoke(app, ["serve"], env={"KEYSTONE_ENV": "test"})

    assert result.exit_code == 1
    assert "oidc_issuer" in result.output


@pytest.mark.phase(3)
@pytest.mark.usefixtures("logging_restored")
def test_serve_refuses_to_start_with_authentication_off_in_prod(clean_env: None) -> None:
    result = runner.invoke(
        app, ["serve"], env={"KEYSTONE_ENV": "prod", "KEYSTONE_AUTH__MODE": "none"}
    )

    assert result.exit_code == 1
    assert "auth.mode none is only allowed when env is dev or test" in result.output
