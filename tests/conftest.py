import os
from pathlib import Path

import pytest

from keystone.settings import Settings

pytest_plugins = ["pytester", "tests.fixtures.db", "tests.fixtures.upstreams"]


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--phase", type=int, default=99, help="run tests introduced up to this phase")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "phase(n): phase that introduced this test")
    config.addinivalue_line("markers", "services: needs postgres and redis")
    config.addinivalue_line("markers", "docker: needs the Docker daemon")
    config.addinivalue_line("markers", "slow: downloads models or runs longer than 10 s")
    config.addinivalue_line("markers", "e2e: runs against the full compose stack")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    max_phase = config.getoption("--phase")
    for item in items:
        marker = item.get_closest_marker("phase")
        if marker is None:
            raise pytest.UsageError(f"{item.nodeid} is missing @pytest.mark.phase(n)")
        if marker.args[0] > max_phase:
            item.add_marker(pytest.mark.skip(reason=f"introduced in phase {marker.args[0]}"))


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop KEYSTONE_* variables so a developer's shell cannot change a test's result."""
    for name in [n for n in os.environ if n.startswith("KEYSTONE_")]:
        monkeypatch.delenv(name)


@pytest.fixture
def settings(tmp_path: Path, clean_env: None) -> Settings:
    """Test settings: env=test and a temp config file."""
    config = tmp_path / "keystone.yaml"
    config.write_text("log_level: warning\n")
    return Settings(env="test", config_path=config)
