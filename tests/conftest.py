import pytest

pytest_plugins = ["pytester"]


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
