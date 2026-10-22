"""The four demo upstreams, running in background threads for the whole test session.

`demo_upstreams` starts them once. An autouse fixture posts /_reset to all four before each test
that uses them, so no test sees another test's mail, transfers or files.
"""

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from mcp import Client

from examples.upstreams import bank_server, echo_server, files_server, mail_server
from tests.fixtures.servers import ServerThread

NAMES = ("mail", "files", "bank", "echo")


class DemoUpstreams:
    def __init__(self, threads: dict[str, ServerThread], workspace: Path) -> None:
        self.threads = threads
        self.workspace = workspace  # the files server's directory, for tests that plant a symlink

    def base(self, name: str) -> str:
        return self.threads[name].url

    def url(self, name: str) -> str:
        """The MCP endpoint of one upstream."""
        return f"{self.base(name)}/mcp"

    def client(self, name: str) -> Client:
        return Client(self.url(name))

    def reset(self) -> None:
        for name in NAMES:
            httpx.post(f"{self.base(name)}/_reset", timeout=10).raise_for_status()

    def state(self, name: str) -> dict[str, object]:
        response = httpx.get(f"{self.base(name)}/_state", timeout=10)
        response.raise_for_status()
        state: dict[str, object] = response.json()
        return state


@pytest.fixture(scope="session")
def demo_upstreams(tmp_path_factory: pytest.TempPathFactory) -> Iterator[DemoUpstreams]:
    root: Path = tmp_path_factory.mktemp("demo-upstreams")
    workspace = root / "workspace"
    apps = {
        "mail": mail_server.create_server(root / "mail.db"),
        "files": files_server.create_server(workspace, root / "files.db"),
        "bank": bank_server.create_server(root / "bank.db"),
        "echo": echo_server.create_server(poisoned=False),
    }
    threads = {name: ServerThread(app.streamable_http_app()).start() for name, app in apps.items()}
    try:
        yield DemoUpstreams(threads, workspace.resolve())
    finally:
        for thread in threads.values():
            thread.stop()


@pytest.fixture(autouse=True)
def _reset_demo_upstreams(request: pytest.FixtureRequest) -> None:
    if "demo_upstreams" in request.fixturenames:
        request.getfixturevalue("demo_upstreams").reset()
