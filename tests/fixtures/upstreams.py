"""The four demo upstreams, running in background threads for the whole test session.

`demo_upstreams` starts them once, open to anyone. `keyed_upstreams` starts four more that require
an `X-Api-Key` header, as the compose stack does; the echo server's key is the canary secret of
invariant I3. An autouse fixture posts /_reset to the servers of each test that uses them, so no
test sees another test's mail, transfers or files.
"""

import secrets
from collections.abc import Iterator, Mapping
from pathlib import Path

import httpx
import pytest
from mcp import Client

from examples.upstreams import _common, bank_server, echo_server, files_server, mail_server
from tests.fixtures.servers import ServerThread

NAMES = ("mail", "files", "bank", "echo")


class DemoUpstreams:
    def __init__(
        self,
        threads: dict[str, ServerThread],
        workspace: Path,
        keys: Mapping[str, str] | None = None,
    ) -> None:
        self.threads = threads
        self.workspace = workspace  # the files server's directory, for tests that plant a symlink
        self.keys = dict(keys or {})  # the API key each server requires, if it requires one

    def environ(self) -> dict[str, str]:
        """The keys as the environment variables the compose config names them by."""
        return {f"{name.upper()}_API_KEY": key for name, key in self.keys.items()}

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


def start_upstreams(root: Path, keys: Mapping[str, str] | None = None) -> DemoUpstreams:
    """Start the four servers under `root`. A server named in `keys` requires that API key."""
    workspace = root / "workspace"
    apps = {
        "mail": mail_server.create_server(root / "mail.db"),
        "files": files_server.create_server(workspace, root / "files.db"),
        "bank": bank_server.create_server(root / "bank.db"),
        "echo": echo_server.create_server(poisoned=False),
    }
    threads = {}
    for name, app in apps.items():
        key = (keys or {}).get(name)
        asgi = (
            _common.http_app(app, api_key=key, host="127.0.0.1")
            if key
            else app.streamable_http_app()
        )
        threads[name] = ServerThread(asgi).start()
    return DemoUpstreams(threads, workspace.resolve(), keys)


@pytest.fixture(scope="session")
def demo_upstreams(tmp_path_factory: pytest.TempPathFactory) -> Iterator[DemoUpstreams]:
    started = start_upstreams(tmp_path_factory.mktemp("demo-upstreams"))
    try:
        yield started
    finally:
        for thread in started.threads.values():
            thread.stop()


@pytest.fixture(scope="session")
def canary_secret() -> str:
    """A string that must never appear in a log, an audit record, a result or a message. It is
    the API key of the keyed echo server, so it really is a credential Keystone holds."""
    return f"ks-canary-{secrets.token_hex(12)}"


@pytest.fixture(scope="session")
def keyed_upstreams(
    tmp_path_factory: pytest.TempPathFactory, canary_secret: str
) -> Iterator[DemoUpstreams]:
    keys = {name: f"test-{name}-key-{secrets.token_hex(6)}" for name in NAMES}
    keys["echo"] = canary_secret
    started = start_upstreams(tmp_path_factory.mktemp("keyed-upstreams"), keys)
    try:
        yield started
    finally:
        for thread in started.threads.values():
            thread.stop()


@pytest.fixture(autouse=True)
def _reset_demo_upstreams(request: pytest.FixtureRequest) -> None:
    for name in ("demo_upstreams", "keyed_upstreams"):
        if name in request.fixturenames:
            request.getfixturevalue(name).reset()
