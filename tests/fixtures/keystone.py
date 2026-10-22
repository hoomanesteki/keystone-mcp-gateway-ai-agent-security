"""A Keystone app served on a random port, wired to the demo upstreams.

The app runs in a background thread with its own event loop (engineering note 3), and every test
gets a new one, because a session manager runs once per instance (engineering note 2).
"""

from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest
from fastapi import FastAPI
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from pydantic import SecretStr

from keystone.app import create_app
from keystone.audit.sink import InMemoryAuditSink
from keystone.registry.config import UpstreamConfig
from keystone.settings import RegistrySettings, Settings, TenantConfig
from tests.fixtures.servers import ServerThread

# Re-exported so tests/conftest.py can name one module: tests/unit/test_phase_plugin.py copies the
# conftest and strips its single `pytest_plugins` line, so that line must stay on one line.
from tests.fixtures.upstreams import (  # noqa: F401
    NAMES,
    DemoUpstreams,
    _reset_demo_upstreams,
    demo_upstreams,
)


@dataclass
class KeystoneApp:
    app: FastAPI
    thread: ServerThread

    @property
    def url(self) -> str:
        """The MCP endpoint."""
        return f"{self.thread.url}/mcp"

    @property
    def base(self) -> str:
        return self.thread.url

    @property
    def audit(self) -> InMemoryAuditSink:
        sink = self.app.state.audit
        assert isinstance(sink, InMemoryAuditSink)
        return sink


@pytest.fixture
def keystone_app_factory(
    demo_upstreams: DemoUpstreams,  # noqa: F811 - the re-exported fixture above
    clean_env: None,
    test_database_url: str,
    clean_db: None,
) -> Iterator[Callable[..., KeystoneApp]]:
    """Start Keystone against the test database. Keyword arguments go to create_app (a spy
    dispatcher, an interceptor). Tests that use it need Postgres, so they carry the `services`
    marker, and `clean_db` empties the tables the app wrote."""
    started: list[KeystoneApp] = []

    def start(*, registry: RegistrySettings | None = None, **app_options: Any) -> KeystoneApp:
        settings = Settings(
            env="test",
            registry=registry or RegistrySettings(),
            database_url=SecretStr(test_database_url),
            tenants=[TenantConfig(id="acme", name="Acme Corp")],
            allow_private_upstreams=True,
            upstreams=[
                UpstreamConfig(id=name, tenant="acme", url=demo_upstreams.url(name))
                for name in NAMES
            ],
        )
        app = create_app(settings, **app_options)
        running = KeystoneApp(app, ServerThread(app).start())
        started.append(running)
        return running

    yield start
    for running in reversed(started):
        running.thread.stop()


@pytest.fixture
def keystone_app(keystone_app_factory: Callable[..., KeystoneApp]) -> KeystoneApp:
    return keystone_app_factory()


McpConnect = Callable[..., AbstractAsyncContextManager[Client]]


@pytest.fixture
def mcp_client() -> McpConnect:
    """Open an MCP client session to Keystone. `token` becomes a bearer token (Phase 3)."""

    @asynccontextmanager
    async def connect(
        app: KeystoneApp, *, token: str | None = None, **client_options: Any
    ) -> AsyncIterator[Client]:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(15)) as http:
            transport = streamable_http_client(app.url, http_client=http)
            async with Client(transport, **client_options) as client:
                yield client

    return connect
