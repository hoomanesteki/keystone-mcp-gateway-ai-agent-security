"""A Keystone app served on a random port, wired to the demo upstreams.

The app runs in a background thread with its own event loop (engineering note 3), and every test
gets a new one, because a session manager runs once per instance (engineering note 2).
"""

from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol

import httpx2
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from pydantic import SecretStr
from redis.asyncio import Redis

from keystone.app import create_app
from keystone.audit.sink import InMemoryAuditSink
from keystone.registry.config import UpstreamConfig
from keystone.settings import (
    AgentConfig,
    HealthSettings,
    PolicySettings,
    RegistrySettings,
    Settings,
    TenantConfig,
)

# Re-exported so tests/conftest.py can name one module: tests/unit/test_phase_plugin.py copies the
# conftest and strips its single `pytest_plugins` line, so that line must stay on one line.
from tests.fixtures.fake_idp import FakeIdp, fake_idp  # noqa: F401
from tests.fixtures.policies import POLICY_ROOT
from tests.fixtures.redis import redis, test_redis_url  # noqa: F401
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import (  # noqa: F401
    NAMES,
    DemoUpstreams,
    GlobexFiles,
    _reset_demo_upstreams,
    canary_secret,
    demo_upstreams,
    globex_files,
    keyed_upstreams,
)

AGENTS = {"support-agent": AgentConfig(trust="standard"), "ops-agent": AgentConfig(trust="high")}
# The vault key of every test app. Made when the test run starts and never written anywhere.
TEST_MASTER_KEY = Fernet.generate_key().decode()


def auth_options(idp: FakeIdp) -> dict[str, Any]:
    """Settings that make an app trust tokens from the fake IdP, with the two demo agents."""
    return {
        "oidc_issuer": idp.issuer,
        "oidc_audience": idp.audience,
        "agents": dict(AGENTS),
        "master_keys": SecretStr(TEST_MASTER_KEY),
    }


def globex_upstream(files: GlobexFiles) -> UpstreamConfig:
    """The globex tenant's files upstream, with its key taken from the environment."""
    return UpstreamConfig(
        id=files.name,
        tenant="globex",
        url=files.url,
        credential_mode="static",
        credential_env={"X-Api-Key": "FILES_GLOBEX_API_KEY"},
    )


def credentialed_upstreams(upstreams: DemoUpstreams, tenant: str = "acme") -> list[UpstreamConfig]:
    """Config for upstreams that require a key: static credentials taken from the environment, in
    the form the compose config uses. Hand `upstreams.environ()` to create_app as `environ`."""
    return [
        UpstreamConfig(
            id=name,
            tenant=tenant,
            url=upstreams.url(name),
            credential_mode="static",
            credential_env={"X-Api-Key": f"{name.upper()}_API_KEY"},
        )
        for name in NAMES
    ]


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
    request: pytest.FixtureRequest,
    demo_upstreams: DemoUpstreams,  # noqa: F811 - the re-exported fixture above
    fake_idp: FakeIdp,  # noqa: F811
    clean_env: None,
    test_database_url: str,
    clean_db: None,
    test_redis_url: str,  # noqa: F811 - the re-exported fixtures above
    redis: Redis,  # noqa: F811
) -> Iterator[Callable[..., KeystoneApp]]:
    """Start Keystone against the test database and Redis database 15. `settings` overrides
    Settings fields, and other keyword arguments go to create_app (a spy dispatcher, an
    interceptor). `keyed=True` points it at the demo servers that require an API key and gives it
    their keys through the environment, as compose does. Tests that use it need Postgres and
    Redis, so they carry the `services` marker, and `clean_db` and `redis` empty what the app
    wrote."""
    started: list[KeystoneApp] = []

    def start(
        *,
        registry: RegistrySettings | None = None,
        settings: Mapping[str, Any] | None = None,
        keyed: bool = False,
        globex: bool = False,
        **app_options: Any,
    ) -> KeystoneApp:
        tenants = [TenantConfig(id="acme", name="Acme Corp")]
        if keyed:
            keyed_servers: DemoUpstreams = request.getfixturevalue("keyed_upstreams")
            keyed_servers.reset()
            upstreams = credentialed_upstreams(keyed_servers)
            app_options.setdefault("environ", keyed_servers.environ())
        else:
            upstreams = [
                UpstreamConfig(id=name, tenant="acme", url=demo_upstreams.url(name))
                for name in NAMES
            ]
        if globex:
            # A second tenant with a drive of its own. Its key reaches Keystone through the
            # environment, like the others.
            files_globex: GlobexFiles = request.getfixturevalue("globex_files")
            files_globex.reset()
            tenants.append(TenantConfig(id="globex", name="Globex Inc"))
            upstreams = [*upstreams, globex_upstream(files_globex)]
            app_options["environ"] = {**app_options.get("environ", {}), **files_globex.environ()}
        options: dict[str, Any] = {
            "env": "test",
            "registry": registry or RegistrySettings(),
            "database_url": SecretStr(test_database_url),
            "redis_url": SecretStr(test_redis_url),
            "tenants": tenants,
            "allow_private_upstreams": True,
            "upstreams": upstreams,
            # The repository's own policies, wherever the tests are run from.
            "policy": PolicySettings(root=POLICY_ROOT, include_demo=True),
            **auth_options(fake_idp),
        }
        options.update(settings or {})
        app = create_app(Settings(**options), **app_options)
        running = KeystoneApp(app, ServerThread(app).start())
        started.append(running)
        return running

    yield start
    for running in reversed(started):
        running.thread.stop()


@pytest.fixture
def keystone_app(keystone_app_factory: Callable[..., KeystoneApp]) -> KeystoneApp:
    return keystone_app_factory()


@pytest.fixture
def start_keystone(
    fake_idp: FakeIdp,  # noqa: F811
    clean_env: None,
    test_database_url: str,
    clean_db: None,
    test_redis_url: str,  # noqa: F811
    redis: Redis,  # noqa: F811
) -> Iterator[Callable[..., KeystoneApp]]:
    """Start Keystone with upstreams the test chooses, for tests about upstreams that go down or
    arrive late. The timers (periodic sync, health probes) are off unless the test sets them."""
    started: list[KeystoneApp] = []

    def start(
        upstreams: list[UpstreamConfig],
        *,
        registry: RegistrySettings | None = None,
        health: HealthSettings | None = None,
        **app_options: Any,
    ) -> KeystoneApp:
        settings = Settings(
            env="test",
            database_url=SecretStr(test_database_url),
            redis_url=SecretStr(test_redis_url),
            tenants=[TenantConfig(id="acme", name="Acme Corp")],
            allow_private_upstreams=True,
            upstreams=upstreams,
            registry=registry or RegistrySettings(sync_interval_s=0),
            health=health or HealthSettings(interval_s=0),
            policy=PolicySettings(root=POLICY_ROOT, include_demo=True),
            **auth_options(fake_idp),
        )
        app = create_app(settings, **app_options)
        running = KeystoneApp(app, ServerThread(app).start())
        started.append(running)
        return running

    yield start
    for running in reversed(started):
        running.thread.stop()


class Endpoint(Protocol):
    @property
    def url(self) -> str: ...


McpConnect = Callable[..., AbstractAsyncContextManager[Client]]


@pytest.fixture
def mcp_client(fake_idp: FakeIdp) -> McpConnect:  # noqa: F811
    """Open an MCP client session to Keystone, signed in as alice of acme through support-agent.

    `user` and `agent` choose another demo user (a test that calls a high-risk tool uses
    `user="olivia"`, an operator). `token` sends that exact token instead, and `token=""` sends
    none. Other keyword arguments go to the MCP client.
    """

    @asynccontextmanager
    async def connect(
        app: Endpoint,
        *,
        token: str | None = None,
        user: str = "alice",
        agent: str | None = None,
        **client_options: Any,
    ) -> AsyncIterator[Client]:
        bearer = fake_idp.token_for(user, agent) if token is None else token
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
        async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(15)) as http:
            transport = streamable_http_client(app.url, http_client=http)
            async with Client(transport, **client_options) as client:
                yield client

    return connect
