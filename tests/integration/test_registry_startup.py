"""KS-203: the app syncs at startup and on a timer, and a dead upstream never stops either."""

import socket
import time
from collections.abc import Callable, Iterator

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from examples.upstreams import echo_server
from keystone.app import create_app
from keystone.registry.config import UpstreamConfig
from keystone.registry.repo import UpstreamRepo
from keystone.settings import RegistrySettings, Settings, TenantConfig
from tests.fixtures.keystone import McpConnect
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


class Running:
    def __init__(self, thread: ServerThread) -> None:
        self.thread = thread
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True
        self.thread.stop()

    @property
    def url(self) -> str:
        return f"{self.thread.url}/mcp"


@pytest.fixture
def start_app(
    clean_env: None, test_database_url: str, sessionmaker: Sessions
) -> Iterator[Callable[..., Running]]:
    started: list[Running] = []

    def start(upstreams: list[UpstreamConfig], interval_s: float = 0.0) -> Running:
        settings = Settings(
            env="test",
            database_url=SecretStr(test_database_url),
            tenants=[TenantConfig(id="acme", name="Acme Corp")],
            upstreams=upstreams,
            allow_private_upstreams=True,
            registry=RegistrySettings(sync_interval_s=interval_s),
        )
        running = Running(ServerThread(create_app(settings)).start())
        started.append(running)
        return running

    yield start
    for running in reversed(started):
        if not running.stopped:
            running.stop()


class LateEcho:
    """The echo server, brought up late on a port the app already knows."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.thread: ServerThread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def start(self) -> None:
        app = echo_server.create_server(poisoned=False).streamable_http_app()
        self.thread = ServerThread(app, port=self.port).start()

    def stop(self) -> None:
        if self.thread is not None:
            self.thread.stop()
            self.thread = None


def config(name: str, url: str) -> UpstreamConfig:
    return UpstreamConfig(id=name, tenant="acme", url=url)


async def tool_names(connect: McpConnect, app: Running) -> set[str]:
    # McpConnect takes the KeystoneApp fixture type, which only needs `.url` here.
    async with connect(app) as client:  # type: ignore[arg-type]
        return {t.name for t in (await client.list_tools()).tools}


async def test_startup_survives_a_dead_upstream_and_the_timer_retries_it(
    start_app: Callable[..., Running],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    late = LateEcho(free_port())
    try:
        app = start_app(
            [config("mail", demo_upstreams.url("mail")), config("echo", late.url)], interval_s=0.5
        )

        # The app is up. Mail's tools are there; the dead upstream has an error and no tools.
        assert await tool_names(mcp_client, app) == {
            "mail__list_emails",
            "mail__read_email",
            "mail__send_email",
        }
        repo = UpstreamRepo(sessionmaker)
        echo = await repo.get("echo")
        mail = await repo.get("mail")
        assert echo is not None and echo.last_error is not None
        assert echo.last_error.startswith("KS_UPSTREAM_ERROR")
        assert echo.last_sync_at is None
        assert mail is not None and mail.status == "up" and mail.last_error is None

        # The upstream comes up. The next round of the timer finds it.
        late.start()
        deadline = time.monotonic() + 30
        names: set[str] = set()
        while time.monotonic() < deadline and "echo__echo" not in names:
            names = await tool_names(mcp_client, app)
        assert "echo__echo" in names, "the periodic sync never picked the upstream up"
        echo = await repo.get("echo")
        assert echo is not None and echo.status == "up" and echo.last_error is None
    finally:
        late.stop()


async def test_a_dead_upstream_at_a_later_startup_keeps_the_tools_it_had(
    start_app: Callable[..., Running],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    host = LateEcho(free_port())
    host.start()
    first = start_app([config("echo", host.url)])
    assert "echo__echo" in await tool_names(mcp_client, first)
    first.stop()
    host.stop()

    second = start_app([config("echo", host.url), config("mail", demo_upstreams.url("mail"))])

    # A failed sync proves nothing was removed, so the tools stay. A call to them fails on its
    # own (KS-209 makes that fast).
    assert {"echo__echo", "mail__read_email"} <= await tool_names(mcp_client, second)
    echo = await UpstreamRepo(sessionmaker).get("echo")
    assert echo is not None and echo.last_error is not None
    assert echo.last_sync_at is not None  # the good sync from the first run
