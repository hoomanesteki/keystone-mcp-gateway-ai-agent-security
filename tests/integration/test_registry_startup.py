"""KS-203: the app syncs at startup and on a timer, and a dead upstream never stops either."""

from collections.abc import Callable

import anyio
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from examples.upstreams import echo_server
from keystone.registry.config import UpstreamConfig
from keystone.registry.repo import UpstreamRepo
from keystone.settings import RegistrySettings
from tests.fixtures.approvals import VIRTUAL_TOOLS
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.servers import RestartableServer
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]


def echo_on_a_free_port() -> RestartableServer:
    return RestartableServer(
        lambda: echo_server.create_server(poisoned=False).streamable_http_app()
    )


def config(name: str, url: str) -> UpstreamConfig:
    return UpstreamConfig(id=name, tenant="acme", url=url)


async def tool_names(connect: McpConnect, app: KeystoneApp) -> set[str]:
    async with connect(app) as client:
        return {t.name for t in (await client.list_tools()).tools}


async def test_startup_survives_a_dead_upstream_and_the_timer_retries_it(
    start_keystone: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    late = echo_on_a_free_port()
    try:
        app = start_keystone(
            [config("mail", demo_upstreams.url("mail")), config("echo", late.url)],
            registry=RegistrySettings(sync_interval_s=0.5),
        )

        # The app is up. Mail's tools are there; the dead upstream has an error and no tools.
        assert await tool_names(mcp_client, app) == VIRTUAL_TOOLS | {
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
        with anyio.fail_after(30):
            while "echo__echo" not in await tool_names(mcp_client, app):  # noqa: ASYNC110
                await anyio.sleep(0.3)
        echo = await repo.get("echo")
        assert echo is not None and echo.status == "up" and echo.last_error is None
    finally:
        late.stop()


async def test_a_dead_upstream_at_a_later_startup_keeps_the_tools_it_had(
    start_keystone: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    host = echo_on_a_free_port().start()
    try:
        first = start_keystone([config("echo", host.url)])
        assert "echo__echo" in await tool_names(mcp_client, first)
        first.thread.stop()
        host.stop()

        second = start_keystone(
            [config("echo", host.url), config("mail", demo_upstreams.url("mail"))]
        )

        # A failed sync proves nothing was removed, so the tools stay. A call to them fails on its
        # own (KS-209 makes that fast).
        assert {"echo__echo", "mail__read_email"} <= await tool_names(mcp_client, second)
        echo = await UpstreamRepo(sessionmaker).get("echo")
        assert echo is not None and echo.last_error is not None
        assert echo.last_sync_at is not None  # the good sync from the first run
    finally:
        host.stop()
