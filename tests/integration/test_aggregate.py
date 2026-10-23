"""KS-204: one list for every upstream, calls routed by the tool's upstream."""

import anyio
import mcp_types as types
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import ToolStatus
from keystone.gateway.server import Gateway
from keystone.registry.repo import ToolRepo, UpstreamRepo
from keystone.settings import RegistrySettings, Settings
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import one
from tests.fixtures.upstreams import NAMES, DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]


async def test_list_aggregates_all_upstreams(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    # An operator sees all twelve; support does not see the two high-risk tools (KS-406).
    async with mcp_client(keystone_app, user="olivia") as client:
        names = [t.name for t in (await client.list_tools()).tools]

    assert names == sorted(names)
    assert len(names) == 12
    assert {name.partition("__")[0] for name in names} == set(NAMES)
    for upstream in NAMES:
        assert len([n for n in names if n.startswith(f"{upstream}__")]) == 3


async def test_call_routes_to_correct_upstream(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    async with mcp_client(keystone_app) as client:
        balance = await client.call_tool("bank__get_balance", {"account": "CHK-001"})

    assert not balance.is_error
    assert one(balance)["account"] == "CHK-001"
    assert demo_upstreams.state("bank")["calls"] == ["get_balance"]
    for other in ("mail", "files", "echo"):
        assert demo_upstreams.state(other)["calls"] == []


async def test_every_upstream_gets_only_its_own_calls(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    calls = {
        "mail": ("mail__list_emails", {"folder": "inbox"}, "list_emails"),
        "files": ("files__list_files", {"path": "."}, "list_files"),
        "bank": ("bank__list_transactions", {"account": "CHK-001"}, "list_transactions"),
        "echo": ("echo__echo", {"payload": "x"}, "echo"),
    }
    async with mcp_client(keystone_app) as client:
        for exposed, arguments, _ in calls.values():
            result = await client.call_tool(exposed, arguments)
            assert not result.is_error, exposed

    for name, (_, _, upstream_tool) in calls.items():
        assert demo_upstreams.state(name)["calls"] == [upstream_tool]


async def test_a_disabled_upstream_leaves_the_list_and_its_tools_are_not_found(
    keystone_app: KeystoneApp, mcp_client: McpConnect, sessionmaker: Sessions
) -> None:
    await UpstreamRepo(sessionmaker).set_status("bank", "disabled")

    async with mcp_client(keystone_app, user="olivia") as client:
        deadline = anyio.current_time() + 10
        names: list[str] = []
        while anyio.current_time() < deadline:  # the gateway's cache expires after 2 s
            names = [t.name for t in (await client.list_tools()).tools]
            if not any(n.startswith("bank__") for n in names):
                break
            await anyio.sleep(0.3)
        result = await client.call_tool("bank__get_balance", {"account": "CHK-001"})

    assert len(names) == 9
    assert result.is_error
    assert result.meta is not None and result.meta["keystone/code"] == "KS_TOOL_NOT_FOUND"


class Listener:
    """Counts the tools/list_changed notifications a client receives."""

    def __init__(self) -> None:
        self.count = 0
        self.heard = anyio.Event()

    async def __call__(self, message: object) -> None:
        if isinstance(message, types.ToolListChangedNotification):
            self.count += 1
            self.heard.set()


async def test_the_server_says_it_sends_list_changed(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:
        tools = client.server_capabilities.tools

    assert tools is not None and tools.list_changed is True


async def test_open_sessions_hear_that_the_tool_list_changed(
    keystone_app_factory: object, mcp_client: McpConnect, sessionmaker: Sessions
) -> None:
    app = keystone_app_factory(registry=RegistrySettings(cache_ttl_s=0.2))  # type: ignore[operator]
    listener = Listener()
    async with mcp_client(app, message_handler=listener) as client:
        before = {t.name for t in (await client.list_tools()).tools}
        assert listener.count == 0

        # A change made behind the gateway's back, as the CLI would make it.
        await ToolRepo(sessionmaker).set_status(
            "acme", "echo__sleep", ToolStatus.QUARANTINED, reason="description_changed"
        )
        with anyio.fail_after(15):
            await listener.heard.wait()
        after = {t.name for t in (await client.list_tools()).tools}

    assert before - after == {"echo__sleep"}
    assert listener.count == 1


async def test_a_sync_that_changes_nothing_sends_nothing(
    keystone_app_factory: object, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(  # type: ignore[operator]
        registry=RegistrySettings(cache_ttl_s=0.2, sync_interval_s=0.3)
    )
    listener = Listener()
    async with mcp_client(app, message_handler=listener) as client:
        await client.list_tools()
        await anyio.sleep(2.0)  # several syncs and several cache reloads

    assert listener.count == 0


async def test_a_session_of_another_tenant_is_not_told() -> None:
    # The gateway keeps the tenant with each session it may notify. Checked without a network.
    sent: list[str] = []

    class Session:
        def __init__(self, name: str) -> None:
            self.name = name

        async def send_tool_list_changed(self) -> None:
            sent.append(self.name)

    gateway = Gateway(Settings(env="test"), None, None, None)  # type: ignore[arg-type]
    gateway._open["a"] = ("acme", Session("acme-1"))  # type: ignore[assignment]
    gateway._open["b"] = ("globex", Session("globex-1"))  # type: ignore[assignment]
    gateway._open["c"] = ("acme", Session("acme-2"))  # type: ignore[assignment]

    await gateway.notify_tools_changed("acme")

    assert sorted(sent) == ["acme-1", "acme-2"]


async def test_a_session_that_cannot_be_reached_is_forgotten() -> None:
    class Broken:
        async def send_tool_list_changed(self) -> None:
            raise ConnectionResetError("gone")

    gateway = Gateway(Settings(env="test"), None, None, None)  # type: ignore[arg-type]
    gateway._open["a"] = ("acme", Broken())  # type: ignore[assignment]

    await gateway.notify_tools_changed("acme")

    assert gateway._open == {}
