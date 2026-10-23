"""I4: a quarantined or disabled tool never appears in tools/list and never dispatches."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import anyio
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import ToolStatus
from keystone.registry.pinning import OPERATOR_DISABLED, REMOVED
from keystone.registry.repo import ToolRepo, UpstreamRepo
from keystone.settings import RegistrySettings
from tests.fixtures.approvals import VIRTUAL_TOOLS
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.upstreams import DemoUpstreams

Sessions = async_sessionmaker[AsyncSession]


async def quarantine(sessions: Sessions) -> None:
    await ToolRepo(sessions).set_pending(
        "acme",
        "mail__read_email",
        description="changed",
        input_schema={"type": "object"},
        reason="schema_changed",
    )


async def disable_by_hand(sessions: Sessions) -> None:
    await ToolRepo(sessions).set_status(
        "acme", "files__read_file", ToolStatus.DISABLED, reason=OPERATOR_DISABLED
    )


async def disable_as_removed(sessions: Sessions) -> None:
    await ToolRepo(sessions).set_status("acme", "echo__echo", ToolStatus.DISABLED, reason=REMOVED)


async def disable_the_upstream(sessions: Sessions) -> None:
    await UpstreamRepo(sessions).set_status("bank", "disabled")


@dataclass(frozen=True)
class Way:
    """One way to make a tool unavailable, and the call that must then be refused."""

    change: Callable[[Sessions], Awaitable[None]]
    tool: str
    arguments: dict[str, Any]
    upstream: str
    upstream_tool: str


WAYS = [
    Way(quarantine, "mail__read_email", {"email_id": "m01"}, "mail", "read_email"),
    Way(disable_by_hand, "files__read_file", {"path": "README.txt"}, "files", "read_file"),
    Way(disable_as_removed, "echo__echo", {"payload": "x"}, "echo", "echo"),
    Way(disable_the_upstream, "bank__get_balance", {"account": "CHK-001"}, "bank", "get_balance"),
]


@pytest.mark.services
@pytest.mark.phase(2)
async def test_i4(
    keystone_app_factory: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    sessionmaker: Sessions,
) -> None:
    """Each tool is made unavailable behind the gateway's back, as the CLI in another process
    would, after the gateway has listed the tools and holds them in its cache. The calls follow
    at once, with no wait: the cache expiring must not be what stops them."""
    app = keystone_app_factory(registry=RegistrySettings(cache_ttl_s=0.3))
    async with mcp_client(app, user="olivia") as client:  # an operator lists all twelve tools
        assert len((await client.list_tools()).tools) == 12 + len(VIRTUAL_TOOLS)

        for way in WAYS:
            await way.change(sessionmaker)
        results = {w.tool: await client.call_tool(w.tool, w.arguments) for w in WAYS}

        gone = {w.tool for w in WAYS}
        with anyio.fail_after(15):
            while True:
                names = {t.name for t in (await client.list_tools()).tools}
                if not names & gone:
                    break
                await anyio.sleep(0.2)

    for way in WAYS:
        result = results[way.tool]
        assert result.is_error, way.tool
        assert result.meta is not None
        assert result.meta["keystone/code"] in {"KS_QUARANTINED", "KS_TOOL_NOT_FOUND"}, way.tool
        calls: Any = demo_upstreams.state(way.upstream)["calls"]
        assert way.upstream_tool not in calls, way.tool
    # Three single tools are gone, and so are all three tools of the disabled upstream.
    assert len(names) == 12 - 3 - 3 + len(VIRTUAL_TOOLS)
    refused = [r for r in app.audit.records if r["tool_name"] in gone]
    assert len(refused) == 4
    assert all(r["dispatched"] is False and r["outcome"] == "rejected" for r in refused)
