"""KS-208: MCP servers that Keystone starts and talks to over stdin and stdout."""

import json
import os
import signal
import sys
from collections.abc import Callable
from pathlib import Path

import anyio
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.errors import Code, Reject
from keystone.core.types import ToolResult
from keystone.gateway.upstreams import (
    StdioUpstreamClient,
    UpstreamDirectory,
    UpstreamPool,
    UpstreamTarget,
    directory_client_factory,
)
from keystone.registry.config import UpstreamConfig
from keystone.registry.repo import UpstreamRepo
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

ROOT = Path(__file__).resolve().parents[2]
PROBE = str(ROOT / "tests" / "fixtures" / "stdio_probe.py")
FAST = (0.05, 0.1, 0.2)
Sessions = async_sessionmaker[AsyncSession]


def text_of(result: ToolResult) -> str:
    [block] = result.content
    return str(block["text"])


async def pid_of(client: StdioUpstreamClient) -> int:
    return int(text_of(await client.call_tool("pid", {}, timeout_s=10)))


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def test_stdio_list_and_call(
    start_keystone: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    sessionmaker: Sessions,
) -> None:
    echo = UpstreamConfig(
        id="echostd",
        tenant="acme",
        transport="stdio",
        command=[sys.executable, "-m", "examples.upstreams.echo_server", "--transport", "stdio"],
        # The child gets nothing of Keystone's environment, so it must be told where `examples` is.
        env={"PYTHONPATH": str(ROOT)},
    )
    app = start_keystone([echo])

    async with mcp_client(app) as client:
        tools = sorted(t.name for t in (await client.list_tools()).tools)
        result = await client.call_tool("echostd__echo", {"payload": "over a pipe"})

    assert tools == ["echostd__echo", "echostd__fail", "echostd__sleep"]
    assert not result.is_error
    assert texts(result) == ["over a pipe"]
    row = await UpstreamRepo(sessionmaker).get("echostd")
    assert row is not None
    assert (row.transport, row.status, row.last_error) == ("stdio", "up", None)
    assert row.command == echo.command


async def test_stdio_restart_after_crash() -> None:
    async with anyio.create_task_group() as group:
        client = StdioUpstreamClient([sys.executable, PROBE], {}, group, backoff_s=FAST)
        try:
            first = await pid_of(client)
            os.kill(first, signal.SIGKILL)

            # A call that races the death notice may fail once. The next one must succeed on a
            # new process.
            failures = 0
            second = first
            with anyio.fail_after(20):
                while second == first:
                    try:
                        second = await pid_of(client)
                    except Reject as reject:
                        assert reject.code is Code.UPSTREAM_ERROR
                        failures += 1
                        await anyio.sleep(0.1)
            third = await pid_of(client)
        finally:
            await client.aclose()

    assert failures <= 1
    assert second != first
    assert third == second  # one restart, then the same process serves


async def test_stdio_env_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("KEYSTONE_MASTER_KEYS", "KEYSTONE_DATABASE_URL", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, f"canary-{name}")
    async with anyio.create_task_group() as group:
        client = StdioUpstreamClient(
            [sys.executable, PROBE], {"FEATURE": "on", "MODE": "test"}, group, backoff_s=FAST
        )
        try:
            seen = json.loads(text_of(await client.call_tool("env", {}, timeout_s=10)))
        finally:
            await client.aclose()

    assert "canary" not in json.dumps(seen)
    assert seen["FEATURE"] == "on" and seen["MODE"] == "test"
    assert seen["PATH"] == os.environ["PATH"]
    # Not even the variables the SDK would add by default.
    for name in ("HOME", "USER", "LOGNAME", "SHELL", "TERM"):
        assert name not in seen
    assert not [name for name in seen if name.upper().startswith("KEYSTONE_")]


async def test_a_configured_path_replaces_keystones(monkeypatch: pytest.MonkeyPatch) -> None:
    async with anyio.create_task_group() as group:
        client = StdioUpstreamClient(
            [sys.executable, PROBE],
            {"PATH": f"/nonexistent:{Path(sys.executable).parent}"},
            group,
            backoff_s=FAST,
        )
        try:
            seen = json.loads(text_of(await client.call_tool("env", {}, timeout_s=10)))
        finally:
            await client.aclose()

    assert seen["PATH"].startswith("/nonexistent:")


async def test_the_child_ends_when_the_client_closes() -> None:
    async with anyio.create_task_group() as group:
        client = StdioUpstreamClient([sys.executable, PROBE], {}, group, backoff_s=FAST)
        pid = await pid_of(client)
        assert alive(pid)

        await client.aclose()

    with anyio.fail_after(5):
        while alive(pid):  # noqa: ASYNC110
            await anyio.sleep(0.05)


async def test_the_child_ends_when_the_pool_closes() -> None:
    directory = UpstreamDirectory()
    directory.update({"probe": UpstreamTarget(transport="stdio", command=(sys.executable, PROBE))})
    async with UpstreamPool(directory_client_factory(directory)) as pool:
        client = await pool.get("probe", None)
        text = text_of(await client.call_tool("pid", {}, timeout_s=10))
        pid = int(text)
        assert alive(pid)

    with anyio.fail_after(5):
        while alive(pid):  # noqa: ASYNC110
            await anyio.sleep(0.05)


async def test_it_starts_only_when_needed() -> None:
    async with anyio.create_task_group() as group:
        client = StdioUpstreamClient([sys.executable, PROBE], {}, group, backoff_s=FAST)
        assert client._connection is None
        await pid_of(client)
        assert client._connection is not None
        await client.aclose()


async def test_a_command_that_cannot_start_is_an_upstream_error_and_not_a_hang() -> None:
    async with anyio.create_task_group() as group:
        client = StdioUpstreamClient(["no-such-program-here"], {}, group, backoff_s=FAST)
        try:
            with anyio.fail_after(30), pytest.raises(Reject) as raised:
                await client.list_tools()
            healthy = await client.health()
        finally:
            await client.aclose()

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert "no-such-program-here" not in raised.value.message
    assert healthy is False


async def test_a_stdio_upstream_needs_a_command() -> None:
    async with anyio.create_task_group() as group:
        with pytest.raises(ValueError, match="needs a command"):
            StdioUpstreamClient([], {}, group)
        group.cancel_scope.cancel()
