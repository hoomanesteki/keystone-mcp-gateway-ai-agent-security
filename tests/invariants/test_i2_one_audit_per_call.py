"""I2: every call leaves exactly one audit record, whatever happened to it."""

from typing import Any

import anyio
import pytest

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, ToolResult
from keystone.gateway.pipeline import Dispatcher
from tests.fixtures.keystone import KeystoneApp, McpConnect


class RejectsTool:
    """A rate-limit slot that refuses one tool."""

    name = "rate_limit"

    async def before_call(self, ctx: CallContext) -> None:
        if ctx.tool.name == "echo__sleep":
            raise Reject(Code.RATE_LIMITED, "too many sleeps")

    async def after_call(self, ctx: CallContext) -> None:
        return None


class FailsOnBoom:
    def __init__(self, inner: Dispatcher) -> None:
        self.inner = inner

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        if ctx.arguments.get("payload") == "boom":
            raise RuntimeError("the dispatcher blew up")
        return await self.inner.dispatch(ctx)


CALLS: list[tuple[str, dict[str, Any], str]] = [
    ("echo__echo", {"payload": "fine"}, "ok"),
    ("echo__echo", {"payload": 7}, "rejected"),  # schema violation
    ("echo__missing", {}, "rejected"),  # unknown tool
    ("echo__sleep", {"seconds": 0.01}, "rejected"),  # refused by an interceptor
    ("echo__echo", {"payload": "boom"}, "error"),  # the dispatcher raises
    ("echo__fail", {"message": "tool error"}, "ok"),  # the upstream reports a tool error
    ("bank__get_balance", {"account": "CHK-001"}, "ok"),
    ("bank__get_balance", {}, "rejected"),
]


@pytest.mark.phase(1)
async def test_i2(keystone_app_factory: Any, mcp_client: McpConnect) -> None:
    app: KeystoneApp = keystone_app_factory(
        interceptors={"rate_limit": RejectsTool()}, wrap_dispatcher=FailsOnBoom
    )

    async with mcp_client(app) as client:
        for tool, arguments, _ in CALLS:
            await client.call_tool(tool, arguments)

    records = app.audit.records
    assert len(records) == len(CALLS)
    assert [r["outcome"] for r in records] == [outcome for *_, outcome in CALLS]
    assert len({r["call_id"] for r in records}) == len(CALLS)


@pytest.mark.phase(1)
async def test_i2_concurrent_calls(keystone_app: KeystoneApp, mcp_client: McpConnect) -> None:
    async with mcp_client(keystone_app) as client, anyio.create_task_group() as calls:
        for i in range(30):
            if i % 3 == 0:
                calls.start_soon(client.call_tool, "echo__echo", {"payload": i})  # invalid
            elif i % 3 == 1:
                calls.start_soon(client.call_tool, "echo__nothing", {})  # unknown
            else:
                calls.start_soon(client.call_tool, "echo__echo", {"payload": str(i)})

    records = keystone_app.audit.records
    assert len(records) == 30
    assert len({r["call_id"] for r in records}) == 30
    assert sorted(r["outcome"] for r in records) == ["ok"] * 10 + ["rejected"] * 20
