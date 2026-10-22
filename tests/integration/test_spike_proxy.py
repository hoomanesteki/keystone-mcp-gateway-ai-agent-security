"""KS-101: the smallest proxy that answers the five spike questions.

The findings and the SDK names are in docs/spikes/mcp-proxy.md. This test keeps the round trip
alive so an SDK upgrade that breaks the pattern fails here first.
"""

import contextlib
from collections.abc import AsyncIterator
from typing import Any, cast

import anyio
import httpx2
import mcp_types as types
import pytest
from fastapi import FastAPI
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.shared.exceptions import MCPError
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS
from starlette.requests import Request
from starlette.routing import Route

from tests.fixtures.servers import ServerThread


def build_upstream() -> MCPServer:
    upstream = MCPServer("spike-upstream")

    @upstream.tool()
    def echo(text: str) -> str:
        """Return the text unchanged."""
        return text

    return upstream


def build_gateway(upstream_url: str, seen_sessions: list[str]) -> FastAPI:
    holder: dict[str, Client] = {}

    async def hold_upstream_session(ready: anyio.Event, stop: anyio.Event) -> None:
        # Question 4. The session is entered and left in this one task (engineering note 1).
        # Request handlers run in other tasks and only borrow the open session.
        async with Client(upstream_url) as upstream:
            holder["upstream"] = upstream
            ready.set()
            await stop.wait()

    async def on_list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        # Questions 2 and 3. The HTTP request is on the context, so the list can differ per caller.
        request = cast("Request", ctx.request)
        if request.headers.get("x-user") != "olivia":
            return types.ListToolsResult(tools=[])
        listing = await holder["upstream"].list_tools()
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=f"up__{tool.name}",
                    description=tool.description,
                    input_schema=tool.input_schema,
                )
                for tool in listing.tools
            ]
        )

    async def on_call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        request = cast("Request", ctx.request)
        seen_sessions.append(request.headers.get("mcp-session-id", ""))
        prefix, _, name = params.name.partition("__")
        if prefix != "up":
            # Question 5. A refusal is a normal result: is_error set, machine-readable _meta.
            return types.CallToolResult(
                content=[types.TextContent(text=f"[keystone:KS_TOOL_NOT_FOUND] {params.name}")],
                is_error=True,
                _meta={"keystone/code": "KS_TOOL_NOT_FOUND"},
            )
        result = await holder["upstream"].call_tool(name, params.arguments)
        # Copy the content only. The upstream's _meta carries its own server identity.
        return types.CallToolResult(
            content=result.content,
            structured_content=result.structured_content,
            is_error=result.is_error,
        )

    async def handshake_era_only(ctx: ServerRequestContext, call_next: Any) -> Any:
        # The 2026-07-28 era has no Mcp-Session-Id. Answering it with this error makes a client in
        # its default "auto" mode fall back to the initialize handshake, which has sessions.
        if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:
            raise MCPError(
                code=types.UNSUPPORTED_PROTOCOL_VERSION,
                message="Unsupported protocol version",
                data={
                    "supported": list(HANDSHAKE_PROTOCOL_VERSIONS),
                    "requested": ctx.protocol_version,
                },
            )
        return await call_next(ctx)

    server = Server("keystone", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    server.middleware.insert(0, handshake_era_only)
    # Question 1. One manager per app: run() works once per instance (engineering note 2).
    manager = StreamableHTTPSessionManager(app=server)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        ready, stop = anyio.Event(), anyio.Event()
        async with manager.run(), anyio.create_task_group() as tasks:
            tasks.start_soon(hold_upstream_session, ready, stop)
            await ready.wait()
            yield
            stop.set()

    app = FastAPI(lifespan=lifespan)
    app.router.routes.append(Route("/mcp", endpoint=StreamableHTTPASGIApp(manager)))
    return app


def texts(result: types.CallToolResult) -> list[str]:
    return [block.text for block in result.content if isinstance(block, types.TextContent)]


def as_user(url: str, user: str) -> Client:
    http = httpx2.AsyncClient(headers={"x-user": user}, timeout=httpx2.Timeout(10))
    return Client(streamable_http_client(url, http_client=http))


@pytest.mark.phase(1)
async def test_minimal_proxy_roundtrip() -> None:
    seen_sessions: list[str] = []
    upstream = ServerThread(build_upstream().streamable_http_app()).start()
    gateway = ServerThread(build_gateway(f"{upstream.url}/mcp", seen_sessions)).start()
    try:
        async with as_user(f"{gateway.url}/mcp", "olivia") as client:
            # The probe for the newer era was refused, so the client used the handshake.
            assert client.protocol_version in HANDSHAKE_PROTOCOL_VERSIONS

            listing = await client.list_tools()
            assert [tool.name for tool in listing.tools] == ["up__echo"]

            first = await client.call_tool("up__echo", {"text": "hello"})
            second = await client.call_tool("up__echo", {"text": "again"})
            assert texts(first) == ["hello"]
            assert not first.is_error
            assert first.meta is None
            assert len(seen_sessions) == 2
            assert seen_sessions[0] and seen_sessions[0] == seen_sessions[1]
            assert texts(second) == ["again"]

            refused = await client.call_tool("other__tool", {})
            assert refused.is_error
            assert refused.meta == {"keystone/code": "KS_TOOL_NOT_FOUND"}

        async with as_user(f"{gateway.url}/mcp", "mallory") as client:
            assert (await client.list_tools()).tools == []
    finally:
        gateway.stop()
        upstream.stop()
