"""The gateway's MCP endpoint, following the spike (docs/spikes/mcp-proxy.md, ADR-0003).

The low-level Server serves `tools/list` and `tools/call`. A call becomes a CallContext and goes
through the pipeline; nothing here talks to an upstream. Only the handshake protocol era is
served, because session state is keyed by Mcp-Session-Id and the newer era has none.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import mcp_types as types
import structlog
from fastapi import FastAPI
from mcp.server import Server, ServerRequestContext
from mcp.server.context import CallNext, HandlerResult
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from keystone.core.errors import Code, Reject, to_tool_result
from keystone.core.ids import new_id
from keystone.core.types import CallContext, Principal, SessionState, ToolRef, ToolResult
from keystone.gateway.pipeline import Pipeline
from keystone.gateway.sessions import InMemorySessionStore
from keystone.registry.static import StaticRegistry
from keystone.settings import Settings

log = structlog.get_logger()

SESSION_HEADER = "mcp-session-id"
MAX_NAME_IN_MESSAGE = 100
MAX_NAME_IN_AUDIT = 200

Context = ServerRequestContext[Any, Any]


class Gateway:
    def __init__(
        self,
        settings: Settings,
        registry: StaticRegistry,
        sessions: InMemorySessionStore,
        pipeline: Pipeline,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.sessions = sessions
        self.pipeline = pipeline

    def principal(self) -> Principal:
        # KS-304 replaces this with the principal from the validated token.
        principal = self.settings.dev_principal
        if principal is None:
            raise MCPError(code=types.INTERNAL_ERROR, message="no authentication is configured")
        return principal

    async def list_tools(
        self, ctx: Context, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        tools = await self.registry.list_for_tenant(self.principal().tenant_id)
        return types.ListToolsResult(
            tools=[
                types.Tool(name=t.name, description=t.description, input_schema=t.input_schema)
                for t in tools
            ]
        )

    async def call_tool(
        self, ctx: Context, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        principal = self.principal()
        session = await self._session(ctx, principal)
        tool = await self.registry.get(principal.tenant_id, params.name)
        call = CallContext(
            call_id=new_id(),
            received_at=datetime.now(UTC),
            principal=principal,
            session=session,
            tool=tool or unknown_tool(params.name, principal),
            arguments=params.arguments or {},
        )
        if tool is None:
            shown = params.name[:MAX_NAME_IN_MESSAGE]
            result = await self.pipeline.reject(
                call, Reject(Code.TOOL_NOT_FOUND, f"there is no tool named {shown!r}")
            )
        else:
            result = await self.pipeline.run(call)
        return to_call_tool_result(result, call.call_id)

    async def _session(self, ctx: Context, principal: Principal) -> SessionState:
        # ctx.request is typed Any in the SDK. On HTTP it is the Starlette request.
        request = cast("Request | None", ctx.request)
        session_id = request.headers.get(SESSION_HEADER) if request is not None else None
        if not session_id:
            return SessionState(
                session_id=f"unbound-{new_id()}", principal=principal, created_at=datetime.now(UTC)
            )
        return await self.sessions.get(session_id) or await self.sessions.create(
            session_id, principal
        )


def unknown_tool(name: str, principal: Principal) -> ToolRef:
    """A stand-in so a call to a tool that does not exist can still be audited."""
    return ToolRef(
        name=name[:MAX_NAME_IN_AUDIT],
        upstream_id="unknown",
        upstream_tool_name=name[:MAX_NAME_IN_AUDIT],
        tenant_id=principal.tenant_id,
        description="",
        input_schema={},
        description_hash="",
        schema_hash="",
    )


def to_call_tool_result(result: ToolResult, call_id: str) -> types.CallToolResult:
    try:
        return types.CallToolResult.model_validate(
            {
                "content": result.content,
                "structuredContent": result.structured_content,
                "isError": result.is_error,
            }
        )
    except ValidationError:
        # An upstream sent a content block this SDK cannot represent. Say so, keep the details
        # in the log, and do not pass the block on.
        log.error("result_not_representable", call_id=call_id)
        refusal = to_tool_result(
            Reject(
                Code.UPSTREAM_ERROR, "the upstream server sent a result that cannot be passed on"
            ),
            call_id,
        )
        return types.CallToolResult.model_validate({"content": refusal.content, "isError": True})


async def handshake_era_only(ctx: Context, call_next: CallNext) -> HandlerResult:
    """Answer the newer protocol era with the error that means "I speak these versions".

    A client in its default `auto` mode then falls back to the initialize handshake by itself.
    """
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


def build_server(gateway: Gateway) -> Server[Any]:
    server: Server[Any] = Server(
        "keystone", on_list_tools=gateway.list_tools, on_call_tool=gateway.call_tool
    )
    server.middleware.insert(0, handshake_era_only)
    return server


def transport_security(settings: Settings) -> TransportSecuritySettings:
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=[f"http://{host}" for host in settings.allowed_hosts],
    )


class _Unauthenticated:
    """Stands in for the MCP endpoint when nobody can be identified: refuse every request."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"error": "authentication is required"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, receive, send)


def mount_mcp(app: FastAPI, gateway: Gateway) -> StreamableHTTPSessionManager:
    """Serve /mcp. The caller runs the returned manager inside the app's lifespan, and builds a
    new manager for every app, because run() works once per instance (engineering note 2)."""
    manager = StreamableHTTPSessionManager(
        app=build_server(gateway), security_settings=transport_security(gateway.settings)
    )
    # A Route, not a Mount: a Mount redirects /mcp to /mcp/.
    endpoint = (
        StreamableHTTPASGIApp(manager) if gateway.settings.dev_principal else _Unauthenticated()
    )
    app.router.routes.append(Route("/mcp", endpoint=endpoint))
    return manager
