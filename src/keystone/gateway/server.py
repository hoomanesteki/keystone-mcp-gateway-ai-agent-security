"""The gateway's MCP endpoint, following the spike (docs/spikes/mcp-proxy.md, ADR-0003).

The low-level Server serves `tools/list` and `tools/call`. A call becomes a CallContext and goes
through the pipeline; nothing here talks to an upstream. Only the handshake protocol era is
served, because session state is keyed by Mcp-Session-Id and the newer era has none.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import anyio
import mcp_types as types
import structlog
from fastapi import FastAPI
from mcp.server import NotificationOptions, Server, ServerRequestContext
from mcp.server.context import CallNext, HandlerResult
from mcp.server.models import InitializationOptions
from mcp.server.session import ServerSession
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecurityMiddleware, TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS
from pydantic import ValidationError
from starlette.requests import Request
from starlette.routing import Route

from keystone.core.errors import (
    KEYSTONE_META_PREFIX,
    Code,
    Reject,
    RejectionResult,
    to_tool_result,
)
from keystone.core.ids import new_id
from keystone.core.types import CallContext, Principal, SessionState, ToolRef, ToolResult
from keystone.gateway.pipeline import Pipeline
from keystone.gateway.sessions import SessionStore
from keystone.identity.middleware import (
    PRINCIPAL_KEY,
    SESSION_HEADER,
    Authenticator,
    McpAuthMiddleware,
    SessionBindings,
    principal_key,
)
from keystone.registry.service import ToolLookup
from keystone.settings import Settings

log = structlog.get_logger()

UNBOUND_PREFIX = "unbound-"
CALL_ID_KEY = "keystone/call_id"
MAX_OPEN_SESSIONS = 10_000
NOTIFY_TIMEOUT_S = 2.0
MAX_NAME_IN_MESSAGE = 100
MAX_NAME_IN_AUDIT = 200

Context = ServerRequestContext[Any, Any]


class ToolFilter(Protocol):
    async def visible(self, principal: Principal, tools: Sequence[ToolRef]) -> list[ToolRef]: ...


class Gateway:
    def __init__(
        self,
        settings: Settings,
        registry: ToolLookup,
        sessions: SessionStore,
        pipeline: Pipeline,
        tool_filter: ToolFilter | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.sessions = sessions
        self.pipeline = pipeline
        # What decides which tools a caller sees. Without one the caller sees every tool of its
        # tenant, which only the unit tests of the gateway want.
        self.tool_filter = tool_filter
        # Who opened each session. The authentication middleware fills it and checks it.
        self.bindings = SessionBindings()
        # The sessions to tell when the tool list changes: session id -> (tenant, session). A
        # session is kept as it was last seen, in least recently used order, and dropped when a
        # notification to it fails. The SDK ends idle sessions without telling us.
        self._open: OrderedDict[str, tuple[str, ServerSession]] = OrderedDict()

    def principal(self, ctx: Context) -> Principal:
        """Who is calling, as the authentication middleware worked it out from this request's own
        token. Nothing else in the request, a header or an argument, can name a tenant or a user."""
        request = cast("Request | None", ctx.request)
        found = request.scope.get(PRINCIPAL_KEY) if request is not None else None
        if not isinstance(found, Principal):
            raise MCPError(code=types.INTERNAL_ERROR, message="the request carries no principal")
        return found

    async def list_tools(
        self, ctx: Context, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        principal = self.principal(ctx)
        tenant_id = principal.tenant_id
        self._remember(ctx, tenant_id)
        # The registry is asked for this tenant only. A tool of another tenant that came back
        # anyway is not shown (invariant I5).
        tools = [
            t for t in await self.registry.list_for_tenant(tenant_id) if t.tenant_id == tenant_id
        ]
        if self.tool_filter is not None:
            try:
                tools = await self.tool_filter.visible(principal, tools)
            except Exception:
                # A listing that cannot be decided shows nothing. Every call is decided again
                # when it is made, so this hides tools and opens nothing.
                log.exception("tool_list_filter_failed", tenant=tenant_id)
                tools = []
        return types.ListToolsResult(
            tools=[
                types.Tool(name=t.name, description=t.description, input_schema=t.input_schema)
                for t in tools
            ]
        )

    async def call_tool(
        self, ctx: Context, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        principal = self.principal(ctx)
        self._remember(ctx, principal.tenant_id)
        session: SessionState | None = None
        try:
            session = await self._session(ctx, principal)
        except Exception as exc:
            # Flags and taint live in the session. A call that cannot read them does not run, and
            # is still refused through the pipeline so that it leaves its audit record.
            log.error("session_store_failed", error=type(exc).__name__)
        tool = await self.registry.get(principal.tenant_id, params.name)
        if tool is not None and tool.tenant_id != principal.tenant_id:
            tool = None  # as above: another tenant's tool does not exist for this caller
        call = CallContext(
            call_id=new_id(),
            received_at=datetime.now(UTC),
            principal=principal,
            session=session or unbound_session(principal),
            tool=tool or unknown_tool(params.name, principal),
            arguments=params.arguments or {},
        )
        if tool is None:
            shown = params.name[:MAX_NAME_IN_MESSAGE]
            result = await self.pipeline.reject(
                call, Reject(Code.TOOL_NOT_FOUND, f"there is no tool named {shown!r}")
            )
        elif session is None:
            result = await self.pipeline.reject(
                call, Reject(Code.DENIED, "session state is unavailable")
            )
        elif principal_key(session.principal) != principal_key(principal):
            # The middleware has checked this against who opened the session. The stored state
            # says it too, and a call never runs on state that belongs to someone else.
            result = await self.pipeline.reject(
                call, Reject(Code.DENIED, "session belongs to another principal")
            )
        else:
            result = await self.pipeline.run(call)
            await self._save(session)
        return to_call_tool_result(result, call.call_id)

    def _remember(self, ctx: Context, tenant_id: str) -> None:
        request = cast("Request | None", ctx.request)
        session_id = request.headers.get(SESSION_HEADER) if request is not None else None
        if not session_id:
            return
        self._open[session_id] = (tenant_id, ctx.session)
        self._open.move_to_end(session_id)
        while len(self._open) > MAX_OPEN_SESSIONS:
            self._open.popitem(last=False)

    async def notify_tools_changed(self, tenant_id: str) -> None:
        """Send `notifications/tools/list_changed` to every open session of the tenant. It reaches
        a client that holds the standalone GET stream open; one that does not hears nothing and
        finds out at its next `tools/list`."""
        targets = [(sid, s) for sid, (tenant, s) in self._open.items() if tenant == tenant_id]

        async def tell(session_id: str, session: ServerSession) -> None:
            try:
                with anyio.fail_after(NOTIFY_TIMEOUT_S):
                    await session.send_tool_list_changed()
            except Exception as exc:
                self._open.pop(session_id, None)
                log.debug("list_changed_not_sent", error=type(exc).__name__)

        async with anyio.create_task_group() as group:
            for session_id, session in targets:
                group.start_soon(tell, session_id, session)

    async def _save(self, session: SessionState) -> None:
        """Write the session back after a call. A failure is logged and does not undo the call."""
        if session.session_id.startswith(UNBOUND_PREFIX):
            return
        try:
            await self.sessions.save(session)
        except Exception as exc:
            log.error("session_not_saved", error=type(exc).__name__)

    async def _session(self, ctx: Context, principal: Principal) -> SessionState:
        # ctx.request is typed Any in the SDK. On HTTP it is the Starlette request.
        request = cast("Request | None", ctx.request)
        session_id = request.headers.get(SESSION_HEADER) if request is not None else None
        if not session_id:
            return unbound_session(principal)
        return await self.sessions.get(session_id) or await self.sessions.create(
            session_id, principal
        )


def unbound_session(principal: Principal) -> SessionState:
    """State for a request that names no session. It is never stored."""
    return SessionState(
        session_id=f"{UNBOUND_PREFIX}{new_id()}", principal=principal, created_at=datetime.now(UTC)
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


def result_meta(result: ToolResult, call_id: str) -> dict[str, Any]:
    meta: dict[str, Any] = {CALL_ID_KEY: call_id}
    # Only a result Keystone wrote itself counts. A text block from an upstream can carry any
    # _meta, including keys that look like a rejection.
    if isinstance(result, RejectionResult):
        meta |= {k: v for k, v in result.meta.items() if k.startswith(KEYSTONE_META_PREFIX)}
        meta[CALL_ID_KEY] = call_id
    return meta


def to_call_tool_result(result: ToolResult, call_id: str) -> types.CallToolResult:
    """The wire form. The result-level _meta is Keystone's own, never the upstream's, and it
    names the call so an agent can quote it to whoever reads the audit log. A rejection adds its
    `keystone/*` keys (the code, and any reason) so a client need not dig into the text block."""
    meta = result_meta(result, call_id)
    try:
        return types.CallToolResult.model_validate(
            {
                "content": result.content,
                "structuredContent": result.structured_content,
                "isError": result.is_error,
                "_meta": meta,
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
        return types.CallToolResult.model_validate(
            {
                "content": refusal.content,
                "isError": True,
                "_meta": result_meta(refusal, call_id),
            }
        )


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


class KeystoneServer(Server[Any]):
    """The low-level server, with `tools.listChanged` advertised: the gateway sends
    `notifications/tools/list_changed` when a sync changes what a tenant can see. The session
    manager builds the `initialize` result by calling this method, so the override is the only
    place to turn the capability on."""

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
        extensions: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        return super().create_initialization_options(
            notification_options or NotificationOptions(tools_changed=True),
            experimental_capabilities,
            extensions,
        )


def build_server(gateway: Gateway) -> Server[Any]:
    server: Server[Any] = KeystoneServer(
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


def mount_mcp(
    app: FastAPI, gateway: Gateway, authenticator: Authenticator
) -> StreamableHTTPSessionManager:
    """Serve /mcp behind authentication. The caller runs the returned manager inside the app's
    lifespan, and builds a new manager for every app, because run() works once per instance
    (engineering note 2)."""
    security = transport_security(gateway.settings)
    manager = StreamableHTTPSessionManager(app=build_server(gateway), security_settings=security)
    endpoint = McpAuthMiddleware(
        StreamableHTTPASGIApp(manager),
        authenticator=authenticator,
        bindings=gateway.bindings,
        sessions=lambda: gateway.sessions,
        security=TransportSecurityMiddleware(security),
    )
    # A Route, not a Mount: a Mount redirects /mcp to /mcp/.
    app.router.routes.append(Route("/mcp", endpoint=endpoint))
    return manager
