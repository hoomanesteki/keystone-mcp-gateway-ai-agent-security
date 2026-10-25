"""Authentication for /mcp, and the binding of a session to the principal that opened it (KS-304).

Every request to /mcp passes through `McpAuthMiddleware` before the MCP SDK sees it:

1. The Host and Origin headers are checked, as the SDK would, so a request from a page on another
   site is refused before anything else is done with it.
2. The bearer token becomes a principal, or the request is refused: 401 with a pointer to the
   sign-in metadata, 403 for an agent that may not connect, 503 when the identity provider's keys
   cannot be fetched.
3. A request that names an MCP session must come from the principal that opened it. The binding
   is made when the session is created, from the response to `initialize`, which is the first
   place the session id exists. A different principal gets 403, and a session id nobody bound
   gets 404, which tells a client to start a new session.

The principal travels in the ASGI scope, which the SDK hands to the handlers unchanged
(docs/spikes/mcp-proxy.md, question 2). The principal of each call comes from that request's own
token, so a refreshed token with new groups takes effect at once. Only the tenant, the user and
the agent must stay the same for the life of a session.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable
from enum import StrEnum
from typing import TYPE_CHECKING

import anyio
import structlog
from mcp.server.transport_security import TransportSecurityMiddleware
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from keystone.core.types import Principal
from keystone.identity.jwt import AuthError, Forbidden, KeysUnavailable, Reason, TokenValidator
from keystone.identity.metadata import metadata_url, public_origin
from keystone.identity.principals import principal_from_claims
from keystone.settings import Settings

if TYPE_CHECKING:
    from keystone.gateway.sessions import SessionStore

log = structlog.get_logger()

PRINCIPAL_KEY = "keystone.principal"
SESSION_HEADER = "mcp-session-id"
MAX_BOUND_SESSIONS = 10_000
STORE_TIMEOUT_S = 5.0
RETRY_AFTER_S = "5"
# RFC 6750 section 2.1: the scheme is case-insensitive and the credentials are token68.
BEARER = re.compile(r"(?i:bearer) +([A-Za-z0-9\-._~+/]+=*)")


class AuthConfigError(ValueError):
    """The authentication settings cannot work. The message names every problem."""


def check_auth_settings(settings: Settings) -> None:
    problems: list[str] = []
    if settings.auth.mode == "oidc":
        if not settings.oidc_issuer:
            problems.append(
                "auth.mode is oidc, so oidc_issuer (KEYSTONE_OIDC_ISSUER) must be set; "
                "for local work without sign-in set auth.mode to none"
            )
        if settings.env == "prod":
            for name in ("oidc_issuer", "oidc_discovery_url", "public_base_url"):
                value = getattr(settings, name)
                if value and not value.startswith("https://"):
                    problems.append(f"{name} must be an https URL when env is prod")
    if problems:
        raise AuthConfigError("; ".join(problems))


def bearer_token(headers: Headers) -> str:
    values = headers.getlist("authorization")
    if not values:
        raise AuthError(Reason.NO_CREDENTIALS)
    match = BEARER.fullmatch(values[0]) if len(values) == 1 else None
    if match is None:
        raise AuthError(Reason.MALFORMED)
    return match.group(1)


class Authenticator:
    """Turns the headers of a request into a Principal, or raises AuthError."""

    def __init__(self, settings: Settings) -> None:
        check_auth_settings(settings)
        self.settings = settings
        self.validator: TokenValidator | None = None
        if settings.auth.mode == "oidc" and settings.oidc_issuer:
            self.validator = TokenValidator(
                settings.oidc_issuer,
                settings.oidc_audience,
                discovery_url=settings.oidc_discovery_url,
                max_age_s=settings.oidc_jwks_max_age_s,
            )

    async def principal(self, headers: Headers) -> Principal:
        return await self._principal(
            headers, allow_unknown_agents=self.settings.auth.allow_unknown_agents
        )

    async def admin_principal(self, headers: Headers) -> Principal:
        """The caller of an admin route. The token is checked exactly as for /mcp, but the caller
        need not be a listed agent: the admin CLI and the console are not agents. What lets a
        caller in is the `admin` role, which the route checks."""
        return await self._principal(headers, allow_unknown_agents=True)

    async def _principal(self, headers: Headers, *, allow_unknown_agents: bool) -> Principal:
        if self.settings.auth.mode == "none":
            if self.settings.dev_principal is None:
                raise AuthError(Reason.NO_CREDENTIALS)
            return self.settings.dev_principal
        if self.validator is None:
            raise KeysUnavailable
        claims = await self.validator.validate(bearer_token(headers))
        principal = principal_from_claims(
            claims, self.settings.agents, allow_unknown_agents=allow_unknown_agents
        )
        if principal.tenant_id not in {tenant.id for tenant in self.settings.tenants}:
            # A sound token from an identity provider that serves other tenants too. Keystone
            # has nothing for this one, and would only create sessions and rows for it.
            raise Forbidden(Reason.UNKNOWN_TENANT)
        return principal


PrincipalKey = tuple[str, str, str]


def principal_key(principal: Principal) -> PrincipalKey:
    """What must stay the same for the life of a session: tenant, user and agent."""
    return (principal.tenant_id, principal.user_id, principal.agent_id)


class Verdict(StrEnum):
    SAME = "same"
    DIFFERENT = "different"
    UNKNOWN = "unknown"


class SessionBindings:
    """Who opened each session. Held in this process, because the SDK's sessions are held here
    too: a session id this process did not create is answered with 404 by the SDK anyway. It is
    bounded, and the oldest binding is dropped first. Redis holds the session state; whether a
    request may use a session does not depend on Redis being up."""

    def __init__(self, max_sessions: int = MAX_BOUND_SESSIONS) -> None:
        self._max = max_sessions
        self._bound: OrderedDict[str, PrincipalKey] = OrderedDict()

    def bind(self, session_id: str, principal: Principal) -> None:
        self._bound[session_id] = principal_key(principal)
        self._bound.move_to_end(session_id)
        while len(self._bound) > self._max:
            self._bound.popitem(last=False)

    def verdict(self, session_id: str, principal: Principal) -> Verdict:
        bound = self._bound.get(session_id)
        if bound is None:
            return Verdict.UNKNOWN
        self._bound.move_to_end(session_id)
        return Verdict.SAME if bound == principal_key(principal) else Verdict.DIFFERENT

    def forget(self, session_id: str) -> None:
        self._bound.pop(session_id, None)


def auth_refusal(request: Request, error: AuthError, settings: Settings) -> Response:
    """The HTTP answer to a request that could not be tied to a principal: 401 with a pointer to
    the sign-in metadata, 403, or 503 when the identity provider's keys cannot be fetched. The
    MCP endpoint and the admin API answer in the same words."""
    reason = error.reason.value
    if isinstance(error, KeysUnavailable):
        log.error("auth_unavailable", reason=reason)
        return JSONResponse(
            {"error": "temporarily_unavailable", "reason": reason},
            status_code=503,
            headers={"Retry-After": RETRY_AFTER_S},
        )
    if error.status == 403:
        log.info("auth_refused", status=403, reason=reason)
        return JSONResponse({"error": "forbidden", "reason": reason}, status_code=403)
    origin = public_origin(request, settings.public_base_url)
    challenge = f'Bearer resource_metadata="{metadata_url(origin)}"'
    no_token = error.reason is Reason.NO_CREDENTIALS
    if not no_token:
        log.info("auth_refused", status=401, reason=reason)
    body = {"error": "unauthorized" if no_token else "invalid_token", "reason": reason}
    return JSONResponse(body, status_code=401, headers={"WWW-Authenticate": challenge})


def _response_header(message: Message, name: bytes) -> str | None:
    for key, value in message.get("headers", []):
        if key.lower() == name:
            return str(value.decode("latin-1"))
    return None


class McpAuthMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        authenticator: Authenticator,
        bindings: SessionBindings,
        sessions: Callable[[], SessionStore],
        security: TransportSecurityMiddleware,
    ) -> None:
        self.app = app
        self.authenticator = authenticator
        self.bindings = bindings
        # A callable, so a store swapped in after startup (a test does) is the one used.
        self.sessions = sessions
        self.security = security

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        blocked = await self.security.validate_request(request, is_post=False)
        if blocked is not None:
            await blocked(scope, receive, send)
            return
        try:
            principal = await self.authenticator.principal(request.headers)
        except AuthError as error:
            await self._refusal(request, error)(scope, receive, send)
            return
        scope[PRINCIPAL_KEY] = principal

        session_id = request.headers.get(SESSION_HEADER)
        if session_id is None:
            await self.app(scope, receive, self._bind_new_session(send, principal))
            return
        verdict = self.bindings.verdict(session_id, principal)
        if verdict is Verdict.UNKNOWN:
            await _session_refusal(404, "Session not found")(scope, receive, send)
        elif verdict is Verdict.DIFFERENT:
            log.warning("session_binding_mismatch", user=principal.user_id, session=session_id[:8])
            await _session_refusal(403, "session belongs to another principal")(
                scope, receive, send
            )
        else:
            if request.method == "DELETE":
                send = self._forget_when_ended(send, session_id)
            await self.app(scope, receive, send)

    def _refusal(self, request: Request, error: AuthError) -> Response:
        return auth_refusal(request, error, self.authenticator.settings)

    def _bind_new_session(self, send: Send, principal: Principal) -> Send:
        """Bind the session the SDK creates for this request, before the client can learn its id.
        A request without a session id either opens one (its response carries the new id in
        `Mcp-Session-Id`) or is refused, and a refusal binds nothing."""

        async def bind(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] < 400:
                session_id = _response_header(message, SESSION_HEADER.encode())
                if session_id:
                    await self._bind(session_id, principal)
            await send(message)

        return bind

    async def _bind(self, session_id: str, principal: Principal) -> None:
        self.bindings.bind(session_id, principal)
        try:
            with anyio.fail_after(STORE_TIMEOUT_S):
                await self.sessions().create(session_id, principal)
        except Exception as exc:
            # The binding above is what keeps the session safe. A call that finds no stored state
            # is refused through the pipeline, and audited, as before.
            log.error("session_not_stored", error=type(exc).__name__)

    def _forget_when_ended(self, send: Send, session_id: str) -> Send:
        async def forget(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] < 300:
                self.bindings.forget(session_id)
            await send(message)

        return forget


def _session_refusal(status: int, message: str) -> Response:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": message}},
        status_code=status,
    )
