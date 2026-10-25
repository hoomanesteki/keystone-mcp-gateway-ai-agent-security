"""The LLM passthrough (KS-806, ADR-0016): a model request with the identity, the budget and the
tracing of a tool call.

An agent points its SDK at Keystone instead of at the provider, and uses its Keystone token as the
API key:

    ANTHROPIC_BASE_URL=http://keystone:8080/llm/anthropic   (the SDK adds /v1/messages)
    OPENAI_BASE_URL=http://keystone:8080/llm/openai/v1      (the SDK adds /chat/completions)

For each request the proxy

1. checks the token as /mcp does (`Authorization: Bearer`, or `x-api-key`, which is where the
   Anthropic SDK puts its key). The caller must belong to the tenant that owns the provider keys,
   `llm_proxy.tenant`. No policy decides which agent may call a model: any agent of that tenant
   that can sign in may, within its budgets.
2. reads the body (at most `max_body_bytes`) and finds the model in the price list. A model with no
   price is refused with 400, unless `allow_unpriced` lets it through at no cost.
3. stops the request with 402 when its estimated cost would take a budget over its limit. The
   estimate is the body at four bytes a token as input plus `max_tokens` of output, and the request
   is not sent to the provider. A budget service that cannot be read stops it too (503).
4. sends the body on with a fixed set of headers and the provider's key from the vault, which the
   caller never sees. An OpenAI stream is asked to report its usage (`include_usage`), because
   the cost is made from the provider's own count.
5. hands the answer back as it arrives. A stream goes through byte for byte; the proxy reads the
   usage out of the events as they pass and changes nothing.
6. books what the request cost: one `kind="llm"` row in the ledger, the tokens on the metric, the
   spend on the linked session, and the final attributes of the span. All of it is written before
   the last byte of the answer is sent, so a client that has the whole answer can ask what it cost.

The cost is booked from what is known. A stream that ends without usage, or that is cut, is booked
for the tokens that were counted so far, and a warning is logged. The budget check is not a
reservation: requests that are in flight together can overshoot a limit by what they cost.

A provider's error goes back with its status and its body, minus the key if the provider repeated
it. Keystone's own refusals use `{"error": {"type": "keystone", "code": ...}}`.

What the proxy does not do: it is not rate limited, it writes no `audit_events` row (the ledger and
the span are its record), and it forwards no header of the caller beyond a short list.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Protocol

import anyio
import httpx2
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import SecretStr
from starlette.datastructures import Headers
from starlette.types import Send

from keystone import __version__
from keystone.core.errors import Code
from keystone.core.ids import new_id
from keystone.core.types import Principal
from keystone.gateway.interceptors.budget import WHOSE, when
from keystone.gateway.sessions import SessionStore
from keystone.identity.jwt import AuthError
from keystone.identity.middleware import auth_refusal, principal_key
from keystone.identity.vault import Vault
from keystone.logging import register_secret
from keystone.metering.budgets import BudgetExceeded, money, plain, usd
from keystone.metering.ledger import LedgerEntry
from keystone.metering.llm_usage import BodyUsage, Provider, StreamUsage, UsageReader
from keystone.metering.pricing import ModelPrice, PriceList, cost, estimate
from keystone.registry.repo import UpstreamRepo
from keystone.settings import LlmProxySettings, Settings
from keystone.telemetry.metrics import UNPRICED, Metrics
from keystone.telemetry.tracing import NoopTracer, OpenSpan, Tracer, user_hash

log = structlog.get_logger()

PROVIDERS: tuple[Provider, ...] = ("anthropic", "openai")
# Where the provider's API is, below the base URL. The proxy builds the URL: a caller picks neither
# the host nor the path.
PATHS: dict[Provider, str] = {
    "anthropic": "/v1/messages",
    "openai": "/v1/chat/completions",
}
# The pseudo-upstreams that hold the provider keys (registry/naming.py reserves the ids).
UPSTREAM_IDS: dict[Provider, str] = {"anthropic": "llm_anthropic", "openai": "llm_openai"}
SESSION_HEADER = "x-keystone-session"
REQUEST_ID_HEADER = "x-keystone-request-id"

# The headers of the caller that are sent on. Everything else, the token and the cookies included,
# stays here. `anthropic-version` and `anthropic-beta` are how the Anthropic SDK picks what it
# speaks; `accept` is how a stream is asked for.
FORWARDED_REQUEST_HEADERS = ("accept", "anthropic-version", "anthropic-beta")
# The headers of the provider's answer that are sent back. The rate limit headers of a provider
# describe the account all agents share, and are left out.
PASSED_RESPONSE_HEADERS = ("content-type", "cache-control", "retry-after", "request-id")
MAX_HEADER_CHARS = 256
MAX_MODEL_CHARS = 200
# The most output a request is assumed to ask for. A larger number only makes the estimate larger
# than any budget, and an absurd one must not grow the sums.
MAX_ASKED_TOKENS = 10_000_000
MAX_CHOICES = 128
# An error body is read whole, to take the key out of it, and no more than this.
MAX_ERROR_BODY_BYTES = 1024 * 1024
CONNECT_TIMEOUT_S = 10.0
# A request waits this long for a free connection to the provider before it is told to try again.
POOL_TIMEOUT_S = 10.0
MAX_CONNECTIONS = 200
MAX_KEEPALIVE = 50
# How long the rest of an answer is read for when its caller has left (see `read_the_rest`).
DRAIN_S = 5.0
MIN_SECRET_CHARS = 8
REDACTED = b"[redacted]"
# How an answer ended: all of it was sent, the provider's stream broke, or the caller went away.
COMPLETE = "complete"
CUT = "cut"
CLIENT_GONE = "client_gone"


class LlmCode(StrEnum):
    UNAUTHORIZED = "KS_UNAUTHORIZED"
    FORBIDDEN = "KS_FORBIDDEN"
    DENIED = Code.DENIED.value
    INVALID_REQUEST = "KS_INVALID_REQUEST"
    TOO_LARGE = "KS_REQUEST_TOO_LARGE"
    MODEL_NOT_PRICED = "KS_MODEL_NOT_PRICED"
    BUDGET_EXCEEDED = Code.BUDGET_EXCEEDED.value
    SESSION_NOT_FOUND = "KS_SESSION_NOT_FOUND"
    SESSION_MISMATCH = "KS_SESSION_MISMATCH"
    KEY_MISSING = "KS_PROVIDER_KEY_MISSING"
    UPSTREAM_ERROR = Code.UPSTREAM_ERROR.value
    UPSTREAM_TIMEOUT = Code.UPSTREAM_TIMEOUT.value
    UNAVAILABLE = "KS_UNAVAILABLE"
    INTERNAL = "KS_INTERNAL_ERROR"


class Refusal(Exception):
    """Keystone's own answer to a request. `failed` is False for a request that was refused and
    True for one that could not be served; both are answered the same way."""

    def __init__(
        self,
        status: int,
        code: LlmCode,
        message: str,
        facts: Mapping[str, Any] | None = None,
        *,
        failed: bool = False,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.facts = dict(facts or {})
        self.failed = failed
        self.headers = dict(headers or {})


class StreamBroken(Exception):
    """The provider's stream ended in an error after the answer had begun. Raising it is how the
    response is cut short, so that the caller sees an error and not a stream that looks finished."""


class Authenticating(Protocol):
    async def principal(self, headers: Headers) -> Principal: ...


class KeyVault(Protocol):
    async def service_headers(self, tenant_id: str, upstream_id: str) -> dict[str, SecretStr]: ...


class Spending(Protocol):
    async def check(self, principal: Principal, cost: float | Decimal) -> None: ...

    async def record(self, entry: LedgerEntry) -> bool: ...


@dataclass(frozen=True)
class Route:
    name: Provider
    upstream_id: str
    path: str
    base_url: str
    api_key_env: str | None

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"


@dataclass(frozen=True)
class Parsed:
    """What the proxy needs to know of a request body."""

    payload: dict[str, Any]
    model: str
    stream: bool
    # The most tokens of output the request may ask for, counting each answer it asks for.
    max_output: int


@dataclass
class Call:
    """One request, from its arrival to the booking of its cost."""

    id: str
    route: Route
    principal: Principal
    received_at: datetime
    began: float
    span: OpenSpan
    model: str = ""
    price: ModelPrice | None = None
    price_label: str = UNPRICED
    session_id: str | None = None
    stream: bool = False
    # What must not appear in an answer: the provider's key, as sent and bare.
    secrets: tuple[str, ...] = ()
    # Set once the answer is handed to a Relay, which then ends the span.
    relaying: bool = False
    settled: bool = field(default=False, repr=False)


@dataclass
class Answer:
    """The provider's answer on its way back. `chunks` is the one iterator over its bytes: the
    relay reads it, and a reader that comes late carries on from where the relay stopped, because
    a response cannot be iterated twice."""

    upstream: httpx2.Response
    chunks: AsyncIterator[bytes]
    reader: UsageReader


# -- reading the request


def asked_tokens(provider: Provider, payload: Mapping[str, Any], default: int) -> int:
    keys = ("max_tokens",) if provider == "anthropic" else ("max_completion_tokens", "max_tokens")
    for key in keys:
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return min(value, MAX_ASKED_TOKENS)
    return default


def parse_request(provider: Provider, body: bytes, default_max_tokens: int) -> Parsed:
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError):
        raise Refusal(400, LlmCode.INVALID_REQUEST, "the body is not valid JSON") from None
    if not isinstance(payload, dict):
        raise Refusal(400, LlmCode.INVALID_REQUEST, "the body must be a JSON object")
    model = payload.get("model")
    if not isinstance(model, str) or not model.strip() or len(model) > MAX_MODEL_CHARS:
        raise Refusal(
            400,
            LlmCode.INVALID_REQUEST,
            f"model must be a model name of up to {MAX_MODEL_CHARS} characters",
        )
    stream = payload.get("stream")
    if stream is not None and not isinstance(stream, bool):
        raise Refusal(400, LlmCode.INVALID_REQUEST, "stream must be true or false")
    choices = payload.get("n") if provider == "openai" else None
    answers = choices if isinstance(choices, int) and 1 <= choices <= MAX_CHOICES else 1
    return Parsed(
        payload=payload,
        model=model,
        stream=bool(stream),
        max_output=asked_tokens(provider, payload, default_max_tokens) * answers,
    )


def with_usage_reported(payload: Mapping[str, Any]) -> bytes | None:
    """The body of an OpenAI stream request with `stream_options.include_usage` on, or None when
    it is on already. Without it OpenAI never says what a stream used."""
    options = payload.get("stream_options")
    if isinstance(options, Mapping) and options.get("include_usage") is True:
        return None
    merged = (
        {**options, "include_usage": True}
        if isinstance(options, Mapping)
        else {"include_usage": True}
    )
    return json.dumps({**payload, "stream_options": merged}, separators=(",", ":")).encode()


def printable(value: str) -> bool:
    return 0 < len(value) <= MAX_HEADER_CHARS and value.isascii() and value.isprintable()


def forward_headers(incoming: Mapping[str, str]) -> dict[str, str]:
    """The headers of the request to the provider, apart from its key. `identity` keeps the answer
    uncompressed, so that the bytes that pass are the bytes the usage is read from."""
    headers = {
        "content-type": "application/json",
        "accept-encoding": "identity",
        "user-agent": f"keystone/{__version__}",
    }
    for name in FORWARDED_REQUEST_HEADERS:
        value = incoming.get(name)
        if value is not None and printable(value):
            headers[name] = value
    return headers


def key_headers(provider: Provider, key: str) -> dict[str, str]:
    """How each provider wants its key: the header the vault stores it under."""
    return {"x-api-key": key} if provider == "anthropic" else {"Authorization": f"Bearer {key}"}


def secrets_of(headers: Mapping[str, str]) -> tuple[str, ...]:
    """The strings that must never leave: each header value, and the token inside an
    `Authorization: Bearer` one. All are registered with the log scrubber, which matches whole
    values, so the bare token needs its own entry."""
    found: list[str] = []
    for value in headers.values():
        found.append(value)
        scheme, _, token = value.partition(" ")
        if scheme.lower() == "bearer" and token:
            found.append(token.strip())
    wanted = tuple(dict.fromkeys(s for s in found if len(s) >= MIN_SECRET_CHARS))
    for secret in wanted:
        register_secret(secret)
    return wanted


def scrub(data: bytes, secrets: tuple[str, ...]) -> bytes:
    for secret in secrets:
        data = data.replace(secret.encode(), REDACTED)
    return data


def passed_headers(headers: httpx2.Headers, secrets: tuple[str, ...]) -> dict[str, str]:
    kept: dict[str, str] = {}
    for name in PASSED_RESPONSE_HEADERS:
        value = headers.get(name)
        if value is not None and printable(value):
            kept[name] = scrub(value.encode(), secrets).decode()
    return kept


def keystone_error(refusal: Refusal, request_id: str) -> JSONResponse:
    # The facts go first, so that none of them can replace the type, the code or the message.
    body = {
        "error": {
            **refusal.facts,
            "type": "keystone",
            "code": refusal.code.value,
            "message": refusal.message,
        }
    }
    return JSONResponse(
        body,
        status_code=refusal.status,
        headers={**refusal.headers, REQUEST_ID_HEADER: request_id},
    )


async def read_the_rest(answer: Answer) -> str:
    """The caller left before it had all of an answer that is not a stream. The provider finished
    that answer before it sent the first byte, and charges for it, so the rest is read to learn the
    cost; a caller that hangs up would otherwise not be charged. A stream is not read on: the
    provider is still generating it, and stopping is what keeps the cost down. Returns how the
    answer ended."""
    finished = False
    with anyio.move_on_after(DRAIN_S):
        try:
            async for chunk in answer.chunks:
                answer.reader.feed(chunk)
            finished = True
        except Exception:  # noqa: S110 - the provider's connection broke; book what was read
            pass
    return COMPLETE if finished else CLIENT_GONE


# -- the response that carries an answer back


class Relay(StreamingResponse):
    """A streamed answer that is booked however it ends. Starlette's own response does not close
    the iterator when the client goes away or the response cannot begin, so the booking is also
    made here, once, from the `finally` of the one place every ending passes through."""

    def __init__(
        self,
        content: AsyncIterator[bytes],
        *,
        status_code: int,
        headers: Mapping[str, str],
        settle: Callable[[str], Awaitable[None]],
    ) -> None:
        super().__init__(content, status_code=status_code, headers=headers)
        self._settle = settle

    async def stream_response(self, send: Send) -> None:
        try:
            await super().stream_response(send)
        finally:
            await self._settle(CLIENT_GONE)


class LlmProxy:
    def __init__(
        self,
        settings: Settings,
        *,
        authenticator: Authenticating,
        vault: KeyVault,
        budgets: Spending,
        sessions: SessionStore | None,
        prices: PriceList,
        metrics: Metrics | None = None,
        tracer: Tracer | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        config = settings.llm_proxy
        if config.tenant is None:
            raise ValueError("llm_proxy.tenant must be set")
        self._settings = settings
        self._config: LlmProxySettings = config
        self._tenant = config.tenant
        self._authenticator = authenticator
        self._vault = vault
        self._budgets = budgets
        self._sessions = sessions
        self._prices = prices
        self._metrics = metrics
        self._tracer: Tracer = tracer or NoopTracer()
        self._now = now
        self._routes = {
            "anthropic": Route(
                "anthropic",
                UPSTREAM_IDS["anthropic"],
                PATHS["anthropic"],
                config.anthropic.base_url,
                config.anthropic.api_key_env,
            ),
            "openai": Route(
                "openai",
                UPSTREAM_IDS["openai"],
                PATHS["openai"],
                config.openai.base_url,
                config.openai.api_key_env,
            ),
        }
        self._owns_client = client is None
        self._client = client or httpx2.AsyncClient(
            timeout=httpx2.Timeout(
                config.timeout_s, connect=CONNECT_TIMEOUT_S, pool=POOL_TIMEOUT_S
            ),
            limits=httpx2.Limits(
                max_connections=MAX_CONNECTIONS, max_keepalive_connections=MAX_KEEPALIVE
            ),
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- one request

    async def handle(self, provider: Provider, request: Request) -> Response:
        route = self._routes[provider]
        request_id = new_id()
        received_at = self._now()
        began = time.monotonic()
        try:
            principal = await self._principal(request)
        except AuthError as error:
            # The same statuses and challenge as /mcp; the body is in this proxy's shape.
            return self._auth_refusal(request, error, request_id)
        span = self._tracer.open_span(
            "keystone.llm_call",
            {
                "gen_ai.operation.name": "chat",
                "gen_ai.system": provider,
                "keystone.tenant": principal.tenant_id,
                "keystone.agent": principal.agent_id,
                "keystone.user_hash": user_hash(principal.user_id),
                "keystone.request_id": request_id,
            },
            kind="server",
            incoming=request.headers,
        )
        call = Call(request_id, route, principal, received_at, began, span)
        try:
            response = await self._serve(call, request)
        except Refusal as refusal:
            response = self._refused(call, refusal)
        except BaseException:
            # A request that was dropped (the client left, the server is stopping) or a fault in
            # Keystone. The span ends either way, and an exception is not recorded on it.
            span.fail("the request did not finish")
            span.set("keystone.outcome", "error")
            span.end()
            raise
        if not call.relaying:
            span.end()
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    async def _principal(self, request: Request) -> Principal:
        headers = request.headers
        if "authorization" not in headers and "x-api-key" in headers:
            # The Anthropic SDK sends its key in x-api-key: the Keystone token goes there as well.
            headers = Headers({"authorization": f"Bearer {headers['x-api-key']}"})
        return await self._authenticator.principal(headers)

    def _auth_refusal(self, request: Request, error: AuthError, request_id: str) -> Response:
        answer = auth_refusal(request, error, self._settings)
        code = {
            401: LlmCode.UNAUTHORIZED,
            403: LlmCode.FORBIDDEN,
            503: LlmCode.UNAVAILABLE,
        }.get(answer.status_code, LlmCode.UNAUTHORIZED)
        message = {
            LlmCode.UNAUTHORIZED: "send a Keystone token as the bearer token or as x-api-key",
            LlmCode.FORBIDDEN: "this token may not use Keystone",
            LlmCode.UNAVAILABLE: "tokens cannot be checked right now",
        }[code]
        kept = {
            name: value
            for name, value in answer.headers.items()
            if name.lower() in ("www-authenticate", "retry-after")
        }
        refusal = Refusal(
            answer.status_code, code, message, {"reason": error.reason.value}, headers=kept
        )
        return keystone_error(refusal, request_id)

    async def _serve(self, call: Call, request: Request) -> Response:
        if call.principal.tenant_id != self._tenant:
            raise Refusal(403, LlmCode.DENIED, "the LLM proxy does not serve this tenant")
        body = await self._read_body(request)
        parsed = parse_request(call.route.name, body, self._config.default_max_tokens)
        call.model, call.stream = parsed.model, parsed.stream
        call.span.set("gen_ai.request.model", parsed.model)
        call.span.set("keystone.llm.stream", parsed.stream)
        call.price, call.price_label = self._price(parsed.model)
        if call.price is None:
            log.warning(
                "llm_model_unpriced",
                request_id=call.id,
                provider=call.route.name,
                model=parsed.model,
                tenant=call.principal.tenant_id,
            )
        call.session_id = await self._linked_session(request, call.principal)
        if call.price is not None:
            await self._check_budget(
                call.principal, estimate(call.price, len(body), parsed.max_output)
            )
        sent = {**forward_headers(request.headers), **await self._provider_key(call)}
        content = body
        if call.route.name == "openai" and parsed.stream:
            content = with_usage_reported(parsed.payload) or body
        return await self._forward(call, sent, content)

    async def _read_body(self, request: Request) -> bytes:
        limit = self._config.max_body_bytes
        too_large = Refusal(
            413, LlmCode.TOO_LARGE, f"the request body is over the limit of {limit} bytes"
        )
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            raise too_large
        encoding = request.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise Refusal(415, LlmCode.INVALID_REQUEST, "send the body without a content-encoding")
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > limit:
                raise too_large
        return bytes(body)

    def _price(self, model: str) -> tuple[ModelPrice | None, str]:
        found = self._prices.match(model)
        if found is not None:
            return found[1], found[0]
        if self._config.allow_unpriced:
            return None, UNPRICED
        raise Refusal(
            400,
            LlmCode.MODEL_NOT_PRICED,
            f"the model {model!r} has no price in the pricing file, so Keystone cannot "
            "cost it and does not forward it",
        )

    async def _linked_session(self, request: Request, principal: Principal) -> str | None:
        """The session named by X-Keystone-Session, which must be this caller's own."""
        named = request.headers.get(SESSION_HEADER)
        if named is None:
            return None
        session_id = named.strip()
        if self._sessions is None:
            return None
        try:
            state = await self._sessions.get(session_id) if printable(session_id) else None
        except Exception as error:
            log.error("llm_session_lookup_failed", error=type(error).__name__)
            raise Refusal(
                503,
                LlmCode.UNAVAILABLE,
                "the session could not be read, so the request was not sent",
            ) from None
        if state is None:
            raise Refusal(404, LlmCode.SESSION_NOT_FOUND, "there is no such session")
        if principal_key(state.principal) != principal_key(principal):
            raise Refusal(403, LlmCode.SESSION_MISMATCH, "that session belongs to someone else")
        return session_id

    async def _check_budget(self, principal: Principal, estimated: Decimal) -> None:
        try:
            await self._budgets.check(principal, estimated)
        except BudgetExceeded as exceeded:
            budget = exceeded.budget
            facts = {
                "scope": budget.scope,
                "window": budget.window,
                "limit_usd": float(budget.limit_usd),
                "spent_usd": float(exceeded.spent),
                "estimate_usd": float(estimated),
                "resets_at": when(exceeded.resets_at),
            }
            raise Refusal(
                402,
                LlmCode.BUDGET_EXCEEDED,
                f"the {WHOSE[budget.scope]} budget of {usd(budget.limit_usd)} a {budget.window} "
                f"would be passed by this request, estimated at {usd(estimated)} with "
                f"{usd(exceeded.spent)} spent; it resets at {facts['resets_at']}",
                facts,
            ) from None
        except Exception as error:
            # A budget that cannot be read is not a budget with room in it.
            log.error("llm_budget_check_failed", error=type(error).__name__)
            raise Refusal(
                503,
                LlmCode.UNAVAILABLE,
                "the budget could not be checked, so the request was not sent",
            ) from None

    async def _provider_key(self, call: Call) -> dict[str, str]:
        route = call.route
        try:
            stored = await self._vault.service_headers(self._tenant, route.upstream_id)
        except Exception as error:
            log.error("llm_key_read_failed", provider=route.name, error=type(error).__name__)
            raise Refusal(
                503, LlmCode.UNAVAILABLE, "the provider key could not be read", failed=True
            ) from None
        headers = {name: value.get_secret_value() for name, value in stored.items()}
        if not headers and route.api_key_env is not None:
            log.error("llm_key_missing", provider=route.name, variable=route.api_key_env)
            raise Refusal(
                503,
                LlmCode.KEY_MISSING,
                f"Keystone holds no API key for {route.name}; the owner sets {route.api_key_env} "
                "and restarts, or stores one with `keystone cred set`",
                failed=True,
            )
        call.secrets = secrets_of(headers)
        return headers

    # -- the provider

    async def _forward(self, call: Call, headers: Mapping[str, str], content: bytes) -> Response:
        request = self._client.build_request(
            "POST", call.route.url, content=content, headers=dict(headers)
        )
        try:
            upstream = await self._client.send(request, stream=True)
        except httpx2.PoolTimeout:
            log.warning("llm_provider_busy", request_id=call.id, provider=call.route.name)
            raise Refusal(
                503,
                LlmCode.UNAVAILABLE,
                "too many model requests are in flight; try again in a moment",
                failed=True,
                headers={"retry-after": "1"},
            ) from None
        except httpx2.TimeoutException:
            log.warning("llm_provider_timeout", request_id=call.id, provider=call.route.name)
            raise Refusal(
                504, LlmCode.UPSTREAM_TIMEOUT, "the provider did not answer in time", failed=True
            ) from None
        except httpx2.HTTPError as error:
            log.warning(
                "llm_provider_unreachable",
                request_id=call.id,
                provider=call.route.name,
                error=type(error).__name__,
            )
            raise Refusal(
                502, LlmCode.UPSTREAM_ERROR, "the provider could not be reached", failed=True
            ) from None
        status = upstream.status_code
        if 200 <= status < 300:
            return self._relay(call, upstream)
        return await self._pass_error(call, upstream)

    async def _pass_error(self, call: Call, upstream: httpx2.Response) -> Response:
        """A provider's error goes back as it came, with its status, minus any copy of the key."""
        status = upstream.status_code
        received = bytearray()
        try:
            async for chunk in upstream.aiter_bytes():
                received += chunk
                if len(received) > MAX_ERROR_BODY_BYTES:
                    break
        except httpx2.HTTPError:
            raise Refusal(
                502, LlmCode.UPSTREAM_ERROR, "the provider's error could not be read", failed=True
            ) from None
        finally:
            with anyio.CancelScope(shield=True):
                await upstream.aclose()
        if 300 <= status < 400:
            raise Refusal(
                502, LlmCode.UPSTREAM_ERROR, "the provider answered with a redirect", failed=True
            )
        body = scrub(bytes(received), call.secrets)
        emit = log.warning if status >= 500 else log.info
        emit(
            "llm_provider_error",
            request_id=call.id,
            provider=call.route.name,
            model=call.model,
            status=status,
        )
        call.span.set("keystone.outcome", "error")
        call.span.set("http.response.status_code", status)
        call.span.fail(f"the provider answered {status}")
        return Response(
            body, status_code=status, headers=passed_headers(upstream.headers, call.secrets)
        )

    def _relay(self, call: Call, upstream: httpx2.Response) -> Response:
        sse = upstream.headers.get("content-type", "").lower().startswith("text/event-stream")
        reader: UsageReader = StreamUsage(call.route.name) if sse else BodyUsage(call.route.name)
        answer = Answer(upstream, upstream.aiter_bytes(), reader)
        call.relaying = True

        async def settle(ended: str) -> None:
            await self._settle(call, answer, ended)

        async def whole() -> list[bytes]:
            # The provider finished this answer before it sent the first byte. A caller that leaves
            # makes the server cancel the task that is reading it, and a read cut in the middle
            # closes the connection with the usage unread, so the request is booked without a cost
            # (KS-997). The read is shielded and the answer is handed on from memory.
            chunks: list[bytes] = []
            with anyio.CancelScope(shield=True), anyio.fail_after(DRAIN_S):
                async for chunk in answer.chunks:
                    reader.feed(chunk)
                    chunks.append(chunk)
            return chunks

        async def body() -> AsyncIterator[bytes]:
            try:
                if not sse:
                    held = await whole()
                    await settle(COMPLETE)
                    for chunk in held:
                        yield chunk
                    return
                async for chunk in answer.chunks:
                    reader.feed(chunk)
                    yield chunk
            except (httpx2.HTTPError, TimeoutError):
                await settle(CUT)
                raise StreamBroken from None
            await settle(COMPLETE)

        return Relay(
            body(),
            status_code=upstream.status_code,
            headers=passed_headers(upstream.headers, call.secrets),
            settle=settle,
        )

    # -- the booking

    async def _settle(self, call: Call, answer: Answer, ended: str) -> None:
        """Book the request once, however the answer ended, and end its span. Nothing here raises:
        the answer has gone out, and a fault in the books is logged for an operator to see."""
        if call.settled:
            return
        call.settled = True
        with anyio.CancelScope(shield=True):
            if ended == CLIENT_GONE and isinstance(answer.reader, BodyUsage):
                ended = await read_the_rest(answer)
            with contextlib.suppress(Exception):  # the connection is gone either way
                await answer.upstream.aclose()
            try:
                answer.reader.finish()
                await self._book(call, answer.upstream.status_code, answer.reader, ended)
            except Exception as error:
                log.error(
                    "llm_booking_failed",
                    request_id=call.id,
                    provider=call.route.name,
                    model=call.model,
                    error=type(error).__name__,
                )
            finally:
                call.span.end()

    async def _book(self, call: Call, status: int, reader: UsageReader, ended: str) -> None:
        usage = reader.usage
        spent = (
            cost(call.price, usage) if call.price is not None and usage is not None else money(0)
        )
        principal = call.principal
        span = call.span
        known = usage is not None
        if ended != COMPLETE or not reader.final:
            # What was counted is booked, and the cost may be short of what the provider charged.
            reason = ended if ended != COMPLETE else ("partial_usage" if known else "no_usage")
            log.warning(
                "llm_usage_incomplete",
                request_id=call.id,
                provider=call.route.name,
                model=call.model,
                reason=reason,
                counted=known,
            )
        total_in = usage.total_input if usage is not None else None
        total_out = usage.output_tokens if usage is not None else None
        span.set("http.response.status_code", status)
        span.set("keystone.cost_usd", float(spent))
        span.set(
            "keystone.llm.usage", "final" if reader.final else ("partial" if known else "missing")
        )
        span.set("keystone.llm.ended", ended)
        span.set("keystone.outcome", "ok" if ended == COMPLETE else "error")
        if total_in is not None and total_out is not None:
            span.set("gen_ai.usage.input_tokens", total_in)
            span.set("gen_ai.usage.output_tokens", total_out)
        if ended != COMPLETE:
            span.fail(f"the answer ended early: {ended}")
        log.info(
            "llm_request",
            request_id=call.id,
            provider=call.route.name,
            model=call.model,
            tenant=principal.tenant_id,
            agent=principal.agent_id,
            user=user_hash(principal.user_id),
            stream=call.stream,
            status=status,
            ended=ended,
            input_tokens=total_in,
            output_tokens=total_out,
            cost_usd=plain(spent),
            duration_ms=round((time.monotonic() - call.began) * 1000),
        )
        if usage is not None and self._metrics is not None:
            self._metrics.llm_tokens_used(
                principal.tenant_id,
                call.price_label,
                {
                    "input": usage.input_tokens,
                    "output": usage.output_tokens,
                    "cache_read": usage.cache_read_tokens,
                    "cache_write": usage.cache_write_tokens,
                },
            )
        # The ledger first, then what reads from it, as for a tool call (ADR-0014).
        await self._budgets.record(
            LedgerEntry(
                ts=call.received_at,
                tenant_id=principal.tenant_id,
                user_id=principal.user_id,
                agent_id=principal.agent_id,
                kind="llm",
                ref=call.id,
                cost_usd=spent,
                model=call.model,
                input_tokens=total_in,
                output_tokens=total_out,
            )
        )
        if call.session_id is not None and self._sessions is not None and spent > 0:
            await self._sessions.add_spend(call.session_id, float(spent))

    def _refused(self, call: Call, refusal: Refusal) -> Response:
        span = call.span
        span.set("keystone.outcome", "error" if refusal.failed else "rejected")
        span.set("keystone.reject_code", refusal.code.value)
        span.set("http.response.status_code", refusal.status)
        if refusal.failed:
            span.fail(refusal.code.value)
        log.info(
            "llm_refused",
            request_id=call.id,
            provider=call.route.name,
            model=call.model or None,
            tenant=call.principal.tenant_id,
            agent=call.principal.agent_id,
            code=refusal.code.value,
            status=refusal.status,
        )
        return keystone_error(refusal, call.id)


def mount_llm_proxy(app: FastAPI, proxy: LlmProxy) -> None:
    """The two routes. They are not part of the app's OpenAPI document: the app has none, and the
    request and response are the providers' own."""

    def add(provider: Provider) -> None:
        async def endpoint(request: Request) -> Response:
            return await proxy.handle(provider, request)

        app.add_api_route(
            f"/llm/{provider}{PATHS[provider]}",
            endpoint,
            methods=["POST"],
            include_in_schema=False,
            name=f"llm_{provider}",
        )

    for provider in PROVIDERS:
        add(provider)


async def seed_provider_keys(
    config: LlmProxySettings, repo: UpstreamRepo, vault: Vault, environ: Mapping[str, str]
) -> list[str]:
    """Make the rows that the provider keys belong to, and store the keys the environment holds.

    Each provider is a pseudo-upstream (`llm_anthropic`, `llm_openai`) with a static credential,
    which is how the vault already keeps what Keystone sends on a caller's behalf. The key is read
    from the variable the config names and goes in through the same code as `keystone cred set`. A
    variable that is not set leaves the stored key as it is, so a key stored by hand stays. Returns
    the providers whose key it wrote. Call it after the tenant rows exist."""
    if config.tenant is None:
        raise ValueError("llm_proxy.tenant must be set")
    written: list[str] = []
    for provider in PROVIDERS:
        settings = getattr(config, provider)
        upstream_id = UPSTREAM_IDS[provider]
        await repo.ensure_provider(config.tenant, upstream_id, settings.base_url)
        variable = settings.api_key_env
        value = environ.get(variable, "") if variable else ""
        if value:
            # The vault registers a stored value with the log scrubber as the whole header, which
            # for `Authorization` is "Bearer <key>"; the key alone needs its own entry.
            register_secret(value)
            if await vault.seed(config.tenant, upstream_id, key_headers(provider, value)):
                written.append(provider)
                log.info("llm_key_seeded", provider=provider)
        elif variable:
            log.warning("llm_key_variable_not_set", provider=provider, variable=variable)
    return written
