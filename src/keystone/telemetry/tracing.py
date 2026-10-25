"""Tracing: one trace per tool call, a span for each stage (KS-504).

The pipeline wraps a call in a root span, `keystone.tool_call`, and gives each interceptor hook and
the upstream call a child. The trace id is also written to the call's audit row, so a record in the
log leads to its trace.

What a span may hold (the gate reads this): the tool name, the call id, the tenant, the agent, the
decision and its reasons, the outcome, the rejection code, and `keystone.user_hash`. It holds no
raw user id and no argument value. An exception is never recorded on a span, because its text can
carry a header or an argument: a failure is a status with fixed text.

`keystone.user_hash` is the first 12 hex characters of sha256 of the user id. It lets two traces of
one user be matched. It is not secret: whoever holds a list of user ids can hash them.

A request to the LLM proxy (KS-806) has a span of its own, `keystone.llm_call`. It holds the
provider, the model that was asked for, the token counts, the cost, the status and the same tenant,
agent and user hash. It holds no prompt, no answer and no key: the proxy never puts a header or a
body on a span.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar
from typing import Literal, Protocol

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from keystone import __version__
from keystone.core.types import CallContext

SpanValue = str | int | float | bool | Sequence[str]
Kind = Literal["internal", "server", "client"]

SERVICE_NAME = "keystone"
TRACE_HEADERS = ("traceparent", "tracestate")
USER_HASH_LENGTH = 12
MAX_NAME_IN_SPAN = 200
# Spans leave in batches. A short delay puts the demo's traces in Jaeger within a second or two.
EXPORT_DELAY_MS = 1000
# A collector that does not answer holds up only the export thread, and for this long at most.
EXPORT_TIMEOUT_S = 5.0

_KINDS = {
    "internal": SpanKind.INTERNAL,
    "server": SpanKind.SERVER,
    "client": SpanKind.CLIENT,
}

# The trace headers of the request that carries the call. The gateway sets them for the length of
# the call, and the root span reads them, so the pipeline's signature does not change for tracing.
INCOMING_TRACE: ContextVar[Mapping[str, str] | None] = ContextVar("incoming_trace", default=None)

_propagator = TraceContextTextMapPropagator()


class SpanHandle(Protocol):
    def set(self, key: str, value: SpanValue) -> None: ...

    def fail(self, description: str) -> None:
        """Mark the span failed. The description is fixed text, never an exception's."""
        ...


class OpenSpan(SpanHandle, Protocol):
    """A span that the caller ends itself, for work that outlives the function that began it: the
    answer to a request that is streamed back after its handler has returned."""

    def end(self) -> None:
        """End the span. A second call does nothing."""
        ...


class Tracer(Protocol):
    def span(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None = None,
        *,
        kind: Kind = "internal",
    ) -> AbstractContextManager[SpanHandle]: ...

    def open_span(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None = None,
        *,
        kind: Kind = "internal",
        incoming: Mapping[str, str] | None = None,
    ) -> OpenSpan:
        """Begin a span that is not made current and ends when `end()` is called. It is a child of
        the trace in `incoming` (the headers of the request) when they carry one."""
        ...

    def tool_call(self, ctx: CallContext) -> AbstractContextManager[SpanHandle]:
        """The root span of a call: a child of the incoming `traceparent` when there is one."""
        ...

    def shutdown(self) -> None:
        """Send the spans that are still waiting."""
        ...


class _NoSpan:
    def set(self, key: str, value: SpanValue) -> None:
        return None

    def fail(self, description: str) -> None:
        return None


NO_SPAN: SpanHandle = _NoSpan()


class _NoOpenSpan(_NoSpan):
    def end(self) -> None:
        return None


class NoopTracer:
    """No spans at all: what runs when no OTLP endpoint is set."""

    def span(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None = None,
        *,
        kind: Kind = "internal",
    ) -> AbstractContextManager[SpanHandle]:
        return contextlib.nullcontext(_NoSpan())

    def open_span(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None = None,
        *,
        kind: Kind = "internal",
        incoming: Mapping[str, str] | None = None,
    ) -> OpenSpan:
        return _NoOpenSpan()

    def tool_call(self, ctx: CallContext) -> AbstractContextManager[SpanHandle]:
        return contextlib.nullcontext(_NoSpan())

    def shutdown(self) -> None:
        return None


class _OTelSpan:
    def __init__(self, span: Span) -> None:
        self._span = span

    def set(self, key: str, value: SpanValue) -> None:
        if isinstance(value, str):
            self._span.set_attribute(key, value)
        elif isinstance(value, Sequence):
            self._span.set_attribute(key, list(value))
        else:
            self._span.set_attribute(key, value)

    def fail(self, description: str) -> None:
        self._span.set_status(Status(StatusCode.ERROR, description))


class _OTelOpenSpan(_OTelSpan):
    def __init__(self, span: Span) -> None:
        super().__init__(span)
        self._ended = False

    def end(self) -> None:
        if not self._ended:
            self._ended = True
            self._span.end()


def user_hash(user_id: str) -> str:
    return hashlib.sha256(user_id.encode("utf-8", "replace")).hexdigest()[:USER_HASH_LENGTH]


class OTelTracer:
    """Spans through the OpenTelemetry SDK. It owns its provider, so no global state is shared and
    every app and every test has a tracer of its own."""

    def __init__(self, provider: TracerProvider) -> None:
        self._provider = provider
        self._tracer = provider.get_tracer(SERVICE_NAME, __version__)

    @classmethod
    def exporting_to(cls, endpoint: str) -> OTelTracer:
        """Send spans to an OTLP/HTTP endpoint such as http://jaeger:4318."""
        url = endpoint.rstrip("/")
        if not url.endswith("/v1/traces"):
            url += "/v1/traces"
        resource = Resource.create({"service.name": SERVICE_NAME, "service.version": __version__})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=url, timeout=EXPORT_TIMEOUT_S)
        provider.add_span_processor(
            BatchSpanProcessor(exporter, schedule_delay_millis=EXPORT_DELAY_MS)
        )
        return cls(provider)

    def span(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None = None,
        *,
        kind: Kind = "internal",
    ) -> AbstractContextManager[SpanHandle]:
        return self._start(name, attrs, _KINDS[kind], None)

    def open_span(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None = None,
        *,
        kind: Kind = "internal",
        incoming: Mapping[str, str] | None = None,
    ) -> OpenSpan:
        carrier = {k: incoming[k] for k in TRACE_HEADERS if incoming and incoming.get(k)}
        parent = _propagator.extract(carrier) if carrier else None
        # The span is started and not made current: it ends in another task than the one that began
        # it, where detaching a context would fail. Exceptions are not recorded, as in `_start`.
        span = self._tracer.start_span(
            name,
            context=parent,
            kind=_KINDS[kind],
            record_exception=False,
            set_status_on_exception=False,
        )
        handle = _OTelOpenSpan(span)
        for key, value in (attrs or {}).items():
            handle.set(key, value)
        return handle

    def tool_call(self, ctx: CallContext) -> AbstractContextManager[SpanHandle]:
        incoming = INCOMING_TRACE.get()
        parent = _propagator.extract(dict(incoming)) if incoming else None
        attributes: dict[str, SpanValue] = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": ctx.tool.name[:MAX_NAME_IN_SPAN],
            "gen_ai.tool.call.id": ctx.call_id,
            "keystone.tenant": ctx.principal.tenant_id,
            "keystone.agent": ctx.principal.agent_id,
            "keystone.user_hash": user_hash(ctx.principal.user_id),
        }
        return self._start("keystone.tool_call", attributes, SpanKind.SERVER, parent)

    @contextmanager
    def _start(
        self,
        name: str,
        attrs: Mapping[str, SpanValue] | None,
        kind: SpanKind,
        parent: otel_context.Context | None,
    ) -> Iterator[SpanHandle]:
        # Exceptions are not recorded and do not set the status: their text is not ours to send.
        with self._tracer.start_as_current_span(
            name,
            context=parent,
            kind=kind,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            handle = _OTelSpan(span)
            for key, value in (attrs or {}).items():
                handle.set(key, value)
            yield handle

    def shutdown(self) -> None:
        self._provider.shutdown()


def build_tracer(otlp_endpoint: str | None) -> Tracer:
    """The tracer for a deployment: exporting when an endpoint is configured, otherwise none."""
    return OTelTracer.exporting_to(otlp_endpoint) if otlp_endpoint else NoopTracer()


@contextmanager
def incoming_trace(headers: Mapping[str, str]) -> Iterator[None]:
    """Make the trace headers of a request the parent of the call's root span. Other headers are
    dropped, and a request with none leaves the call to start a trace of its own."""
    carrier = {name: headers[name] for name in TRACE_HEADERS if headers.get(name)}
    token = INCOMING_TRACE.set(carrier or None)
    try:
        yield
    finally:
        INCOMING_TRACE.reset(token)


def current_trace_id() -> str | None:
    """The trace id of the span running now, as 32 hex characters, or None outside a span."""
    context = trace.get_current_span().get_span_context()
    return format(context.trace_id, "032x") if context.is_valid else None


def trace_context_meta() -> dict[str, str] | None:
    """`traceparent` (and `tracestate`) of the span running now, for the `_meta` of a request to an
    upstream, or None when no span is running."""
    carrier: dict[str, str] = {}
    _propagator.inject(carrier)
    return carrier or None
