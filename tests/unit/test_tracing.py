"""KS-504: the spans the pipeline emits, with an in-memory exporter."""

import hashlib
from typing import Any

import pytest
from opentelemetry.trace import SpanKind, StatusCode

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ToolResult
from keystone.gateway.wiring import INTERCEPTOR_ORDER, PipelineDeps, build_pipeline
from keystone.settings import Settings
from keystone.telemetry.tracing import (
    INCOMING_TRACE,
    NoopTracer,
    OTelTracer,
    build_tracer,
    current_trace_id,
    incoming_trace,
    trace_context_meta,
    user_hash,
)
from tests.fixtures.calls import make_ctx
from tests.fixtures.tracing import dump, named, traced

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_SPAN_ID = "00f067aa0ba902b7"
TRACEPARENT = f"00-{TRACE_ID}-{PARENT_SPAN_ID}-01"


class Echoing:
    async def dispatch(self, ctx: CallContext) -> ToolResult:
        return ToolResult(content=[{"type": "text", "text": "ok"}])


class Denies:
    """A policy slot that decides deny and refuses the call."""

    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(effect=Effect.DENY, reasons=["default-deny"], source="policy")
        raise Reject(Code.DENIED, "denied by policy: default-deny")

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Allows:
    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(
            effect=Effect.ALLOW, reasons=["operators-high", "audit-me"], source="policy"
        )

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Crashes:
    name = "budget"

    async def before_call(self, ctx: CallContext) -> None:
        raise RuntimeError("secret detail at /srv/keystone/internal.py with key sk-live-123")

    async def after_call(self, ctx: CallContext) -> None:
        return None


def pipeline_with(settings: Settings, tracer: OTelTracer | NoopTracer, **slots: Any) -> Any:
    deps = PipelineDeps(Echoing(), InMemoryAuditSink(), tracer=tracer)
    return build_pipeline(settings, deps, slots or None)


@pytest.mark.phase(5)
async def test_tool_call_span_attributes(settings: Settings) -> None:
    tracer, exporter = traced()
    ctx = make_ctx({"text": "hi"})

    await pipeline_with(settings, tracer, policy=Allows()).run(ctx)

    [root] = named(exporter.get_finished_spans(), "keystone.tool_call")
    assert root.kind is SpanKind.SERVER and root.parent is None
    assert dict(root.attributes or {}) == {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "echo__echo",
        "gen_ai.tool.call.id": ctx.call_id,
        "keystone.tenant": "acme",
        "keystone.agent": "ops-agent",
        "keystone.user_hash": hashlib.sha256(b"olivia").hexdigest()[:12],
        "keystone.decision.effect": "allow",
        "keystone.decision.reasons": ("operators-high", "audit-me"),
        "keystone.outcome": "ok",
    }
    assert root.status.status_code is StatusCode.UNSET
    assert (root.resource.attributes or {})["service.name"] == "keystone"


@pytest.mark.phase(5)
async def test_interceptor_child_spans(settings: Settings) -> None:
    tracer, exporter = traced()

    await pipeline_with(settings, tracer, policy=Allows()).run(make_ctx({"text": "hi"}))

    spans = exporter.get_finished_spans()
    [root] = named(spans, "keystone.tool_call")
    for slot in INTERCEPTOR_ORDER:
        hooks = named(spans, f"keystone.interceptor.{slot}")
        # One span for the hook before the call and one for the hook after it.
        assert sorted(str((s.attributes or {})["keystone.hook"]) for s in hooks) == [
            "after_call",
            "before_call",
        ], slot
        assert all(s.kind is SpanKind.INTERNAL for s in hooks)
    [upstream] = named(spans, "keystone.upstream.call")
    assert upstream.kind is SpanKind.CLIENT
    assert dict(upstream.attributes or {}) == {"keystone.upstream": "echo"}
    # Every other span is a child of the root, in the root's trace.
    others = [s for s in spans if s is not root]
    assert len(others) == 2 * len(INTERCEPTOR_ORDER) + 1
    assert all(s.parent is not None and s.parent.span_id == root.context.span_id for s in others)
    assert {s.context.trace_id for s in spans} == {root.context.trace_id}


@pytest.mark.phase(5)
async def test_rejected_call_span_has_code(settings: Settings) -> None:
    tracer, exporter = traced()

    result = await pipeline_with(settings, tracer, policy=Denies()).run(make_ctx({"text": "hi"}))

    assert result.is_error
    spans = exporter.get_finished_spans()
    [root] = named(spans, "keystone.tool_call")
    attributes = dict(root.attributes or {})
    assert attributes["keystone.reject_code"] == "KS_DENIED"
    assert attributes["keystone.outcome"] == "rejected"
    assert attributes["keystone.decision.effect"] == "deny"
    assert attributes["keystone.decision.reasons"] == ("default-deny",)
    assert root.status.status_code is StatusCode.UNSET  # a refusal is not a failure
    assert named(spans, "keystone.upstream.call") == []  # it never reached the upstream


@pytest.mark.phase(5)
async def test_a_crashing_interceptor_marks_the_span_and_leaks_no_text(settings: Settings) -> None:
    tracer, exporter = traced()

    await pipeline_with(settings, tracer, budget=Crashes(), policy=Allows()).run(
        make_ctx({"text": "hi"})
    )

    spans = exporter.get_finished_spans()
    [root] = named(spans, "keystone.tool_call")
    [crashed] = named(spans, "keystone.interceptor.budget")
    assert dict(root.attributes or {})["keystone.outcome"] == "error"
    assert root.status.status_code is StatusCode.ERROR
    assert crashed.status.status_code is StatusCode.ERROR
    for span in spans:
        assert span.events == ()  # no exception was recorded
    assert "secret detail" not in dump(spans) and "sk-live-123" not in dump(spans)


@pytest.mark.phase(5)
async def test_no_user_id_and_no_argument_value_is_in_any_span(settings: Settings) -> None:
    tracer, exporter = traced()
    arguments = {"text": "card 4111 1111 1111 1111 canary-arg-7731"}

    await pipeline_with(settings, tracer, policy=Allows()).run(make_ctx(arguments))
    await pipeline_with(settings, tracer, policy=Denies()).run(make_ctx(arguments))

    everything = dump(exporter.get_finished_spans())
    assert "tool_call" in everything
    for text in ("olivia", "canary-arg-7731", "4111"):
        assert text not in everything, text


@pytest.mark.phase(5)
def test_the_user_hash_is_twelve_hex_characters_of_a_sha256() -> None:
    assert user_hash("olivia") == hashlib.sha256(b"olivia").hexdigest()[:12]
    assert len(user_hash("")) == 12 and set(user_hash("x")) <= set("0123456789abcdef")


@pytest.mark.phase(5)
async def test_the_incoming_traceparent_is_the_parent_of_the_root_span(settings: Settings) -> None:
    tracer, exporter = traced()

    with incoming_trace({"traceparent": TRACEPARENT, "x-other": "dropped"}):
        assert INCOMING_TRACE.get() == {"traceparent": TRACEPARENT}
        await pipeline_with(settings, tracer, policy=Allows()).run(make_ctx({"text": "hi"}))

    assert INCOMING_TRACE.get() is None
    [root] = named(exporter.get_finished_spans(), "keystone.tool_call")
    assert format(root.context.trace_id, "032x") == TRACE_ID
    assert root.parent is not None
    assert format(root.parent.span_id, "016x") == PARENT_SPAN_ID and root.parent.is_remote


@pytest.mark.phase(5)
@pytest.mark.parametrize("header", ["garbage", "00-xyz-abc-01", f"00-{'0' * 32}-{'0' * 16}-01", ""])
async def test_a_traceparent_that_cannot_be_read_starts_a_trace_of_its_own(
    settings: Settings, header: str
) -> None:
    tracer, exporter = traced()

    with incoming_trace({"traceparent": header}):
        await pipeline_with(settings, tracer, policy=Allows()).run(make_ctx({"text": "hi"}))

    [root] = named(exporter.get_finished_spans(), "keystone.tool_call")
    assert root.parent is None
    assert format(root.context.trace_id, "032x") != TRACE_ID


@pytest.mark.phase(5)
async def test_the_trace_id_and_the_meta_for_an_upstream_come_from_the_running_span(
    settings: Settings,
) -> None:
    tracer, exporter = traced()
    seen: dict[str, Any] = {}

    class Looks:
        async def dispatch(self, ctx: CallContext) -> ToolResult:
            seen["trace_id"] = current_trace_id()
            seen["meta"] = trace_context_meta()
            return ToolResult(content=[{"type": "text", "text": "ok"}])

    pipeline = build_pipeline(
        settings, PipelineDeps(Looks(), InMemoryAuditSink(), tracer=tracer), {"policy": Allows()}
    )
    await pipeline.run(make_ctx({"text": "hi"}))

    [upstream] = named(exporter.get_finished_spans(), "keystone.upstream.call")
    assert seen["trace_id"] == format(upstream.context.trace_id, "032x")
    assert seen["meta"] is not None
    version, trace_id, span_id, flags = seen["meta"]["traceparent"].split("-")
    assert (version, trace_id, span_id) == (
        "00",
        f"{upstream.context.trace_id:032x}",
        f"{upstream.context.span_id:016x}",
    )
    assert int(flags, 16) & 1  # sampled
    # Outside any span there is nothing to report.
    assert current_trace_id() is None and trace_context_meta() is None


@pytest.mark.phase(5)
async def test_without_an_endpoint_the_noop_tracer_changes_nothing(settings: Settings) -> None:
    pipeline = pipeline_with(settings, NoopTracer(), policy=Allows())

    result = await pipeline.run(make_ctx({"text": "hi"}))

    assert not result.is_error and current_trace_id() is None


@pytest.mark.phase(5)
def test_the_exporter_sends_to_the_traces_path_of_the_endpoint() -> None:
    tracer = OTelTracer.exporting_to("http://jaeger:4318/")
    try:
        provider: Any = tracer._provider
        processor = provider._active_span_processor._span_processors[0]
        assert processor.span_exporter._endpoint == "http://jaeger:4318/v1/traces"
    finally:
        tracer.shutdown()


@pytest.mark.phase(5)
def test_a_tracer_is_built_only_when_an_endpoint_is_set() -> None:
    assert isinstance(build_tracer(None), NoopTracer)
    assert isinstance(build_tracer(""), NoopTracer)
    tracer = build_tracer("http://127.0.0.1:1")
    try:
        assert isinstance(tracer, OTelTracer)
    finally:
        tracer.shutdown()
