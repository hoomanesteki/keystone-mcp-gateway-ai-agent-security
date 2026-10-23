"""KS-704: the output slot scans what a tool returned, writes the scan on the call and taints the
session.

The slot runs over the real scanner (the rules alone) and an in-memory session store. The faults of
the phase gate are injected with fakes at three depths: the rules and the classifier of the
scanner, the scanner itself, and the store. The gate rule is that the scanner cannot crash a call:
a classifier that raises falls back to the rules, and rules that raise let the output through as
it was, with `scan_action="error"` and a count in `keystone_scan_errors_total`.
"""

from typing import Any

import anyio
import pytest
import structlog

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code
from keystone.core.types import (
    CallContext,
    Risk,
    ScanResult,
    SessionState,
    ToolRef,
    ToolResult,
    ToolTag,
)
from keystone.defense.scanner import Inspection
from keystone.gateway.interceptors.scan import OutputScanInterceptor
from keystone.gateway.pipeline import Pipeline
from keystone.gateway.sessions import InMemorySessionStore
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.settings import Settings
from keystone.telemetry.metrics import Metrics
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool
from tests.fixtures.scan import (
    BENIGN,
    INJECTION,
    SUSPICIOUS,
    Falling,
    exploding_rules,
    guard,
    result_of,
    scan_errors,
    scores_seen,
    tainted_sessions,
    texts_of,
)

pytestmark = pytest.mark.phase(7)

SESSION_ID = "session-1"
MAIL = make_tool("mail", "read_email", risk=Risk.LOW, tags=frozenset({ToolTag.READS_UNTRUSTED}))


async def fresh_call(store: InMemorySessionStore | None, tool: ToolRef = MAIL) -> CallContext:
    """A call of olivia's that has not run. Its session is the copy the store handed out, as the
    gateway reads it at the start of a call, or a throwaway one when there is no store."""
    session: SessionState | None = None
    if store is not None:
        session = await store.create(SESSION_ID, OLIVIA)
    return make_ctx({"text": "x"}, tool, session=session)


async def call_with(
    store: InMemorySessionStore | None, result: ToolResult, tool: ToolRef = MAIL
) -> CallContext:
    """A call of olivia's whose upstream has just returned `result`."""
    ctx = await fresh_call(store, tool)
    ctx.result = result
    ctx.dispatched = True
    return ctx


class BrokenGuard:
    """A scanner that raises out of `inspect`, which the real one promises never to do."""

    async def inspect(self, result: ToolResult, tool: ToolRef, call_id: str) -> Inspection:
        raise RuntimeError("the scanner fell over")


class BrokenStore(InMemorySessionStore):
    """A store that cannot record anything, as Redis does when it is down."""

    async def mark_tainted(self, session_id: str) -> SessionState | None:
        raise ConnectionError("the store is down")


# -- what the slot writes on the call


async def test_a_benign_output_goes_on_as_the_same_object_and_is_recorded() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(BENIGN))
    original = ctx.result

    await OutputScanInterceptor(guard(metrics), store, metrics).after_call(ctx)

    assert ctx.result is original
    assert ctx.scan is not None
    assert (ctx.scan.label, ctx.scan.action, ctx.scan.score) == ("benign", "pass", 0.0)
    assert ctx.session.tainted is False
    assert scores_seen(metrics) == 1 and tainted_sessions(metrics) == 0


async def test_an_injection_taints_the_session_in_the_store_and_in_the_call() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION))
    original = ctx.result

    await OutputScanInterceptor(guard(metrics), store, metrics).after_call(ctx)

    assert ctx.scan is not None
    assert (ctx.scan.label, ctx.scan.action, ctx.scan.score) == ("injection", "annotate", 0.88)
    # The action of the tool's risk was applied: the agent reads the output inside the warning.
    assert ctx.result is not original and ctx.result is not None
    assert "<<<untrusted>>>" in "".join(texts_of(ctx.result))
    # The store has the taint, and so has the copy the rest of this call works on.
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is True
    assert ctx.session.tainted is True
    assert tainted_sessions(metrics) == 1 and scores_seen(metrics) == 1


async def test_the_taint_is_set_whatever_the_action_does_to_the_output() -> None:
    store = InMemorySessionStore()
    critical = make_tool("admin", "dump", risk=Risk.CRITICAL)
    ctx = await call_with(store, result_of(INJECTION), critical)

    await OutputScanInterceptor(guard(), store).after_call(ctx)

    assert ctx.scan is not None and ctx.scan.action == "block"
    assert ctx.result is not None and ctx.result.is_error  # withheld
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is True


async def test_a_suspicious_output_is_annotated_and_does_not_taint() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(SUSPICIOUS))

    await OutputScanInterceptor(guard(metrics), store, metrics).after_call(ctx)

    assert ctx.scan is not None
    assert (ctx.scan.label, ctx.scan.action) == ("suspicious", "annotate")
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is False
    assert ctx.session.tainted is False
    assert tainted_sessions(metrics) == 0


async def test_a_session_counts_as_tainted_once_however_many_injections_it_reads() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    slot = OutputScanInterceptor(guard(metrics), store, metrics)
    first = await call_with(store, result_of(INJECTION))
    await slot.after_call(first)
    # The next call reads the session as the store has it now, tainted.
    second = make_ctx({"text": "x"}, MAIL, session=await store.get(SESSION_ID))
    second.result = result_of(INJECTION)

    await slot.after_call(second)

    assert tainted_sessions(metrics) == 1
    assert scores_seen(metrics) == 2  # every scan is a score, whether or not it taints again


async def test_an_error_result_is_still_read_and_can_taint() -> None:
    # An upstream's error text can carry what an attacker wrote (an error that quotes its input),
    # so the story's "skip error results" is read as "add no flags", and the text is still scanned.
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION, is_error=True))

    await OutputScanInterceptor(guard(), store).after_call(ctx)

    assert ctx.scan is not None and ctx.scan.label == "injection"
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is True


async def test_keystones_own_tools_are_not_scanned() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    whoami = make_tool("keystone", "whoami", risk=Risk.LOW)
    ctx = await call_with(store, result_of(INJECTION), whoami)
    original = ctx.result

    await OutputScanInterceptor(guard(metrics), store, metrics).after_call(ctx)

    assert ctx.scan is None and ctx.result is original
    assert scores_seen(metrics) == 0
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is False


async def test_a_call_with_no_result_is_left_alone() -> None:
    ctx = make_ctx({"text": "x"}, MAIL)

    await OutputScanInterceptor(guard(), InMemorySessionStore()).after_call(ctx)

    assert ctx.scan is None and ctx.result is None


async def test_a_session_the_store_does_not_have_is_tainted_in_the_call_alone() -> None:
    # A request with no session id has a throwaway state that is never stored (ADR-0015).
    store = InMemorySessionStore()
    ctx = await call_with(None, result_of(INJECTION))

    await OutputScanInterceptor(guard(), store).after_call(ctx)

    assert ctx.session.tainted is True
    assert await store.get(ctx.session.session_id) is None


async def test_without_a_store_the_call_s_copy_is_tainted() -> None:
    ctx = await call_with(None, result_of(INJECTION))

    await OutputScanInterceptor(guard()).after_call(ctx)

    assert ctx.session.tainted is True


async def test_the_copy_of_the_call_learns_what_other_calls_recorded() -> None:
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION))
    # Another call of the session read a sensitive tool while this one was in flight.
    await store.add_flags(SESSION_ID, {ToolTag.READS_SENSITIVE})

    await OutputScanInterceptor(guard(), store).after_call(ctx)

    assert ctx.session.flags == {ToolTag.READS_SENSITIVE}
    assert ctx.session.tainted is True


async def test_the_slot_does_nothing_before_the_call() -> None:
    ctx = make_ctx({"text": "x"}, MAIL)

    await OutputScanInterceptor(guard()).before_call(ctx)

    assert ctx.scan is None and ctx.decision is None


# -- the gate rule: the scanner cannot crash a call


async def test_rules_that_raise_pass_the_output_through_with_action_error() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION))
    original = ctx.result

    with structlog.testing.capture_logs() as logs:
        await OutputScanInterceptor(
            guard(metrics, rules=exploding_rules()), store, metrics
        ).after_call(ctx)

    assert ctx.result is original  # not annotated, not blocked
    assert ctx.scan is not None
    assert (ctx.scan.action, ctx.scan.label, ctx.scan.score) == ("error", "benign", 0.0)
    assert scan_errors(metrics, "rules") == 1
    # Nothing was judged, so nothing is tainted and no score is recorded for the histogram.
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is False
    assert scores_seen(metrics) == 0 and tainted_sessions(metrics) == 0
    [entry] = [e for e in logs if e["event"] == "scanner_rules_failed"]
    # The log names the stage and the exception, never the text that was being read.
    assert entry["error"] == "RuntimeError" and "attacker" not in str(logs)


async def test_a_classifier_that_raises_falls_back_to_the_rules() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION))

    await OutputScanInterceptor(guard(metrics, classifier=Falling()), store, metrics).after_call(
        ctx
    )

    # The rules still find the injection, and it still taints.
    assert ctx.scan is not None
    assert (ctx.scan.label, ctx.scan.score, ctx.scan.model) == ("injection", 0.88, "error")
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is True
    assert scan_errors(metrics, "classifier") == 1 and scan_errors(metrics, "rules") == 0


async def test_a_scanner_that_raises_out_of_inspect_is_treated_as_failed_rules() -> None:
    metrics = Metrics(tenants=["acme"])
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION))
    original = ctx.result

    await OutputScanInterceptor(BrokenGuard(), store, metrics).after_call(ctx)  # type: ignore[arg-type]

    assert ctx.result is original
    assert ctx.scan is not None and ctx.scan.action == "error"
    assert scan_errors(metrics, "rules") == 1
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is False


async def test_cancellation_is_not_swallowed() -> None:
    store = InMemorySessionStore()
    ctx = await call_with(store, result_of(INJECTION))
    cancelled = anyio.get_cancelled_exc_class()
    slot = OutputScanInterceptor(guard(classifier=Falling(cancelled())), store)

    with pytest.raises(cancelled):
        await slot.after_call(ctx)


async def test_a_scan_that_is_switched_off_records_nothing() -> None:
    ctx = await call_with(InMemorySessionStore(), result_of(INJECTION))
    original = ctx.result

    await OutputScanInterceptor(None).after_call(ctx)

    assert ctx.scan is None and ctx.result is original and ctx.session.tainted is False


# -- inside the pipeline


def pipeline_for(
    settings: Settings,
    upstream: ToolResult,
    *,
    store: InMemorySessionStore,
    metrics: Metrics,
    audit: InMemoryAuditSink,
    **guard_options: Any,
) -> Pipeline:
    """The real pipeline with the real scanning slot, over an upstream that returns `upstream`."""

    class Dispatcher:
        async def dispatch(self, ctx: CallContext) -> ToolResult:
            return upstream

    deps = PipelineDeps(
        dispatcher=Dispatcher(),
        audit=audit,
        metrics=metrics,
        scanner=guard(metrics, **guard_options),
        sessions=store,
    )
    return build_pipeline(settings, deps)


async def test_a_call_whose_rules_raise_still_succeeds_and_the_audit_says_error(
    settings: Settings,
) -> None:
    metrics = Metrics(tenants=["acme"])
    store, audit = InMemorySessionStore(), InMemoryAuditSink()
    upstream = result_of(INJECTION)
    pipeline = pipeline_for(
        settings, upstream, store=store, metrics=metrics, audit=audit, rules=exploding_rules()
    )
    ctx = await fresh_call(store)

    result = await pipeline.run(ctx)

    # The agent gets what the upstream sent, untouched, and the record says the scan failed.
    assert not result.is_error and result.content == upstream.content
    [record] = audit.records
    assert record["outcome"] == "ok" and record["scan_action"] == "error"
    assert record["scan_score"] == 0.0
    assert scan_errors(metrics, "rules") == 1


async def test_a_call_that_reads_an_injection_ends_with_the_score_in_its_audit_record(
    settings: Settings,
) -> None:
    metrics = Metrics(tenants=["acme"])
    store, audit = InMemorySessionStore(), InMemoryAuditSink()
    pipeline = pipeline_for(
        settings, result_of(INJECTION), store=store, metrics=metrics, audit=audit
    )
    ctx = await fresh_call(store)

    await pipeline.run(ctx)

    [record] = audit.records
    assert (record["scan_score"], record["scan_action"]) == (0.88, "annotate")
    stored = await store.get(SESSION_ID)
    assert stored is not None and stored.tainted is True


async def test_a_store_that_cannot_record_the_taint_withholds_the_output(
    settings: Settings,
) -> None:
    # The session is what the Rule of Two reads. An output that could not be recorded as tainted
    # must not reach the agent, so the pipeline's rule for a slot that raises applies.
    metrics = Metrics(tenants=["acme"])
    store, audit = BrokenStore(), InMemoryAuditSink()
    pipeline = pipeline_for(
        settings, result_of(INJECTION), store=store, metrics=metrics, audit=audit
    )
    ctx = await fresh_call(store)

    result = await pipeline.run(ctx)

    assert result.is_error
    assert "attacker" not in "".join(texts_of(result))
    [record] = audit.records
    assert (record["outcome"], record["reject_code"]) == ("error", Code.OUTPUT_BLOCKED.value)


def test_the_scan_result_of_a_failed_scan_is_a_valid_audit_value() -> None:
    assert ScanResult(score=0.0, label="benign", action="error").action == "error"
