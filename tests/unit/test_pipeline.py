import json
from typing import Any, Literal

import anyio
import pytest
from structlog.testing import capture_logs

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ToolResult
from keystone.gateway.pipeline import MAX_ARGUMENT_BYTES, Interceptor, Pipeline
from keystone.telemetry.tracing import NoopTracer
from tests.fixtures.calls import make_ctx, make_tool

ORDER = ["rate_limit", "pinning", "budget", "policy", "approval", "credential"]
AFTER = ["output_scan", "session_flags", "metering"]


class Recorder:
    """An interceptor that writes what it saw into a shared list."""

    def __init__(
        self,
        name: str,
        events: list[str],
        *,
        reject_before: Reject | None = None,
        crash_before: bool = False,
        crash_after: bool = False,
    ) -> None:
        self.name = name
        self.events = events
        self.reject_before = reject_before
        self.crash_before = crash_before
        self.crash_after = crash_after

    async def before_call(self, ctx: CallContext) -> None:
        self.events.append(f"before:{self.name}")
        if self.name == "policy":
            ctx.decision = Decision(effect=Effect.ALLOW, source="stub")
        if self.crash_before:
            raise RuntimeError("secret detail at /srv/keystone/internal.py")
        if self.reject_before:
            raise self.reject_before

    async def after_call(self, ctx: CallContext) -> None:
        self.events.append(f"after:{self.name}")
        if self.crash_after:
            raise RuntimeError("secret detail in the scanner")


class SpyDispatcher:
    def __init__(self, events: list[str], result: ToolResult | None = None) -> None:
        self.events = events
        self.result = result or ToolResult(content=[{"type": "text", "text": "ok"}])
        self.seen_decisions: list[Decision | None] = []

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        self.events.append("dispatch")
        self.seen_decisions.append(ctx.decision)
        return self.result


class Boom:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        raise self.error


class Sleeper:
    async def dispatch(self, ctx: CallContext) -> ToolResult:
        await anyio.sleep(30)
        raise AssertionError("not reached")


class BrokenAudit:
    async def record(
        self, ctx: CallContext, outcome: Literal["ok", "rejected", "error"], reject: Reject | None
    ) -> None:
        raise ConnectionError("audit database is down")

    def healthy(self) -> bool:
        return True


class UnhealthyAudit(InMemoryAuditSink):
    """A sink that still takes records but says it may lose them."""

    def healthy(self) -> bool:
        return False


class CrashingHealth(InMemoryAuditSink):
    def healthy(self) -> bool:
        raise RuntimeError("cannot tell")


def build(
    events: list[str] | None = None,
    dispatcher: Any = None,
    audit: Any = None,
    fail_closed: bool = False,
    **recorder_options: dict[str, Any],
) -> tuple[Pipeline, list[str], InMemoryAuditSink]:
    events = [] if events is None else events
    sink = InMemoryAuditSink()
    interceptors: list[Interceptor] = [
        Recorder(name, events, **recorder_options.get(name, {})) for name in ORDER + AFTER
    ]
    pipeline = Pipeline(
        interceptors,
        dispatcher or SpyDispatcher(events),
        audit or sink,
        NoopTracer(),
        fail_closed=fail_closed,
    )
    return pipeline, events, sink


def text_of(result: ToolResult) -> str:
    return str(result.content[0]["text"])


@pytest.mark.phase(1)
async def test_pipeline_order() -> None:
    pipeline, events, sink = build()
    ctx = make_ctx()

    result = await pipeline.run(ctx)

    assert not result.is_error
    assert events == (
        [f"before:{n}" for n in ORDER + AFTER]
        + ["dispatch"]
        + [f"after:{n}" for n in ORDER + AFTER]
    )
    assert ctx.dispatched is True
    assert set(ctx.timings_ms) == {*ORDER, *AFTER, "dispatch"}
    assert [r["outcome"] for r in sink.records] == ["ok"]
    assert sink.records[0]["call_id"] == ctx.call_id


@pytest.mark.phase(1)
async def test_reject_skips_dispatch_and_audits() -> None:
    reject = Reject(Code.DENIED, "no transfers after 18:00", {"policy": "after-hours"})
    pipeline, events, sink = build(policy={"reject_before": reject})
    ctx = make_ctx()

    result = await pipeline.run(ctx)

    assert result.is_error
    assert text_of(result) == (
        f"[keystone:KS_DENIED] call {ctx.call_id} denied: no transfers after 18:00"
    )
    assert result.content[0]["_meta"]["policy"] == "after-hours"
    # Hooks after the rejecting one never ran, and neither did dispatch or any after hook.
    assert events == [f"before:{n}" for n in ORDER[: ORDER.index("policy") + 1]]
    assert ctx.dispatched is False
    assert ctx.result == result
    assert len(sink.records) == 1
    assert sink.records[0]["outcome"] == "rejected"
    assert sink.records[0]["reject_code"] == "KS_DENIED"
    assert sink.records[0]["dispatched"] is False


@pytest.mark.phase(1)
async def test_after_hooks_run_only_when_dispatched() -> None:
    rejecting, events_rejected, _ = build(
        rate_limit={"reject_before": Reject(Code.RATE_LIMITED, "slow down")}
    )
    await rejecting.run(make_ctx())
    assert not [e for e in events_rejected if e.startswith("after:")]

    passing, events_passed, _ = build()
    await passing.run(make_ctx())
    assert [e for e in events_passed if e.startswith("after:")] == [
        f"after:{n}" for n in ORDER + AFTER
    ]


@pytest.mark.phase(1)
async def test_an_after_hook_can_replace_the_result() -> None:
    class Redactor:
        name = "output_scan"

        async def before_call(self, ctx: CallContext) -> None:
            return None

        async def after_call(self, ctx: CallContext) -> None:
            ctx.result = ToolResult(content=[{"type": "text", "text": "[redacted]"}])

    events: list[str] = []
    sink = InMemoryAuditSink()
    # The pipeline itself refuses a call nobody has decided on (KS-191), so the test supplies a
    # policy slot next to the redactor.
    pipeline = Pipeline(
        [Recorder("policy", events), Redactor()], SpyDispatcher(events), sink, NoopTracer()
    )

    result = await pipeline.run(make_ctx())

    assert text_of(result) == "[redacted]"


@pytest.mark.phase(1)
async def test_dispatch_exception_returns_upstream_error() -> None:
    error = RuntimeError("connect to http://10.0.0.7:8101 failed, key=sk-secret")
    pipeline, _, sink = build(dispatcher=Boom(error))
    ctx = make_ctx()

    with capture_logs() as logs:
        result = await pipeline.run(ctx)

    assert result.is_error
    assert result.content[0]["_meta"]["keystone/code"] == "KS_UPSTREAM_ERROR"
    assert "10.0.0.7" not in json.dumps(result.model_dump())
    assert "sk-secret" not in json.dumps(result.model_dump())
    assert [r["outcome"] for r in sink.records] == ["error"]
    failure = next(entry for entry in logs if entry["event"] == "dispatch_failed")
    assert failure["call_id"] == ctx.call_id
    assert failure["log_level"] == "error"


@pytest.mark.phase(1)
async def test_a_reject_from_dispatch_keeps_its_own_code() -> None:
    timeout = Reject(Code.UPSTREAM_TIMEOUT, "the upstream did not answer in 1 s")
    pipeline, events, sink = build(dispatcher=Boom(timeout))

    result = await pipeline.run(make_ctx())

    assert result.content[0]["_meta"]["keystone/code"] == "KS_UPSTREAM_TIMEOUT"
    assert [r["outcome"] for r in sink.records] == ["error"]
    assert not [e for e in events if e.startswith("after:")]


@pytest.mark.phase(1)
async def test_invalid_arguments_rejected() -> None:
    pipeline, events, sink = build()

    result = await pipeline.run(make_ctx({"text": 42}))

    assert result.is_error
    assert result.content[0]["_meta"]["keystone/code"] == "KS_INVALID_ARGUMENTS"
    assert "42 is not of type 'string'" in text_of(result)
    assert events == []
    assert [r["outcome"] for r in sink.records] == ["rejected"]


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    "arguments", [{}, {"text": "x", "extra": 1}, {"text": None}], ids=["missing", "extra", "null"]
)
async def test_schema_violations_never_reach_a_hook(arguments: dict[str, Any]) -> None:
    pipeline, events, sink = build()

    result = await pipeline.run(make_ctx(arguments))

    assert result.content[0]["_meta"]["keystone/code"] == "KS_INVALID_ARGUMENTS"
    assert events == []
    assert len(sink.records) == 1


@pytest.mark.phase(1)
async def test_arguments_over_one_megabyte_are_rejected() -> None:
    big = {"text": "x" * MAX_ARGUMENT_BYTES}
    pipeline, events, sink = build()

    result = await pipeline.run(make_ctx(big))

    assert result.content[0]["_meta"]["keystone/code"] == "KS_INVALID_ARGUMENTS"
    assert "limit" in text_of(result)
    assert events == []
    assert len(sink.records) == 1


@pytest.mark.phase(1)
async def test_a_broken_tool_schema_is_not_the_agents_fault() -> None:
    tool = make_tool(schema={"type": "object", "properties": {"text": {"$ref": "#/nope"}}})
    pipeline, events, sink = build()

    with capture_logs():
        result = await pipeline.run(make_ctx({"text": "x"}, tool=tool))

    assert result.content[0]["_meta"]["keystone/code"] == "KS_UPSTREAM_ERROR"
    assert events == []
    assert [r["outcome"] for r in sink.records] == ["error"]


@pytest.mark.phase(1)
async def test_a_crashing_before_hook_denies_without_leaking() -> None:
    pipeline, events, sink = build(budget={"crash_before": True})

    with capture_logs():
        result = await pipeline.run(make_ctx())

    assert result.is_error
    assert result.content[0]["_meta"]["keystone/code"] == "KS_DENIED"
    assert "secret detail" not in json.dumps(result.model_dump())
    assert "dispatch" not in events
    assert [r["outcome"] for r in sink.records] == ["error"]


@pytest.mark.phase(1)
async def test_a_crashing_after_hook_blocks_the_output() -> None:
    dispatcher = SpyDispatcher([], ToolResult(content=[{"type": "text", "text": "private data"}]))
    pipeline, _, sink = build(dispatcher=dispatcher, output_scan={"crash_after": True})

    with capture_logs():
        result = await pipeline.run(make_ctx())

    assert result.content[0]["_meta"]["keystone/code"] == "KS_OUTPUT_BLOCKED"
    assert "private data" not in json.dumps(result.model_dump())
    assert [r["outcome"] for r in sink.records] == ["error"]


@pytest.mark.phase(1)
async def test_an_audit_failure_is_counted_and_does_not_change_the_result() -> None:
    pipeline, _, _ = build(audit=BrokenAudit())

    with capture_logs() as logs:
        result = await pipeline.run(make_ctx())

    assert not result.is_error
    assert pipeline.audit_failures == 1
    assert any(entry["event"] == "audit_record_failed" for entry in logs)


@pytest.mark.phase(1)
async def test_a_cancelled_call_is_still_audited() -> None:
    pipeline, _, sink = build(dispatcher=Sleeper())

    with anyio.move_on_after(0.05):
        await pipeline.run(make_ctx())

    assert [r["outcome"] for r in sink.records] == ["error"]
    assert sink.records[0]["dispatched"] is True


class LeavesDecisionEmpty:
    """A policy slot that does nothing, like a pass-through stub with a bug."""

    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Decides:
    """A policy slot that records one decision and never raises."""

    name = "policy"

    def __init__(self, effect: Effect, approval_id: str | None = None) -> None:
        self.effect = effect
        self.approval_id = approval_id

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(effect=self.effect, source="policy")
        ctx.approval_id = self.approval_id

    async def after_call(self, ctx: CallContext) -> None:
        return None


def pipeline_with(policy: Any) -> tuple[Pipeline, SpyDispatcher, InMemoryAuditSink]:
    dispatcher = SpyDispatcher([])
    sink = InMemoryAuditSink()
    return Pipeline([policy], dispatcher, sink, NoopTracer()), dispatcher, sink


@pytest.mark.phase(2)
async def test_no_decision_means_no_dispatch() -> None:
    pipeline, dispatcher, sink = pipeline_with(LeavesDecisionEmpty())
    ctx = make_ctx()

    result = await pipeline.run(ctx)

    assert result.is_error
    assert result.content[0]["_meta"]["keystone/code"] == "KS_DENIED"
    assert result.content[0]["_meta"]["keystone/reason"] == "no-decision"
    assert "no-decision" in text_of(result)
    assert dispatcher.events == []
    assert ctx.dispatched is False
    assert [(r["outcome"], r["reject_code"], r["dispatched"]) for r in sink.records] == [
        ("rejected", "KS_DENIED", False)
    ]


@pytest.mark.phase(2)
@pytest.mark.parametrize(
    "policy",
    [
        Decides(Effect.DENY),
        Decides(Effect.REQUIRE_APPROVAL),
        Decides(Effect.DENY, approval_id="01JAPPROVAL"),
    ],
    ids=["deny", "approval-id-unset", "deny-with-approval-id"],
)
async def test_only_allow_or_a_granted_approval_reaches_dispatch(policy: Decides) -> None:
    pipeline, dispatcher, sink = pipeline_with(policy)

    result = await pipeline.run(make_ctx())

    assert result.content[0]["_meta"]["keystone/code"] == "KS_DENIED"
    assert dispatcher.events == []
    assert [r["dispatched"] for r in sink.records] == [False]


@pytest.mark.phase(2)
@pytest.mark.parametrize(
    "policy",
    [Decides(Effect.ALLOW), Decides(Effect.REQUIRE_APPROVAL, approval_id="01JAPPROVAL")],
    ids=["allow", "approved"],
)
async def test_an_allow_or_an_approved_decision_dispatches(policy: Decides) -> None:
    pipeline, dispatcher, sink = pipeline_with(policy)

    result = await pipeline.run(make_ctx())

    assert not result.is_error
    assert dispatcher.events == ["dispatch"]
    assert [r["outcome"] for r in sink.records] == ["ok"]


@pytest.mark.phase(5)
async def test_a_pipeline_that_fails_closed_refuses_before_anything_runs() -> None:
    sink = UnhealthyAudit()
    pipeline, events, _ = build(audit=sink, fail_closed=True)
    ctx = make_ctx()

    result = await pipeline.run(ctx)

    assert result.is_error
    assert text_of(result).startswith(f"[keystone:KS_DENIED] call {ctx.call_id} denied: ")
    assert result.content[0]["_meta"]["keystone/reason"] == "audit-unavailable"
    assert events == []  # no interceptor ran and nothing was dispatched
    assert ctx.dispatched is False and ctx.decision is None
    # The refusal is still audited, with the reason where a search of the log finds it.
    [record] = sink.records
    assert (record["outcome"], record["reject_code"]) == ("rejected", "KS_DENIED")


@pytest.mark.phase(5)
async def test_a_pipeline_that_fails_open_runs_the_call_and_still_audits_it() -> None:
    sink = UnhealthyAudit()
    pipeline, events, _ = build(audit=sink, fail_closed=False)

    result = await pipeline.run(make_ctx())

    assert not result.is_error
    assert "dispatch" in events
    assert [r["outcome"] for r in sink.records] == ["ok"]


@pytest.mark.phase(5)
async def test_a_health_check_that_raises_counts_as_unhealthy() -> None:
    pipeline, events, _ = build(audit=CrashingHealth(), fail_closed=True)

    with capture_logs() as logs:
        result = await pipeline.run(make_ctx())

    assert result.is_error and events == []
    assert any(entry["event"] == "audit_health_check_failed" for entry in logs)


@pytest.mark.phase(5)
async def test_a_healthy_sink_changes_nothing_when_the_pipeline_fails_closed() -> None:
    pipeline, events, sink = build(fail_closed=True)

    result = await pipeline.run(make_ctx())

    assert not result.is_error and "dispatch" in events
    assert [r["outcome"] for r in sink.records] == ["ok"]
