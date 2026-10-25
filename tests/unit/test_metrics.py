"""KS-505: the metrics, their labels and the pipeline's use of them."""

import re
from typing import Any

import pytest
from prometheus_client.parser import text_string_to_metric_families

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ToolResult
from keystone.gateway.wiring import INTERCEPTOR_ORDER, PipelineDeps, build_pipeline
from keystone.settings import Settings
from keystone.telemetry.metrics import Metrics
from tests.fixtures.calls import make_ctx, make_tool

# Words that would make a label a person or a session. Metrics are less protected than logs, and a
# label with one value for each user gives Prometheus one series for each user.
FORBIDDEN_LABELS = {
    "user",
    "user_id",
    "user_hash",
    "principal",
    "session",
    "session_id",
    "email",
    "sub",
}


class Allows:
    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(effect=Effect.ALLOW, reasons=["r"], source="policy")

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Denies:
    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(effect=Effect.DENY, reasons=["default-deny"], source="policy")
        raise Reject(Code.DENIED, "no")

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Dispatching:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        if self.error is not None:
            raise self.error
        return ToolResult(content=[{"type": "text", "text": "ok"}])


def samples(metrics: Metrics) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for family in text_string_to_metric_families(metrics.render().decode()):
        for sample in family.samples:
            out[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return out


def value(metrics: Metrics, name: str, **labels: str) -> float:
    return samples(metrics).get((name, tuple(sorted(labels.items()))), 0.0)


async def run(
    settings: Settings, metrics: Metrics, dispatcher: Any, slot: Any, ctx: CallContext
) -> ToolResult:
    deps = PipelineDeps(dispatcher, InMemoryAuditSink(), metrics=metrics)
    return await build_pipeline(settings, deps, {"policy": slot}).run(ctx)


@pytest.mark.phase(5)
def test_no_user_labels() -> None:
    metrics = Metrics()

    declared = {label for metric in metrics.declared for label in metric.labels}

    assert declared
    assert declared.isdisjoint(FORBIDDEN_LABELS), declared & FORBIDDEN_LABELS
    # What the registry itself reports agrees with what was declared.
    exposed = {
        label
        for family in metrics.registry.collect()
        for sample in family.samples
        for label in sample.labels
    }
    assert exposed <= declared | {"le"}


@pytest.mark.phase(5)
def test_every_metric_the_story_names_is_declared() -> None:
    declared = {metric.name for metric in Metrics().declared}

    assert declared >= {
        "keystone_tool_calls_total",
        "keystone_tool_call_duration_seconds",
        "keystone_rejections_total",
        "keystone_upstream_errors_total",
        "keystone_quarantined_tools",
        "keystone_policy_eval_seconds",
        "keystone_audit_queue_depth",
        "keystone_audit_failures_total",
        # Phases 6 to 8, declared up front.
        "keystone_approvals_pending",
        "keystone_sessions_tainted_total",
        "keystone_scan_score",
        "keystone_rate_limited_total",
        "keystone_budget_spent_usd",
        "keystone_llm_tokens_total",
    }
    names = [metric.name for metric in Metrics().declared]
    assert len(names) == len(set(names))


@pytest.mark.phase(5)
def test_the_metrics_of_later_phases_are_declared_and_still_empty() -> None:
    text = Metrics().render().decode()

    for name in ("keystone_approvals_pending", "keystone_rate_limited", "keystone_llm_tokens"):
        assert f"# TYPE {name}" in text
    assert not [
        line for line in text.splitlines() if line.startswith("keystone_approvals_pending{")
    ]


@pytest.mark.phase(5)
async def test_a_call_moves_the_counters_and_the_histogram(settings: Settings) -> None:
    metrics = Metrics(tenants=["acme"])

    await run(settings, metrics, Dispatching(), Allows(), make_ctx({"text": "hi"}))

    base = {"tenant": "acme", "tool": "echo__echo", "effect": "allow", "outcome": "ok"}
    assert value(metrics, "keystone_tool_calls_total", **base) == 1
    assert value(metrics, "keystone_tool_call_duration_seconds_count", stage="total") == 1
    assert value(metrics, "keystone_tool_call_duration_seconds_count", stage="upstream") == 1
    # Each interceptor ran its hook before the call and its hook after it.
    for stage in INTERCEPTOR_ORDER:
        count = value(metrics, "keystone_tool_call_duration_seconds_count", stage=stage)
        assert count == 2, stage


@pytest.mark.phase(5)
async def test_a_refusal_is_counted_with_its_code_and_effect(settings: Settings) -> None:
    metrics = Metrics(tenants=["acme"])

    await run(settings, metrics, Dispatching(), Denies(), make_ctx({"text": "hi"}))

    base = {"tenant": "acme", "tool": "echo__echo", "effect": "deny", "outcome": "rejected"}
    assert value(metrics, "keystone_tool_calls_total", **base) == 1
    assert value(metrics, "keystone_rejections_total", tenant="acme", code="KS_DENIED") == 1
    assert value(metrics, "keystone_tool_call_duration_seconds_count", stage="upstream") == 0


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (Reject(Code.UPSTREAM_TIMEOUT, "slow"), "timeout"),
        (Reject(Code.UPSTREAM_ERROR, "broken"), "error"),
        (RuntimeError("secret detail"), "error"),
    ],
)
async def test_an_upstream_failure_is_counted_by_kind(
    settings: Settings, error: Exception, kind: str
) -> None:
    metrics = Metrics(tenants=["acme"], upstreams=["echo"])

    await run(settings, metrics, Dispatching(error), Allows(), make_ctx({"text": "hi"}))

    assert value(metrics, "keystone_upstream_errors_total", upstream="echo", kind=kind) == 1
    assert (
        value(
            metrics,
            "keystone_tool_calls_total",
            tenant="acme",
            tool="echo__echo",
            effect="allow",
            outcome="error",
        )
        == 1
    )


@pytest.mark.phase(5)
async def test_an_upstream_refused_without_a_try_is_counted_as_down(settings: Settings) -> None:
    class Down:
        async def dispatch(self, ctx: CallContext) -> ToolResult:
            ctx.dispatched = False
            raise Reject(Code.UPSTREAM_ERROR, "upstream echo is down")

    metrics = Metrics(tenants=["acme"], upstreams=["echo"])

    await run(settings, metrics, Down(), Allows(), make_ctx({"text": "hi"}))

    assert value(metrics, "keystone_upstream_errors_total", upstream="echo", kind="down") == 1


@pytest.mark.phase(5)
async def test_a_tool_the_registry_does_not_know_is_one_label_value(settings: Settings) -> None:
    metrics = Metrics(tenants=["acme"])
    deps = PipelineDeps(Dispatching(), InMemoryAuditSink(), metrics=metrics)
    pipeline = build_pipeline(settings, deps)

    for made_up in ("a", "b", "c"):
        ctx = make_ctx({}, make_tool(tool=made_up))
        await pipeline.reject(ctx, Reject(Code.TOOL_NOT_FOUND, "no such tool"))

    assert (
        value(
            metrics,
            "keystone_tool_calls_total",
            tenant="acme",
            tool="unknown",
            effect="none",
            outcome="rejected",
        )
        == 3
    )
    assert value(metrics, "keystone_rejections_total", tenant="acme", code="KS_TOOL_NOT_FOUND") == 3
    assert not any("echo__a" in line for line in metrics.render().decode().splitlines())


@pytest.mark.phase(5)
def test_a_tenant_that_is_not_configured_is_other() -> None:
    metrics = Metrics(tenants=["acme"], upstreams=["echo"])

    metrics.upstream_error("made-up-upstream", "error")
    metrics.tools_loaded("made-up-tenant", {})

    assert value(metrics, "keystone_upstream_errors_total", upstream="unknown", kind="error") == 1
    assert value(metrics, "keystone_quarantined_tools", tenant="other") == 0
    assert "made-up" not in metrics.render().decode()


@pytest.mark.phase(5)
def test_label_values_without_a_list_stop_at_a_limit() -> None:
    metrics = Metrics()

    for n in range(500):
        metrics.upstream_error(f"upstream-{n}", "error")

    series = [
        line
        for line in metrics.render().decode().splitlines()
        if line.startswith("keystone_upstream_errors_total{")
    ]
    assert len(series) <= 201  # 200 distinct values and "other"


@pytest.mark.phase(5)
def test_quarantined_tools_are_counted_by_tenant() -> None:
    from keystone.core.types import ToolStatus

    metrics = Metrics(tenants=["acme", "globex"])
    tools = {
        "a": make_tool(tool="a", status=ToolStatus.QUARANTINED),
        "b": make_tool(tool="b", status=ToolStatus.ACTIVE),
        "c": make_tool(tool="c", status=ToolStatus.QUARANTINED),
        "d": make_tool(tool="d", status=ToolStatus.DISABLED),
    }

    metrics.tools_loaded("acme", tools)
    assert value(metrics, "keystone_quarantined_tools", tenant="acme") == 2
    metrics.tools_loaded("acme", {"b": tools["b"]})
    assert value(metrics, "keystone_quarantined_tools", tenant="acme") == 0


@pytest.mark.phase(5)
def test_the_text_format_names_counters_with_total() -> None:
    metrics = Metrics()
    metrics.audit_failures.labels(reason="flush_failed").inc()

    text = metrics.render().decode()

    assert re.search(r'^keystone_audit_failures_total\{reason="flush_failed"\} 1.0$', text, re.M)


@pytest.mark.phase(6)
def test_the_pending_gauge_is_set_for_every_known_tenant_and_returns_to_zero() -> None:
    metrics = Metrics(tenants=["acme", "globex"])

    def pending(tenant: str) -> float | None:
        return metrics.registry.get_sample_value("keystone_approvals_pending", {"tenant": tenant})

    metrics.approvals_changed({"acme": 3})
    assert (pending("acme"), pending("globex")) == (3, 0)

    metrics.approvals_changed({})  # the last request was decided
    assert (pending("acme"), pending("globex")) == (0, 0)

    # A tenant the config does not list shares one series, so a made-up id cannot make more.
    metrics.approvals_changed({"made-up-1": 1, "made-up-2": 2})
    assert pending("other") == 3
    assert pending("made-up-1") is None


@pytest.mark.phase(9)
def test_the_gateway_says_its_profile_whether_it_scans_and_with_what_model() -> None:
    metrics = Metrics()

    metrics.set_info("full", True, "protectai-deberta-v2")

    labels = {"profile": "full", "scanner": "on", "classifier": "protectai-deberta-v2"}
    assert metrics.registry.get_sample_value("keystone_gateway_info", labels) == 1
    # A model that is built has not loaded until the gateway says so.
    ready = {"classifier": "protectai-deberta-v2"}
    assert metrics.registry.get_sample_value("keystone_scanner_classifier_ready", ready) == 0
    metrics.classifier_loaded("protectai-deberta-v2")
    assert metrics.registry.get_sample_value("keystone_scanner_classifier_ready", ready) == 1


@pytest.mark.phase(9)
def test_a_gateway_with_no_model_has_none_to_wait_for() -> None:
    metrics = Metrics()

    metrics.set_info("passthrough", False)

    labels = {"profile": "passthrough", "scanner": "off", "classifier": "none"}
    assert metrics.registry.get_sample_value("keystone_gateway_info", labels) == 1
    assert "keystone_scanner_classifier_ready{" not in metrics.render().decode()


@pytest.mark.phase(9)
def test_the_names_of_models_a_metric_can_carry_are_the_ones_the_settings_allow() -> None:
    from typing import get_args

    from keystone.settings import Classifier
    from keystone.telemetry.metrics import CLASSIFIERS

    # A name the settings do not know is not a label of its own: the set stays bounded.
    assert sorted(CLASSIFIERS) == sorted(get_args(Classifier))
    metrics = Metrics()
    metrics.set_info("full", True, "a-model-somebody-made-up")
    other = {"profile": "full", "scanner": "on", "classifier": "other"}
    assert metrics.registry.get_sample_value("keystone_gateway_info", other) == 1


@pytest.mark.phase(5)
async def test_a_made_up_name_the_rate_limit_refused_is_still_unknown() -> None:
    """A call to a made-up name takes a token (KS-992), and once the bucket is empty the refusal
    is the rate limit's. The name must not become a label value for that: two hundred of them
    would make every real tool first called afterwards "other" for the life of the process."""
    from keystone.gateway.server import unknown_tool
    from keystone.metering.ratelimit import MemoryLimiter
    from keystone.settings import RateLimit, RateLimitSettings
    from tests.fixtures.calls import OLIVIA

    metrics = Metrics(tenants=["acme"])
    limited = Settings(
        env="test",
        rate_limits=RateLimitSettings(per_user=RateLimit(capacity=1, refill_per_s=0.001)),
    )
    deps = PipelineDeps(
        Dispatching(), InMemoryAuditSink(), metrics=metrics, rate_limiter=MemoryLimiter()
    )
    pipeline = build_pipeline(limited, deps)

    for name in ("made_up_a", "made_up_b", "made_up_c"):
        ctx = make_ctx({}, unknown_tool(name, OLIVIA))
        await pipeline.reject(ctx, Reject(Code.TOOL_NOT_FOUND, "no such tool"))

    calls = {
        effect: value(
            metrics,
            "keystone_tool_calls_total",
            tenant="acme",
            tool="unknown",
            effect=effect,
            outcome="rejected",
        )
        for effect in ("none", "deny")
    }
    assert calls == {"none": 1, "deny": 2}
    assert value(metrics, "keystone_rejections_total", tenant="acme", code="KS_RATE_LIMITED") == 2
    assert "made_up" not in metrics.render().decode()
