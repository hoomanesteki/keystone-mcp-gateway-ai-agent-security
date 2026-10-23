"""Prometheus metrics (KS-501, KS-505). One registry per app, so tests that build several apps in
one process do not register a metric twice.

Labels are bounded. A label whose values come from the outside would give Prometheus a new series
for each one: tenant ids, tool names and upstream ids are held to the ones Keystone knows (anything
else is "other" or "unknown"), and the rest are fixed sets: effect, outcome, rejection code, stage,
failure kind. There is no label for a user, a session or an argument. Metrics are often less
protected than logs, and a user label would also make the series count grow with the user base.

The metrics of Phases 6 to 8 (approvals, the scanner, rate limits, budgets, LLM tokens) were
declared before anything set them, so the dashboard could name them from the start. Approvals
(KS-604) and the scanner (KS-704) are set now; rate limits, budgets and LLM tokens wait for
Phase 8.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, ToolRef, ToolStatus

__all__ = ["CONTENT_TYPE_LATEST", "Declared", "Metrics"]

OTHER = "other"
UNKNOWN = "unknown"
NO_DECISION = "none"
# Without a list of known values, this many distinct values are kept and the rest are "other".
MAX_DISTINCT_LABEL_VALUES = 200

# From a millisecond to the longest a tool may be given.
LATENCY_BUCKETS = (
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
)
# The policy engine decides in well under a millisecond.
POLICY_BUCKETS = (0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1)
SCORE_BUCKETS = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
# What can fail in a scan: the classifier, the rules, and the action on a flagged output.
SCAN_STAGES = ("rules", "classifier", "action")


@dataclass(frozen=True)
class Declared:
    """A metric as declared: what a dashboard may name, and the labels it may group by."""

    name: str
    kind: str
    labels: tuple[str, ...]


class _Known:
    """Values for one label: the ones Keystone knows, or the first MAX_DISTINCT_LABEL_VALUES."""

    def __init__(self, known: Collection[str] | None, fallback: str) -> None:
        self._known = frozenset(known) if known else None
        self._seen: set[str] = set()
        self._fallback = fallback

    def values(self) -> frozenset[str]:
        """The values the label can take now: the known ones, or the ones seen so far."""
        return self._known if self._known is not None else frozenset(self._seen)

    def __call__(self, value: str) -> str:
        if self._known is not None:
            return value if value in self._known else self._fallback
        if value in self._seen:
            return value
        if len(self._seen) >= MAX_DISTINCT_LABEL_VALUES:
            return self._fallback
        self._seen.add(value)
        return value


class Metrics:
    def __init__(
        self,
        registry: CollectorRegistry | None = None,
        *,
        tenants: Collection[str] = (),
        upstreams: Collection[str] = (),
    ) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self._declared: list[Declared] = []
        self._tenant = _Known(tenants, OTHER)
        self._upstream = _Known(upstreams, UNKNOWN)
        # Tool names are those of the registry. The pipeline only runs known tools, and a call to
        # a tool that does not exist is counted as "unknown", so the set is bounded by the registry.
        self._tool = _Known(None, OTHER)

        self.tool_calls = self._counter(
            "keystone_tool_calls",
            "Tool calls that reached the gateway, by tenant, tool, policy effect and outcome",
            ["tenant", "tool", "effect", "outcome"],
        )
        self.tool_call_seconds = self._histogram(
            "keystone_tool_call_duration_seconds",
            "Time a call spent in the gateway: stage total, an interceptor, or upstream",
            ["stage"],
            LATENCY_BUCKETS,
        )
        self.rejections = self._counter(
            "keystone_rejections",
            "Calls the gateway refused, by tenant and code",
            ["tenant", "code"],
        )
        self.upstream_errors = self._counter(
            "keystone_upstream_errors",
            "Calls an upstream failed: timeout, down (refused without a try) or error",
            ["upstream", "kind"],
        )
        self.quarantined_tools = self._gauge(
            "keystone_quarantined_tools",
            "Tools held back from agents until a person has read their new definition",
            ["tenant"],
        )
        self.policy_eval_seconds = self._histogram(
            "keystone_policy_eval_seconds",
            "Time the policy engine took to decide",
            [],
            POLICY_BUCKETS,
        )
        # The audit writer sets the depth; it reads its queue when Prometheus asks.
        self.audit_queue_depth = self._gauge(
            "keystone_audit_queue_depth", "Audit records accepted and not yet written", []
        )
        # The reasons are a fixed set (audit/sink.py).
        self.audit_failures = self._counter(
            "keystone_audit_failures",
            "Audit records or batches that could not be written, by reason",
            ["reason"],
        )

        # Set by the approval service from the table (KS-604), on every request, decision and
        # sweep.
        self.approvals_pending = self._gauge(
            "keystone_approvals_pending", "Approvals waiting for a decision", ["tenant"]
        )
        # The output slot sets these (KS-704). The stages are a fixed set (SCAN_STAGES).
        self.sessions_tainted = self._counter(
            "keystone_sessions_tainted",
            "Sessions an injection tainted: one for each output that scored as an injection in a "
            "session that was not tainted yet",
            ["tenant"],
        )
        self.scan_score = self._histogram(
            "keystone_scan_score",
            "Injection scanner scores, one for each output that was scanned",
            ["tenant"],
            SCORE_BUCKETS,
        )
        self.scan_errors = self._counter(
            "keystone_scan_errors",
            "Scans that failed and were worked around, by stage",
            ["stage"],
        )
        # Declared for Phase 8. Nothing sets these yet.
        self.rate_limited = self._counter(
            "keystone_rate_limited", "Calls refused by a rate limit (Phase 8)", ["tenant", "scope"]
        )
        self.budget_spent_usd = self._gauge(
            "keystone_budget_spent_usd",
            "Spend in the current budget window (Phase 8)",
            ["tenant", "scope"],
        )
        self.llm_tokens = self._counter(
            "keystone_llm_tokens",
            "LLM tokens used, by model and direction (Phase 8)",
            ["tenant", "model", "direction"],
        )

    # -- declaring

    def _counter(self, name: str, help_: str, labels: list[str]) -> Counter:
        self._declared.append(Declared(f"{name}_total", "counter", tuple(labels)))
        return Counter(name, help_, labels, registry=self.registry)

    def _gauge(self, name: str, help_: str, labels: list[str]) -> Gauge:
        self._declared.append(Declared(name, "gauge", tuple(labels)))
        return Gauge(name, help_, labels, registry=self.registry)

    def _histogram(
        self, name: str, help_: str, labels: list[str], buckets: Iterable[float]
    ) -> Histogram:
        self._declared.append(Declared(name, "histogram", tuple(labels)))
        return Histogram(name, help_, labels, buckets=tuple(buckets), registry=self.registry)

    @property
    def declared(self) -> list[Declared]:
        """Every metric this registry declares, with the labels it may be grouped by."""
        return list(self._declared)

    # -- recording

    def scan_failed(self, stage: str) -> None:
        """A scan that failed and was worked around: the classifier, the rules or an action."""
        self.scan_errors.labels(stage=stage if stage in SCAN_STAGES else OTHER).inc()

    def scan_scored(self, tenant: str, score: float) -> None:
        """The score of one output that was scanned. A scan that failed has no score and is not
        observed: it is counted by `scan_failed`."""
        self.scan_score.labels(tenant=self._tenant(tenant)).observe(score)

    def session_tainted(self, tenant: str) -> None:
        """An injection tainted a session that was not tainted when the call began."""
        self.sessions_tainted.labels(tenant=self._tenant(tenant)).inc()

    def call_finished(
        self,
        ctx: CallContext,
        outcome: str,
        reject: Reject | None,
        seconds: float,
    ) -> None:
        """One finished call: its counters and its total time."""
        tenant = self._tenant(ctx.principal.tenant_id)
        # A call to a tool that does not exist is "unknown", whatever name the caller made up.
        missing = reject is not None and reject.code is Code.TOOL_NOT_FOUND
        tool = UNKNOWN if missing else self._tool(ctx.tool.name)
        effect = ctx.decision.effect.value if ctx.decision else NO_DECISION
        self.tool_calls.labels(tenant=tenant, tool=tool, effect=effect, outcome=outcome).inc()
        if reject is not None:
            self.rejections.labels(tenant=tenant, code=reject.code.value).inc()
        self.tool_call_seconds.labels(stage="total").observe(seconds)

    def stage(self, name: str, seconds: float) -> None:
        """Time spent in one stage: an interceptor's name, or "upstream"."""
        self.tool_call_seconds.labels(stage=name).observe(seconds)

    def upstream_error(self, upstream: str, kind: str) -> None:
        self.upstream_errors.labels(upstream=self._upstream(upstream), kind=kind).inc()

    def policy_evaluated(self, seconds: float) -> None:
        self.policy_eval_seconds.observe(seconds)

    def approvals_changed(self, pending: Mapping[str, int]) -> None:
        """The requests waiting for a decision, by tenant, as counted in the table. A tenant that
        is known and not in `pending` has none, so its gauge goes down to 0 when the last request
        is decided and is not left at its old value."""
        counts: dict[str, int] = {}
        for tenant, count in pending.items():
            label = self._tenant(tenant)
            counts[label] = counts.get(label, 0) + count
        for tenant in self._tenant.values():
            counts.setdefault(tenant, 0)
        for tenant, count in counts.items():
            self.approvals_pending.labels(tenant=tenant).set(count)

    def tools_loaded(self, tenant: str, tools: Mapping[str, ToolRef]) -> None:
        """The registry loaded a tenant's tools: count the ones held for review."""
        held = sum(1 for tool in tools.values() if tool.status is ToolStatus.QUARANTINED)
        self.quarantined_tools.labels(tenant=self._tenant(tenant)).set(held)

    def render(self) -> bytes:
        """The registry in the Prometheus text format, for GET /metrics."""
        return generate_latest(self.registry)
