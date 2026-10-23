"""Prometheus metrics. One registry per app, so tests that build several apps in one process do
not register the same metric twice. Labels are bounded: a tenant, a tool, a code, never a user."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge


class Metrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        # The audit writer sets this one when it starts; it reads the queue at scrape time.
        self.audit_queue_depth = Gauge(
            "keystone_audit_queue_depth",
            "Audit records accepted and not yet written",
            registry=self.registry,
        )
        # prometheus_client adds the _total suffix. The reasons are a fixed set (audit/sink.py).
        self.audit_failures = Counter(
            "keystone_audit_failures",
            "Audit records or batches that could not be written, by reason",
            ["reason"],
            registry=self.registry,
        )
