"""Audit sinks. The in-memory one is for tests and the demo until Phase 5."""

from __future__ import annotations

from typing import Any, Literal

from keystone.core.errors import Reject
from keystone.core.types import CallContext


class InMemoryAuditSink:
    """One dict per call. It holds identifiers and outcomes, never arguments or results,
    because an audit record must not become a second copy of the data (CONTRIBUTING rule 6)."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def record(
        self,
        ctx: CallContext,
        outcome: Literal["ok", "rejected", "error"],
        reject: Reject | None,
    ) -> None:
        self.records.append(
            {
                "call_id": ctx.call_id,
                "received_at": ctx.received_at,
                "tenant_id": ctx.principal.tenant_id,
                "user_id": ctx.principal.user_id,
                "agent_id": ctx.principal.agent_id,
                "session_id": ctx.session.session_id,
                "tool": ctx.tool.name,
                "upstream_id": ctx.tool.upstream_id,
                "decision": ctx.decision.effect.value if ctx.decision else None,
                "decision_source": ctx.decision.source if ctx.decision else None,
                "dispatched": ctx.dispatched,
                "outcome": outcome,
                "reject_code": reject.code.value if reject else None,
                "timings_ms": dict(ctx.timings_ms),
            }
        )
