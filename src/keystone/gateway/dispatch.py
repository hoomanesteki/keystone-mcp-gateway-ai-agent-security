"""The step that actually calls an upstream: the only place the gateway does so."""

from __future__ import annotations

from typing import Protocol

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, ToolResult
from keystone.gateway.upstreams import UpstreamPool


class DownCheck(Protocol):
    def is_down(self, upstream_id: str) -> bool: ...


class UpstreamDispatcher:
    def __init__(self, pool: UpstreamPool, health: DownCheck | None = None) -> None:
        self.pool = pool
        self.health = health

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        upstream_id = ctx.tool.upstream_id
        if self.health is not None and self.health.is_down(upstream_id):
            # Refused without a connection attempt, so the call never reached the upstream.
            ctx.dispatched = False
            raise Reject(Code.UPSTREAM_ERROR, f"upstream {upstream_id} is down")
        try:
            async with self.pool.lease(upstream_id, ctx.upstream_headers) as client:
                return await client.call_tool(
                    ctx.tool.upstream_tool_name, ctx.arguments, ctx.tool.timeout_s
                )
        finally:
            # The plain values live in the pool's client for as long as it is pooled. The context
            # does not keep them a moment longer than the call, whatever the call did.
            ctx.upstream_headers = {}
