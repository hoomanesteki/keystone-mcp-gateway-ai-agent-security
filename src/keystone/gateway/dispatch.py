"""The step that actually calls an upstream: the only place the gateway does so."""

from __future__ import annotations

from keystone.core.types import CallContext, ToolResult
from keystone.gateway.upstreams import UpstreamPool


class UpstreamDispatcher:
    def __init__(self, pool: UpstreamPool) -> None:
        self.pool = pool

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        client = await self.pool.get(ctx.tool.upstream_id, ctx.upstream_headers)
        return await client.call_tool(
            ctx.tool.upstream_tool_name, ctx.arguments, ctx.tool.timeout_s
        )
