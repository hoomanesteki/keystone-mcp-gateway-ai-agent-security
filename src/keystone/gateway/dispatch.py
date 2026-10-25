"""The step that actually calls an upstream: the only place the gateway does so."""

from __future__ import annotations

from typing import Protocol

import structlog

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, ToolResult
from keystone.gateway.scrub import scrub_result
from keystone.gateway.upstreams import CALL_ID, UpstreamPool
from keystone.registry.naming import is_virtual
from keystone.telemetry.tracing import trace_context_meta

log = structlog.get_logger()

# What one upstream result may hold (KS-906). A result goes through the scanner and into the
# agent's context, so an upstream that answers with thousands of blocks, or 100 MiB, is refused
# as a fault of the upstream and not carried further.
MAX_RESULT_BLOCKS = 256
MAX_RESULT_BYTES = 16 * 1024 * 1024


def check_result_size(result: ToolResult) -> None:
    if len(result.content) > MAX_RESULT_BLOCKS:
        raise Reject(
            Code.UPSTREAM_ERROR,
            f"the upstream returned {len(result.content)} content blocks, the limit is "
            f"{MAX_RESULT_BLOCKS}",
        )
    size = len(result.model_dump_json())
    if size > MAX_RESULT_BYTES:
        raise Reject(
            Code.UPSTREAM_ERROR,
            f"the upstream's result is {size} bytes, the limit is {MAX_RESULT_BYTES}",
        )


class DownCheck(Protocol):
    def is_down(self, upstream_id: str) -> bool: ...


class VirtualRunner(Protocol):
    """The tools Keystone serves itself (`gateway/virtual_tools.py`)."""

    async def call(self, ctx: CallContext) -> ToolResult: ...


class UpstreamDispatcher:
    def __init__(
        self,
        pool: UpstreamPool,
        health: DownCheck | None = None,
        virtual: VirtualRunner | None = None,
    ) -> None:
        self.pool = pool
        self.health = health
        self.virtual = virtual

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        if is_virtual(ctx.tool):
            # No upstream is called: the tool is Keystone's own (KS-603).
            if self.virtual is None:
                raise Reject(Code.TOOL_NOT_FOUND, f"there is no tool named {ctx.tool.name!r}")
            return await self.virtual.call(ctx)
        upstream_id = ctx.tool.upstream_id
        if self.health is not None and self.health.is_down(upstream_id):
            # Refused without a connection attempt, so the call never reached the upstream.
            ctx.dispatched = False
            raise Reject(Code.UPSTREAM_ERROR, f"upstream {upstream_id} is down")
        # The sandbox labels its containers with the call that asked (KS-802). It is read in this
        # task and not sent anywhere: an upstream over the wire never learns the call id.
        call = CALL_ID.set(ctx.call_id)
        try:
            # The trace context of the running span (the upstream call) goes to the upstream in the
            # request's `_meta`, so its spans can join the trace. Nothing is sent without a span.
            meta = trace_context_meta()
            async with self.pool.lease(upstream_id, ctx.upstream_headers) as client:
                if meta:
                    result = await client.call_tool(
                        ctx.tool.upstream_tool_name, ctx.arguments, ctx.tool.timeout_s, meta=meta
                    )
                else:
                    result = await client.call_tool(
                        ctx.tool.upstream_tool_name, ctx.arguments, ctx.tool.timeout_s
                    )
            check_result_size(result)
            # An upstream that echoes the credential it received must not pass it to the agent.
            # This runs before the result leaves dispatch, while the injected values are still
            # on the context (KS-392).
            scrubbed = scrub_result(result, ctx.upstream_headers.values())
            if scrubbed != result:
                log.warning(
                    "upstream_result_redacted",
                    call_id=ctx.call_id,
                    upstream=upstream_id,
                    tool=ctx.tool.name,
                )
            return scrubbed
        finally:
            CALL_ID.reset(call)
            # The plain values live in the pool's client for as long as it is pooled. The context
            # does not keep them a moment longer than the call, whatever the call did.
            ctx.upstream_headers = {}
