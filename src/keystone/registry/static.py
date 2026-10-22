"""The Phase 1 registry: read every upstream's tools once at startup and keep them.

Phase 2 replaces this with a database-backed registry that syncs, pins and quarantines.
"""

from __future__ import annotations

from collections.abc import Sequence

import structlog

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.errors import Reject
from keystone.core.types import ToolRef
from keystone.gateway.upstreams import UpstreamPool
from keystone.registry.config import UpstreamConfig
from keystone.registry.naming import make_tool_name

log = structlog.get_logger()


class StaticRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, dict[str, ToolRef]] = {}

    async def load(self, pool: UpstreamPool, upstreams: Sequence[UpstreamConfig]) -> None:
        """Ask each upstream for its tools. One that cannot answer is skipped and logged, so one
        dead server does not keep the others' tools from loading. Nothing retries before Phase 2."""
        tools: dict[str, dict[str, ToolRef]] = {}
        for upstream in upstreams:
            if upstream.transport != "http":
                continue
            if upstream.tenant is None or upstream.url is None:
                raise ValueError(f"upstream {upstream.id!r} needs a tenant and a url")
            try:
                async with pool.lease(upstream.id) as client:
                    listed = await client.list_tools()
            except Reject as reject:
                log.warning("upstream_unavailable", upstream=upstream.id, code=reject.code.value)
                continue
            for tool in listed:
                try:
                    name = make_tool_name(upstream.id, tool.name)
                except ValueError:
                    log.warning("tool_name_not_exposable", upstream=upstream.id, tool=tool.name)
                    continue
                tools.setdefault(upstream.tenant, {})[name] = ToolRef(
                    name=name,
                    upstream_id=upstream.id,
                    upstream_tool_name=tool.name,
                    tenant_id=upstream.tenant,
                    description=tool.description,
                    input_schema=tool.input_schema,
                    description_hash=sha256_hex(canonical_json(tool.description)),
                    schema_hash=sha256_hex(canonical_json(tool.input_schema)),
                )
        self._tools = tools
        log.info("registry_loaded", tools=sum(len(t) for t in tools.values()))

    async def list_for_tenant(self, tenant_id: str) -> list[ToolRef]:
        return sorted(self._tools.get(tenant_id, {}).values(), key=lambda t: t.name)

    async def get(self, tenant_id: str, name: str) -> ToolRef | None:
        return self._tools.get(tenant_id, {}).get(name)
