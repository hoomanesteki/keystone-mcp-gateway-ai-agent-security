"""The registry the gateway reads: tools from the database, cached briefly, synced on a timer."""

from __future__ import annotations

import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Protocol

import anyio
import structlog

from keystone.core.types import ToolRef, ToolStatus
from keystone.registry.repo import to_tool_ref
from keystone.registry.sync import RegistrySyncer, SyncReport

log = structlog.get_logger()

DEFAULT_CACHE_TTL_S = 2.0


class ToolLookup(Protocol):
    """What the gateway needs to answer `tools/list` and `tools/call`."""

    async def list_for_tenant(self, tenant_id: str) -> list[ToolRef]: ...
    async def get(self, tenant_id: str, name: str) -> ToolRef | None: ...


class ToolRegistry(ToolLookup, Protocol):
    async def sync_upstream(self, upstream_id: str) -> SyncReport: ...


@dataclass
class _Snapshot:
    tools: dict[str, ToolRef]
    loaded_at: float


class RegistryService:
    """Tools per tenant, read from Postgres.

    A snapshot of a tenant's tools lives in memory until a sync in this process drops it or
    `cache_ttl_s` passes. The time limit is what lets a change made by another process (the CLI
    runs a sync of its own) reach the gateway. A tool can be quarantined from another process, so
    the limit is also how long the gateway may keep serving the old status. Keep it short.
    """

    def __init__(
        self,
        syncer: RegistrySyncer,
        *,
        cache_ttl_s: float = DEFAULT_CACHE_TTL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.syncer = syncer
        self._ttl = cache_ttl_s
        self._clock = clock
        self._cache: dict[str, _Snapshot] = {}
        self._generation = 0
        self._lock = anyio.Lock()

    async def list_for_tenant(self, tenant_id: str) -> list[ToolRef]:
        """The active tools of the tenant, sorted by name. Quarantined and disabled tools are
        not listed."""
        tools = await self._tools(tenant_id)
        return sorted((t for t in tools.values() if t.status is ToolStatus.ACTIVE), key=_by_name)

    async def get(self, tenant_id: str, name: str) -> ToolRef | None:
        """The tool in any status, so the pipeline can say why a non-active tool is refused. A
        tool of a disabled upstream is not found."""
        return (await self._tools(tenant_id)).get(name)

    async def sync_upstream(self, upstream_id: str) -> SyncReport:
        try:
            return await self.syncer.sync_upstream(upstream_id)
        finally:
            self.invalidate()

    async def sync_all(self, only: Collection[str] | None = None) -> list[SyncReport]:
        try:
            return await self.syncer.sync_all(only)
        finally:
            self.invalidate()

    def invalidate(self) -> None:
        """Forget every snapshot. A load that started before this call is not stored."""
        self._generation += 1
        self._cache.clear()

    async def run_periodic(self, interval_s: float) -> None:
        """Sync every upstream, forever, `interval_s` apart. An upstream that was down at the
        last round gets another try at every round. Never returns; cancel it to stop."""
        while True:
            await anyio.sleep(interval_s)
            try:
                reports = await self.sync_all()
            except Exception as exc:
                log.error("periodic_sync_failed", error=type(exc).__name__)
                continue
            failed = [r.upstream_id for r in reports if not r.ok]
            log.info("periodic_sync", upstreams=len(reports), failed=failed)

    async def _tools(self, tenant_id: str) -> dict[str, ToolRef]:
        snapshot = self._cache.get(tenant_id)
        if snapshot is not None and self._fresh(snapshot):
            return snapshot.tools
        async with self._lock:
            snapshot = self._cache.get(tenant_id)
            if snapshot is not None and self._fresh(snapshot):
                return snapshot.tools
            generation = self._generation
            tools = await self._load(tenant_id)
            if generation == self._generation:
                self._cache[tenant_id] = _Snapshot(tools, self._clock())
            return tools

    def _fresh(self, snapshot: _Snapshot) -> bool:
        return self._clock() - snapshot.loaded_at < self._ttl

    async def _load(self, tenant_id: str) -> dict[str, ToolRef]:
        upstreams = await self.syncer.upstreams.list(tenant_id, include_disabled=False)
        # A call has to find its upstream, so the directory is refreshed with every load.
        await self.syncer.learn(upstreams)
        live = {row.id for row in upstreams}
        rows = await self.syncer.tools.list_by_tenant(tenant_id)
        return {row.name: to_tool_ref(row) for row in rows if row.upstream_id in live}


def _by_name(tool: ToolRef) -> str:
    return tool.name
