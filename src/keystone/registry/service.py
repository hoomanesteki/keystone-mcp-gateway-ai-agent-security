"""The registry the gateway reads: tools from the database, cached briefly, synced on a timer."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass
from typing import Protocol

import anyio
import structlog

from keystone.core.types import ToolRef, ToolStatus
from keystone.registry.repo import to_tool_ref
from keystone.registry.sync import RegistrySyncer, SyncReport

log = structlog.get_logger()

DEFAULT_CACHE_TTL_S = 2.0
MIN_WATCH_INTERVAL_S = 0.1

# Called with a tenant id when the tools that tenant can see have changed.
Listener = Callable[[str], Awaitable[None]]


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
        self._listeners: list[Listener] = []
        # What each tenant could last see: (name, description hash, schema hash) of its active
        # tools. Unlike the snapshots, a sync does not clear it, so a change shows as a difference.
        self._visible: dict[str, frozenset[tuple[str, str, str]]] = {}
        self._changed: set[str] = set()

    async def list_for_tenant(self, tenant_id: str) -> list[ToolRef]:
        """The active tools of the tenant, sorted by name. Quarantined and disabled tools are
        not listed."""
        tools = await self._tools(tenant_id)
        return sorted((t for t in tools.values() if t.status is ToolStatus.ACTIVE), key=_by_name)

    async def get(self, tenant_id: str, name: str) -> ToolRef | None:
        """The tool in any status, so the pipeline can say why a non-active tool is refused. A
        tool of a disabled upstream is not found."""
        return (await self._tools(tenant_id)).get(name)

    def add_listener(self, listener: Listener) -> None:
        """Be told when the tools a tenant can see change (after a sync here, or when another
        process changed the database and the cache time ran out)."""
        self._listeners.append(listener)

    async def sync_upstream(self, upstream_id: str) -> SyncReport:
        try:
            report = await self.syncer.sync_upstream(upstream_id)
        finally:
            self.invalidate()
        await self._announce()
        return report

    async def sync_all(self, only: Collection[str] | None = None) -> list[SyncReport]:
        try:
            reports = await self.syncer.sync_all(only)
        finally:
            self.invalidate()
        await self._announce()
        return reports

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

    async def run_watch(self) -> None:
        """Look for changes made by another process (the CLI) as often as the cache expires,
        so listeners hear about them without waiting for a request. Never returns."""
        while True:
            await anyio.sleep(max(self._ttl, MIN_WATCH_INTERVAL_S))
            await self._announce()

    async def _announce(self) -> None:
        """Reload every tenant that has been looked at, then tell the listeners about the ones
        whose visible tools changed. Never raises: a failed announcement must not fail a sync."""
        try:
            for tenant_id in list(self._visible):
                await self._tools(tenant_id)
            while self._changed:
                tenant_id = self._changed.pop()
                for listener in self._listeners:
                    await listener(tenant_id)
        except Exception as exc:
            log.warning("tool_change_announcement_failed", error=type(exc).__name__)

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
            self._note_visible(tenant_id, tools)
            return tools

    def _note_visible(self, tenant_id: str, tools: dict[str, ToolRef]) -> None:
        seen = frozenset(
            (t.name, t.description_hash, t.schema_hash)
            for t in tools.values()
            if t.status is ToolStatus.ACTIVE
        )
        previous = self._visible.get(tenant_id)
        self._visible[tenant_id] = seen
        if previous is not None and previous != seen:
            self._changed.add(tenant_id)

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
