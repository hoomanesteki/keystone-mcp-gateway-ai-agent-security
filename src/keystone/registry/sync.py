"""Learn each upstream's tools and keep the registry in step with them (KS-203).

Read this file first when reviewing the registry. The rule it enforces: a sync that goes wrong
for one upstream changes nothing for any other upstream, and changes nothing for that upstream's
own tools either. `sync_upstream` never raises. When it cannot get a complete tool list it writes
the error to the upstream's `last_error` and returns, and only a complete list can mark a tool as
gone. A server that is down, slow or half broken therefore cannot disable its own tools, let
alone anyone else's.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field

import anyio
import structlog
from pydantic import BaseModel, Field

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.errors import Reject
from keystone.core.types import Risk, ToolRef, ToolStatus, ToolTag
from keystone.db.models import Tool, Upstream
from keystone.defense.description_check import check_description
from keystone.gateway.upstreams import (
    UpstreamDirectory,
    UpstreamPool,
    UpstreamTarget,
    UpstreamTool,
)
from keystone.registry.config import ToolOverride
from keystone.registry.naming import make_tool_name
from keystone.registry.pinning import CHANGE_REASONS, REMOVED, SUSPICIOUS, change_reason
from keystone.registry.repo import ToolRepo, UpstreamRepo

log = structlog.get_logger()

DEFAULT_TIMEOUT_S = 20.0


class SyncReport(BaseModel):
    """What one sync of one upstream did, by exposed tool name."""

    upstream_id: str
    created: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)
    # Listed with a description or schema other than the one we hold. Each is held for review.
    changed: list[str] = Field(default_factory=list)
    # The part of `changed` that this sync newly quarantined.
    quarantined: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def target_of(row: Upstream, env: Mapping[str, str] | None = None) -> UpstreamTarget:
    return UpstreamTarget(
        transport=row.transport,
        url=row.url,
        command=tuple(row.command) if row.command else None,
        env=tuple(sorted((env or {}).items())),
    )


def definition_hashes(description: str, input_schema: dict[str, object]) -> tuple[str, str]:
    """The two values pinning compares. They cover exactly what a model reads about a tool."""
    return sha256_hex(canonical_json(description)), sha256_hex(canonical_json(input_schema))


def build_tool_ref(
    upstream: Upstream, name: str, tool: UpstreamTool, override: ToolOverride | None
) -> ToolRef:
    """The registry's view of a tool: the upstream's definition plus the config's overrides.
    Without an override a tool has risk medium, no tags and no cost."""
    override = override or ToolOverride()
    description_hash, schema_hash = definition_hashes(tool.description, tool.input_schema)
    ref = ToolRef(
        name=name,
        upstream_id=upstream.id,
        upstream_tool_name=tool.name,
        tenant_id=upstream.tenant_id,
        description=tool.description,
        input_schema=tool.input_schema,
        risk=override.risk or Risk.MEDIUM,
        tags=frozenset(ToolTag(t) for t in override.tags or ()),
        description_hash=description_hash,
        schema_hash=schema_hash,
        extractors=dict(override.extract),
    )
    # Left out of the constructor so that ToolRef keeps the only copy of its defaults.
    chosen = {
        key: value
        for key, value in (
            ("cost_per_call_usd", override.cost_per_call_usd),
            ("timeout_s", override.timeout_s),
        )
        if value is not None
    }
    return ref.model_copy(update=chosen)


def describe_failure(exc: BaseException) -> str:
    """A line for `last_error`. Exception text can hold URLs and header values, so only a
    Reject's own message, which Keystone wrote, is quoted."""
    if isinstance(exc, Reject):
        return f"{exc.code.value}: {exc.message}"
    if isinstance(exc, TimeoutError):
        return "the sync timed out"
    return f"sync failed ({type(exc).__name__})"


@dataclass
class RegistrySyncer:
    """Reads tool lists from upstreams and writes the differences to the database."""

    upstreams: UpstreamRepo
    tools: ToolRepo
    pool: UpstreamPool
    directory: UpstreamDirectory
    # upstream id -> upstream tool name -> what the config says about it
    overrides: Mapping[str, Mapping[str, ToolOverride]]
    timeout_s: float = DEFAULT_TIMEOUT_S
    # upstream id -> the environment its stdio child gets (from the config file only)
    environments: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    async def learn(self, rows: Iterable[Upstream]) -> None:
        """Tell the directory where the upstreams are, and drop pooled clients whose address
        changed since the last time."""
        changed = self.directory.update(
            {row.id: target_of(row, self.environments.get(row.id)) for row in rows}
        )
        for upstream_id in changed:
            await self.pool.forget(upstream_id)

    async def sync_upstream(self, upstream_id: str) -> SyncReport:
        """Sync one upstream. Never raises (apart from cancellation): every failure ends up in
        the report and in the upstream's `last_error`."""
        report = SyncReport(upstream_id=upstream_id)
        try:
            row = await self.upstreams.get(upstream_id)
            if row is None:
                report.errors.append("there is no such upstream")
                return report
            if row.status == "disabled":
                report.errors.append("the upstream is disabled")
                return report
            await self.learn([row])
            try:
                listed = await self._list(upstream_id)
            except Exception as exc:
                message = describe_failure(exc)
                if not isinstance(exc, Reject | TimeoutError):
                    log.warning("sync_failed", upstream=upstream_id, error=type(exc).__name__)
                report.errors.append(message)
                await self.upstreams.record_sync(upstream_id, error=message)
                return report
            await self._apply(row, listed, report)
            await self.upstreams.record_sync(upstream_id)
            await self.upstreams.set_status_unless_disabled(upstream_id, "up")
        except Exception as exc:
            # The database failed. Nothing here can say more than the type.
            log.error("sync_store_failed", upstream=upstream_id, error=type(exc).__name__)
            report.errors.append(f"could not store the result ({type(exc).__name__})")
        return report

    async def sync_all(self, only: Collection[str] | None = None) -> list[SyncReport]:
        """Sync every live upstream at once, or only those in `only`. One report per upstream,
        in id order. An upstream that fails does not hold up or affect the others."""
        rows = [
            r
            for r in await self.upstreams.list(include_disabled=False)
            if only is None or r.id in only
        ]
        reports: dict[str, SyncReport] = {}

        async def one(upstream_id: str) -> None:
            reports[upstream_id] = await self.sync_upstream(upstream_id)

        async with anyio.create_task_group() as group:
            for row in rows:
                group.start_soon(one, row.id)
        return [reports[row.id] for row in rows]

    async def _list(self, upstream_id: str) -> list[UpstreamTool]:
        with anyio.fail_after(self.timeout_s):
            async with self.pool.lease(upstream_id) as client:
                return await client.list_tools()

    async def _apply(self, row: Upstream, listed: list[UpstreamTool], report: SyncReport) -> None:
        """Write a complete tool list. Only called with one, so a tool missing from it is gone."""
        stored = {t.name: t for t in await self.tools.list_by_upstream(row.tenant_id, row.id)}
        overrides = self.overrides.get(row.id, {})
        for unknown in sorted(set(overrides) - {t.name for t in listed}):
            log.warning("override_for_unknown_tool", upstream=row.id, tool=unknown)

        seen: set[str] = set()
        for tool in listed:
            try:
                name = make_tool_name(row.id, tool.name)
            except ValueError:
                report.errors.append(f"tool {tool.name[:64]!r} cannot be exposed: invalid name")
                continue
            if name in seen:
                report.errors.append(f"tool {name!r} is listed twice")
                continue
            seen.add(name)
            ref = build_tool_ref(row, name, tool, overrides.get(tool.name))
            old = stored.get(name)
            if old is None:
                await self._create(ref, report)
            elif (old.description_hash, old.schema_hash) != (ref.description_hash, ref.schema_hash):
                await self._hold_change(row, old, ref, report)
            else:
                await self.tools.refresh(ref)
                await self._settle(row, old)
                report.unchanged.append(name)

        for name, old in stored.items():
            if name not in seen and old.status != ToolStatus.DISABLED:
                await self.tools.set_status(
                    row.tenant_id, name, ToolStatus.DISABLED, reason=REMOVED
                )
                report.removed.append(name)
        for names in (
            report.created,
            report.unchanged,
            report.changed,
            report.quarantined,
            report.removed,
        ):
            names.sort()

    async def _create(self, ref: ToolRef, report: SyncReport) -> None:
        """Store a tool seen for the first time. One whose description trips the screening is
        stored quarantined, so it never reaches a model before a person has read it."""
        hits = check_description(ref.description)
        if not hits:
            await self.tools.upsert(ref)
        else:
            reason = f"{SUSPICIOUS}:{','.join(hits)}"
            held = ref.model_copy(update={"status": ToolStatus.QUARANTINED})
            await self.tools.upsert(held, quarantine_reason=reason)
            report.quarantined.append(ref.name)
            log.warning("tool_quarantined", upstream=ref.upstream_id, tool=ref.name, reason=reason)
        report.created.append(ref.name)

    async def _settle(self, row: Upstream, old: Tool) -> None:
        """The upstream lists the definition we hold. A tool that sync disabled because it was
        gone is active again. A tool quarantined for a change the upstream has since taken back
        is released: nothing but the definition a person accepted is on offer any more."""
        if old.status == ToolStatus.DISABLED and old.quarantine_reason == REMOVED:
            await self.tools.set_status(row.tenant_id, old.name, ToolStatus.ACTIVE)
        elif (
            old.status == ToolStatus.QUARANTINED
            and old.pending_description is not None
            and old.quarantine_reason in CHANGE_REASONS
        ):
            await self.tools.clear_pending(row.tenant_id, old.name)
            log.info("tool_released", upstream=row.id, tool=old.name, why="change taken back")

    async def _hold_change(
        self, row: Upstream, old: Tool, ref: ToolRef, report: SyncReport
    ) -> None:
        """The upstream lists a different definition. Keep the one we hold, store the new one as
        pending and quarantine the tool. A tool an operator disabled stays disabled."""
        report.changed.append(ref.name)
        await self.tools.refresh(ref)
        if old.status == ToolStatus.DISABLED and old.quarantine_reason != REMOVED:
            return
        reason = change_reason(
            (old.description_hash, old.schema_hash), (ref.description_hash, ref.schema_hash)
        )
        if (
            old.status == ToolStatus.QUARANTINED
            and old.pending_description == ref.description
            and old.pending_schema == ref.input_schema
        ):
            return  # the same pending definition as last time: already held, nothing new to say
        await self.tools.set_pending(
            row.tenant_id,
            ref.name,
            description=ref.description,
            input_schema=ref.input_schema,
            reason=reason or CHANGE_REASONS[0],
        )
        report.quarantined.append(ref.name)
        log.warning(
            "tool_quarantined", upstream=row.id, tool=ref.name, reason=reason, before=old.status
        )
