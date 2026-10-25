"""Storage for upstreams and tools (plan section 3.7).

Each method opens its own short transaction, so a caller never holds one across a network call.
Rows come back as ORM objects; `to_tool_ref` turns a tool row into the contract type. Nothing
here deletes: a removed upstream or a vanished tool is set `disabled`, because audit records name
them and a deleted row would leave the history pointing at nothing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.types import Risk, ToolRef, ToolStatus, ToolTag
from keystone.db.models import Tool, Upstream
from keystone.db.session import affected
from keystone.registry.naming import LLM_UPSTREAM_IDS, is_reserved
from keystone.registry.pinning import OPERATOR_DISABLED, pending_fingerprint

Sessionmaker = async_sessionmaker[AsyncSession]

Transport = Literal["http", "stdio", "container_stdio", "builtin"]
CredentialMode = Literal["none", "static", "per_user"]
UpstreamSource = Literal["config", "cli"]
UpstreamStatus = Literal["unknown", "up", "degraded", "down", "disabled"]


class UpstreamSpec(BaseModel, frozen=True):
    """What an operator tells Keystone about an upstream. Health and sync fields are not here:
    the registry owns them."""

    id: str
    tenant_id: str
    transport: Transport = "http"
    url: str | None = None
    command: list[str] | None = None
    image: str | None = None
    credential_mode: CredentialMode = "none"
    source: UpstreamSource = "config"


class UpstreamRepo:
    def __init__(self, sessionmaker: Sessionmaker) -> None:
        self._sessionmaker = sessionmaker

    async def upsert(self, spec: UpstreamSpec) -> Upstream:
        """Insert the upstream or update its connection details. Status and sync fields stay.
        An id that belongs to another tenant is an error: ids are unique across tenants, and the
        id of Keystone's own tools belongs to none."""
        if is_reserved(spec.id):
            raise ValueError(f"upstream id {spec.id!r} is reserved for Keystone's own use")
        values: dict[str, Any] = spec.model_dump()
        insertion = insert(Upstream).values(values)
        statement = insertion.on_conflict_do_update(
            index_elements=[Upstream.id],
            set_={k: insertion.excluded[k] for k in values if k not in ("id", "tenant_id")},
            where=Upstream.tenant_id == insertion.excluded.tenant_id,
        ).returning(Upstream)
        async with self._sessionmaker() as session, session.begin():
            row = (await session.scalars(statement)).one_or_none()
        if row is None:
            raise ValueError(f"upstream id {spec.id!r} already belongs to another tenant")
        return row

    async def ensure_provider(self, tenant_id: str, upstream_id: str, url: str) -> Upstream:
        """The row that a provider key of the LLM proxy belongs to (KS-806). It is disabled from the
        start, so nothing syncs it, probes it or lists its tools, and it exists because a credential
        needs an upstream to belong to. Only the two ids the proxy uses are accepted here; they are
        reserved against every other way in. An id that belongs to another tenant is an error."""
        if upstream_id not in LLM_UPSTREAM_IDS:
            raise ValueError(f"{upstream_id!r} is not a provider of the LLM proxy")
        insertion = insert(Upstream).values(
            id=upstream_id,
            tenant_id=tenant_id,
            transport="http",
            url=url,
            credential_mode="static",
            source="config",
            status="disabled",
        )
        statement = insertion.on_conflict_do_update(
            index_elements=[Upstream.id],
            set_={"url": insertion.excluded.url, "credential_mode": "static", "status": "disabled"},
            where=Upstream.tenant_id == insertion.excluded.tenant_id,
        ).returning(Upstream)
        async with self._sessionmaker() as session, session.begin():
            row = (await session.scalars(statement)).one_or_none()
        if row is None:
            raise ValueError(f"upstream id {upstream_id!r} already belongs to another tenant")
        return row

    async def list(
        self, tenant_id: str | None = None, *, include_disabled: bool = True
    ) -> Sequence[Upstream]:
        statement = select(Upstream).order_by(Upstream.id)
        if tenant_id is not None:
            statement = statement.where(Upstream.tenant_id == tenant_id)
        if not include_disabled:
            statement = statement.where(Upstream.status != "disabled")
        async with self._sessionmaker() as session:
            return (await session.scalars(statement)).all()

    async def get(self, upstream_id: str) -> Upstream | None:
        async with self._sessionmaker() as session:
            return await session.get(Upstream, upstream_id)

    async def set_status(self, upstream_id: str, status: UpstreamStatus) -> bool:
        """Returns False when there is no such upstream."""
        statement = update(Upstream).where(Upstream.id == upstream_id).values(status=status)
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def set_status_unless_disabled(self, upstream_id: str, status: UpstreamStatus) -> bool:
        """Move a live upstream to `status`. A disabled upstream stays disabled: only an operator
        or the config file turns one back on."""
        statement = (
            update(Upstream)
            .where(Upstream.id == upstream_id, Upstream.status != "disabled")
            .values(status=status)
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def record_sync(self, upstream_id: str, *, error: str | None = None) -> bool:
        """Note the result of a sync. A success stamps `last_sync_at` and clears `last_error`.
        A failure sets `last_error` and leaves the time of the last good sync alone."""
        values: dict[str, Any] = (
            {"last_sync_at": func.now(), "last_error": None}
            if error is None
            else {"last_error": error}
        )
        statement = update(Upstream).where(Upstream.id == upstream_id).values(**values)
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))


def to_tool_ref(row: Tool) -> ToolRef:
    return ToolRef(
        name=row.name,
        upstream_id=row.upstream_id,
        upstream_tool_name=row.upstream_tool_name,
        tenant_id=row.tenant_id,
        description=row.description,
        input_schema=row.input_schema,
        risk=Risk(row.risk),
        tags=frozenset(ToolTag(t) for t in row.tags),
        cost_per_call_usd=float(row.cost_per_call_usd),
        timeout_s=row.timeout_s,
        description_hash=row.description_hash,
        schema_hash=row.schema_hash,
        status=ToolStatus(row.status),
        extractors=dict(row.extractors),
    )


def _columns(
    tool: ToolRef,
    pending_description: str | None,
    pending_schema: dict[str, Any] | None,
    quarantine_reason: str | None,
) -> dict[str, Any]:
    return {
        "tenant_id": tool.tenant_id,
        "name": tool.name,
        "upstream_id": tool.upstream_id,
        "upstream_tool_name": tool.upstream_tool_name,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "risk": tool.risk.value,
        "tags": sorted(t.value for t in tool.tags),
        # repr gives the shortest text that parses back to the same float, so the round trip
        # through NUMERIC loses nothing.
        "cost_per_call_usd": Decimal(repr(tool.cost_per_call_usd)),
        "timeout_s": tool.timeout_s,
        "extractors": tool.extractors,
        "description_hash": tool.description_hash,
        "schema_hash": tool.schema_hash,
        "status": tool.status.value,
        "pending_description": pending_description,
        "pending_schema": pending_schema,
        "quarantine_reason": quarantine_reason,
        "last_seen_at": func.now(),
    }


class ToolRepo:
    def __init__(self, sessionmaker: Sessionmaker) -> None:
        self._sessionmaker = sessionmaker

    async def upsert(
        self,
        tool: ToolRef,
        *,
        pending_description: str | None = None,
        pending_schema: dict[str, Any] | None = None,
        quarantine_reason: str | None = None,
    ) -> Tool:
        """Write every column of the tool, and stamp `last_seen_at`. A name is unique within a
        tenant, so a second upsert of the same name replaces the first."""
        values = _columns(tool, pending_description, pending_schema, quarantine_reason)
        insertion = insert(Tool).values(values)
        statement = insertion.on_conflict_do_update(
            index_elements=[Tool.tenant_id, Tool.name],
            set_={k: insertion.excluded[k] for k in values if k not in ("tenant_id", "name")},
        ).returning(Tool)
        async with self._sessionmaker() as session, session.begin():
            return (await session.scalars(statement)).one()

    async def get(self, tenant_id: str, name: str) -> Tool | None:
        async with self._sessionmaker() as session:
            return await session.get(Tool, (tenant_id, name))

    async def list_by_tenant(
        self, tenant_id: str, *, status: ToolStatus | None = None
    ) -> Sequence[Tool]:
        statement = select(Tool).where(Tool.tenant_id == tenant_id).order_by(Tool.name)
        if status is not None:
            statement = statement.where(Tool.status == status.value)
        async with self._sessionmaker() as session:
            return (await session.scalars(statement)).all()

    async def list_by_upstream(self, tenant_id: str, upstream_id: str) -> Sequence[Tool]:
        statement = (
            select(Tool)
            .where(Tool.tenant_id == tenant_id, Tool.upstream_id == upstream_id)
            .order_by(Tool.name)
        )
        async with self._sessionmaker() as session:
            return (await session.scalars(statement)).all()

    async def set_status(
        self, tenant_id: str, name: str, status: ToolStatus, *, reason: str | None = None
    ) -> bool:
        """Set the status and the reason together, so a reason never outlives its status. An
        active tool holds no pending definition, so making one active drops it. Returns False
        when there is no such tool."""
        values: dict[str, Any] = {"status": status.value, "quarantine_reason": reason}
        if status is ToolStatus.ACTIVE:
            values |= {"pending_description": None, "pending_schema": None}
        statement = (
            update(Tool).where(Tool.tenant_id == tenant_id, Tool.name == name).values(**values)
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def refresh(self, tool: ToolRef) -> bool:
        """Apply what the config says about a tool (risk, tags, cost, timeout, extractors) and
        stamp `last_seen_at`. The definition, its hashes and the status are left alone, so this is
        safe to run while a person approves or disables the tool."""
        statement = (
            update(Tool)
            .where(Tool.tenant_id == tool.tenant_id, Tool.name == tool.name)
            .values(
                risk=tool.risk.value,
                tags=sorted(t.value for t in tool.tags),
                cost_per_call_usd=Decimal(repr(tool.cost_per_call_usd)),
                timeout_s=tool.timeout_s,
                extractors=tool.extractors,
                last_seen_at=func.now(),
            )
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def set_pending(
        self,
        tenant_id: str,
        name: str,
        *,
        description: str,
        input_schema: dict[str, Any],
        reason: str,
    ) -> bool:
        """Hold a changed definition for review: store it, record why, and quarantine the tool,
        in one statement. The live definition and its hashes stay as they were."""
        statement = (
            update(Tool)
            .where(Tool.tenant_id == tenant_id, Tool.name == name)
            .values(
                pending_description=description,
                pending_schema=input_schema,
                quarantine_reason=reason,
                status=ToolStatus.QUARANTINED.value,
            )
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def hold_pending(
        self, tenant_id: str, name: str, *, description: str, input_schema: dict[str, Any]
    ) -> bool:
        """Store a changed definition without touching the status or the reason: for a tool an
        operator disabled, which stays disabled. `enable` then refuses it until the change is
        approved, so a definition nobody has read cannot go into service by that route."""
        statement = (
            update(Tool)
            .where(Tool.tenant_id == tenant_id, Tool.name == name)
            .values(pending_description=description, pending_schema=input_schema)
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def forget_pending(self, tenant_id: str, name: str) -> bool:
        """Drop a pending definition the upstream no longer offers, and nothing else. The tool
        stays in its status: a disabled one is still disabled, one held at first sight is still
        held, and what waits for review is now the pinned definition alone."""
        statement = (
            update(Tool)
            .where(Tool.tenant_id == tenant_id, Tool.name == name)
            .values(pending_description=None, pending_schema=None)
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def current_state(self, tenant_id: str, name: str) -> ToolState | None:
        """The status the database holds for one tool, read fresh and in one query, with the
        status of its upstream folded in. None when there is no such tool."""
        statement = (
            select(Tool.status, Tool.quarantine_reason, Upstream.status)
            .join(Upstream, Upstream.id == Tool.upstream_id)
            .where(Tool.tenant_id == tenant_id, Tool.name == name)
        )
        async with self._sessionmaker() as session:
            # One statement and no transaction around it: a read on every call (the pinning slot)
            # that otherwise sent BEGIN and ROLLBACK as well (KS-992).
            await session.connection(execution_options={"isolation_level": "AUTOCOMMIT"})
            found = (await session.execute(statement)).one_or_none()
        if found is None:
            return None
        tool_status, reason, upstream_status = found
        if upstream_status == "disabled":
            return ToolState(ToolStatus.DISABLED, "upstream_disabled")
        return ToolState(ToolStatus(tool_status), reason)

    async def clear_pending(self, tenant_id: str, name: str) -> bool:
        """Release a tool whose upstream went back to the definition we hold: drop the pending
        definition and make it active. Only a tool that is quarantined with a pending definition
        is touched. Returns whether it was."""
        statement = (
            update(Tool)
            .where(
                Tool.tenant_id == tenant_id,
                Tool.name == name,
                Tool.status == ToolStatus.QUARANTINED.value,
                Tool.pending_description.is_not(None),
            )
            .values(
                status=ToolStatus.ACTIVE.value,
                pending_description=None,
                pending_schema=None,
                quarantine_reason=None,
            )
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))

    async def approve_change(
        self, tenant_id: str, name: str, *, expect_hash: str | None = None
    ) -> Tool:
        """Accept the pending definition of a quarantined tool: it becomes the live one, its
        hashes are recomputed, and the tool is active. A tool quarantined without a pending
        definition (a new tool that screening held back) is released as it is. A tool an operator
        disabled that changed while it was disabled holds its offer the same way, and this is the
        one way to put it back (`enable` refuses it).

        `expect_hash` is the fingerprint that `keystone tool show` printed for the pending
        definition (a prefix is enough). The approval then applies only if the pending definition
        still has it, so a definition that changed again after the person looked is not approved
        by accident."""
        async with self._sessionmaker() as session, session.begin():
            row = await session.get(Tool, (tenant_id, name), with_for_update=True)
            if row is None:
                raise PinningError(f"there is no tool {name!r}")
            changed_while_disabled = (
                row.status == ToolStatus.DISABLED.value
                and row.quarantine_reason == OPERATOR_DISABLED
                and row.pending_description is not None
            )
            if row.status != ToolStatus.QUARANTINED.value and not changed_while_disabled:
                raise PinningError(f"tool {name!r} is {row.status}, not quarantined")
            if row.pending_description is not None and row.pending_schema is not None:
                fingerprint = pending_fingerprint(row.pending_description, row.pending_schema)
                if expect_hash is not None and not fingerprint.startswith(expect_hash.lower()):
                    raise PinningError(
                        f"the pending definition of {name!r} changed after it was shown "
                        f"(fingerprint now {fingerprint[:12]}); look at it again"
                    )
                row.description = row.pending_description
                row.input_schema = row.pending_schema
                row.description_hash = sha256_hex(canonical_json(row.pending_description))
                row.schema_hash = sha256_hex(canonical_json(row.pending_schema))
            row.pending_description = None
            row.pending_schema = None
            row.quarantine_reason = None
            row.status = ToolStatus.ACTIVE.value
            return row


@dataclass(frozen=True)
class ToolState:
    """What the database says about a tool right now: its status, and the reason it is not
    active. The status of a tool of a disabled upstream is `disabled`."""

    status: ToolStatus
    reason: str | None


class PinningError(ValueError):
    """An approval that cannot be applied. The message says why, for the person who ran it."""


def utc_now() -> datetime:
    return datetime.now(UTC)
