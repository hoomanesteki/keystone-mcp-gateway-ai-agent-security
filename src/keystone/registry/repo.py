"""Storage for upstreams and tools (plan section 3.7).

Each method opens its own short transaction, so a caller never holds one across a network call.
Rows come back as ORM objects; `to_tool_ref` turns a tool row into the contract type. Nothing
here deletes: a removed upstream or a vanished tool is set `disabled`, because audit records name
them and a deleted row would leave the history pointing at nothing.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import Risk, ToolRef, ToolStatus, ToolTag
from keystone.db.models import Tool, Upstream
from keystone.db.session import affected

Sessionmaker = async_sessionmaker[AsyncSession]

Transport = Literal["http", "stdio", "container_stdio"]
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
        An id that belongs to another tenant is an error: ids are unique across tenants."""
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
        """Set the status and the reason together, so a reason never outlives its status.
        Returns False when there is no such tool."""
        statement = (
            update(Tool)
            .where(Tool.tenant_id == tenant_id, Tool.name == name)
            .values(status=status.value, quarantine_reason=reason)
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


def utc_now() -> datetime:
    return datetime.now(UTC)
