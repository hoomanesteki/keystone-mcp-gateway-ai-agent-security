"""The admin API (`/admin/api/v1`): what the console and operator scripts use (KS-403, KS-507).

It is a small app of its own, mounted under the prefix, so it has its own OpenAPI schema
(`/admin/api/v1/openapi.json`), its own error bodies and its own CORS rule. The role check is on the
app, not on each route, so a route added later cannot forget it. The schema is the one thing that
needs no token: it describes the routes and holds no data.

Everything is scoped to the tenant of the token. A record, a tool or a session of another tenant is
not found, not forbidden, so the answer does not say that it exists. The one exception is
`/audit/verify`: the hash chain runs through every tenant's records, so its result is about the
whole log, and it says nothing of what any record holds.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlsplit, urlunsplit

from fastapi import Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.responses import JSONResponse, Response

from keystone import __version__
from keystone.admin.auth import AdminAuth, AdminRefused, admin_refused_handler
from keystone.admin.schemas import (
    ApproveChange,
    AuditPage,
    AuditRecord,
    Effect,
    ErrorBody,
    Outcome,
    PolicyEntry,
    PolicySummary,
    SessionInfo,
    ToolDetail,
    ToolDiff,
    ToolState,
    ToolSummary,
    UpstreamInfo,
    VerifyResult,
)
from keystone.admin.tools import ToolAdmin, ToolConflict, ToolNotFound
from keystone.audit.verify import export_record, verify_chain
from keystone.core.types import Principal
from keystone.db.models import AuditEvent, Tool, Upstream
from keystone.defense.description_check import check_description
from keystone.gateway.sessions import SessionDirectory
from keystone.policy.store import PolicyStore
from keystone.registry.pinning import pending_fingerprint, schema_text, unified_diff
from keystone.registry.repo import ToolRepo, UpstreamRepo

PREFIX = "/admin/api/v1"
DEFAULT_PAGE = 50
MAX_PAGE = 200
DEFAULT_VERIFY = 10_000
# A request that checks more than this takes too long to wait for; the CLI checks the whole log.
MAX_VERIFY = 100_000
MAX_SESSIONS = 200


@dataclass(frozen=True)
class AdminDeps:
    auth: AdminAuth
    sessions: async_sessionmaker[AsyncSession]
    tools: ToolAdmin
    policies: PolicyStore
    console_origin: str
    # Where live sessions are listed from. Without one the list is empty.
    session_directory: SessionDirectory | None = None


class NotFound(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _error(status: int, error: str, reason: str) -> JSONResponse:
    return JSONResponse({"error": error, "reason": reason}, status_code=status)


async def _not_found(_request: Request, exc: Exception) -> Response:
    reason = exc.reason if isinstance(exc, NotFound) else str(exc)
    return _error(404, "not_found", reason)


async def _conflict(_request: Request, exc: Exception) -> Response:
    return _error(409, "conflict", str(exc))


def _summary(row: Tool) -> ToolSummary:
    return ToolSummary(
        name=row.name,
        upstream=row.upstream_id,
        status=row.status,  # type: ignore[arg-type]
        risk=row.risk,
        tags=sorted(row.tags),
        reason=row.quarantine_reason,
        pending=row.pending_description is not None,
        description_hash=row.description_hash,
        schema_hash=row.schema_hash,
    )


def _detail(row: Tool) -> ToolDetail:
    held_description, held_schema = row.pending_description, row.pending_schema
    diff = fingerprint = None
    if held_description is not None and held_schema is not None:
        fingerprint = pending_fingerprint(held_description, held_schema)
        diff = ToolDiff(
            description=unified_diff(row.description, held_description, "description"),
            input_schema=unified_diff(
                schema_text(row.input_schema), schema_text(held_schema), "schema"
            ),
        )
    return ToolDetail(
        **_summary(row).model_dump(),
        description=row.description,
        input_schema=row.input_schema,
        description_screening=check_description(row.description),
        pending_description=row.pending_description,
        pending_schema=row.pending_schema,
        pending_screening=(
            check_description(row.pending_description) if row.pending_description else []
        ),
        fingerprint=fingerprint,
        diff=diff,
    )


def _target(row: Upstream) -> str:
    """Where an upstream is, without anything that could be a credential: a URL loses its user
    info and query, a stdio server shows its program and how many arguments it has."""
    if row.url:
        parts = urlsplit(row.url)
        host = parts.hostname or ""
        try:
            port = f":{parts.port}" if parts.port else ""
        except ValueError:
            port = ""
        return urlunsplit((parts.scheme, host + port, parts.path, "", ""))
    command = row.command or []
    if not command:
        return "-"
    extra = f" (+{len(command) - 1} arguments)" if len(command) > 1 else ""
    return command[0] + extra


def _moment(value: datetime | None) -> str | None:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if value else None


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def create_admin_app(deps: AdminDeps) -> FastAPI:
    app = FastAPI(
        title="Keystone admin API",
        version=__version__,
        summary="Audit, tools, upstreams, sessions and policies of one tenant.",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
        # On the app, so every route has it. The schema route is not an API route and has none.
        dependencies=[Depends(deps.auth)],
        responses={
            401: {"model": ErrorBody, "description": "No token, or one that is not valid."},
            403: {"model": ErrorBody, "description": "The token lacks the admin role."},
        },
    )
    app.add_exception_handler(AdminRefused, admin_refused_handler)
    app.add_exception_handler(NotFound, _not_found)
    app.add_exception_handler(ToolNotFound, _not_found)
    app.add_exception_handler(ToolConflict, _conflict)
    # Only the console's origin may call this API from a browser. A request from anywhere else
    # gets no CORS headers, and a preflight from it is refused.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[deps.console_origin],
        allow_methods=["GET", "POST"],
        allow_headers=["authorization", "content-type"],
        max_age=600,
    )
    admin = Annotated[Principal, Depends(deps.auth)]

    # -- audit

    @app.get("/audit", tags=["audit"], summary="Search the audit log, newest first")
    async def search_audit(
        principal: admin,
        user: Annotated[str | None, Query(description="The user id of the caller.")] = None,
        agent: Annotated[str | None, Query(description="The agent (OAuth client) id.")] = None,
        tool: Annotated[str | None, Query(description="The exposed tool name.")] = None,
        effect: Effect | None = None,
        outcome: Outcome | None = None,
        since: Annotated[datetime | None, Query(description="From this time, inclusive.")] = None,
        until: Annotated[datetime | None, Query(description="Up to this time, exclusive.")] = None,
        call_id: str | None = None,
        cursor: Annotated[
            int | None, Query(ge=1, description="Records older than this seq, from next_cursor.")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE,
    ) -> AuditPage:
        table = AuditEvent.__table__
        conditions = [table.c.tenant_id == principal.tenant_id]
        for column, wanted in (
            (table.c.user_id, user),
            (table.c.agent_id, agent),
            (table.c.tool_name, tool),
            (table.c.effect, effect),
            (table.c.outcome, outcome),
            (table.c.call_id, call_id),
        ):
            if wanted is not None:
                conditions.append(column == wanted)
        if since is not None:
            conditions.append(table.c.ts >= _utc(since))
        if until is not None:
            conditions.append(table.c.ts < _utc(until))
        if cursor is not None:
            conditions.append(table.c.seq < cursor)
        # One row more than the page asks for says whether there is another page.
        statement = select(table).where(*conditions).order_by(table.c.seq.desc()).limit(limit + 1)
        async with deps.sessions() as session:
            rows = [dict(row) for row in (await session.execute(statement)).mappings()]
        page = rows[:limit]
        return AuditPage(
            items=[AuditRecord(**export_record(row)) for row in page],
            next_cursor=page[-1]["seq"] if len(rows) > limit else None,
        )

    # Declared before /audit/{seq}, which would otherwise take "verify" for a seq.
    @app.get("/audit/verify", tags=["audit"], summary="Check the hash chain of the newest records")
    async def verify_audit(
        last: Annotated[int, Query(ge=1, le=MAX_VERIFY)] = DEFAULT_VERIFY,
    ) -> VerifyResult:
        verdict = await verify_chain(deps.sessions, last=last)
        return VerifyResult(
            ok=verdict.ok,
            records=verdict.records,
            broken_seq=verdict.seq,
            problem=verdict.problem,
            message=verdict.message,
        )

    @app.get("/audit/{seq}", tags=["audit"], summary="One audit record")
    async def get_audit(principal: admin, seq: int) -> AuditRecord:
        table = AuditEvent.__table__
        statement = select(table).where(
            table.c.seq == seq, table.c.tenant_id == principal.tenant_id
        )
        async with deps.sessions() as session:
            row = (await session.execute(statement)).mappings().first()
        if row is None:
            raise NotFound(f"there is no audit record {seq}")
        return AuditRecord(**export_record(dict(row)))

    # -- tools

    @app.get("/tools", tags=["tools"], summary="The tools of the tenant")
    async def list_tools(principal: admin, status: ToolState | None = None) -> list[ToolSummary]:
        rows = await ToolRepo(deps.sessions).list_by_tenant(principal.tenant_id)
        return [_summary(r) for r in rows if status is None or r.status == status]

    @app.get(
        "/tools/{name}", tags=["tools"], summary="A tool, with its pending definition and diff"
    )
    async def get_tool(principal: admin, name: str) -> ToolDetail:
        return _detail(await deps.tools.get(principal.tenant_id, name))

    @app.post(
        "/tools/{name}/approve-change",
        tags=["tools"],
        summary="Accept the pending definition of a quarantined tool",
    )
    async def approve_change(
        principal: admin, name: str, body: ApproveChange | None = None
    ) -> ToolSummary:
        sent = body or ApproveChange()
        row = await deps.tools.approve_change(
            principal.tenant_id, name, expect=sent.expect, note=sent.note, by=principal.user_id
        )
        return _summary(row)

    @app.post("/tools/{name}/disable", tags=["tools"], summary="Take a tool out of service")
    async def disable_tool(principal: admin, name: str) -> ToolSummary:
        return _summary(await deps.tools.disable(principal.tenant_id, name))

    @app.post("/tools/{name}/enable", tags=["tools"], summary="Put a tool you disabled back")
    async def enable_tool(principal: admin, name: str) -> ToolSummary:
        row, _ = await deps.tools.enable(principal.tenant_id, name)
        return _summary(row)

    # -- upstreams, sessions, policies

    @app.get("/upstreams", tags=["upstreams"], summary="The upstreams of the tenant")
    async def list_upstreams(principal: admin) -> list[UpstreamInfo]:
        rows = await UpstreamRepo(deps.sessions).list(principal.tenant_id, include_disabled=True)
        return [
            UpstreamInfo(
                id=r.id,
                transport=r.transport,
                status=r.status,
                source=r.source,
                credential_mode=r.credential_mode,
                target=_target(r),
                last_sync_at=_moment(r.last_sync_at),
                last_error=r.last_error,
            )
            for r in rows
        ]

    @app.get("/sessions", tags=["sessions"], summary="Live sessions of the tenant")
    async def list_sessions(
        principal: admin, limit: Annotated[int, Query(ge=1, le=MAX_SESSIONS)] = 100
    ) -> list[SessionInfo]:
        if deps.session_directory is None:
            return []
        found = await deps.session_directory.list_for_tenant(principal.tenant_id, limit)
        return [
            SessionInfo(
                session_id=s.session_id,
                user_id=s.principal.user_id,
                agent_id=s.principal.agent_id,
                created_at=_moment(s.created_at) or "",
                flags=sorted(flag.value for flag in s.flags),
                tainted=s.tainted,
                call_count=s.call_count,
                spent_usd=s.spent_usd,
            )
            for s in found
        ]

    @app.get("/policies", tags=["policies"], summary="The policies in force for the tenant")
    async def list_policies(principal: admin) -> PolicySummary:
        loaded = deps.policies.current
        mine = loaded.tenants.get(principal.tenant_id)
        return PolicySummary(
            version=loaded.version,
            policies=[
                PolicyEntry(id=p.id, effect=p.effect, kind=p.kind, file=p.file)
                for p in (mine.policies if mine else ())
            ],
        )

    @app.post(
        "/policies/reload",
        tags=["policies"],
        summary="Read the policy files again",
        responses={422: {"description": "The new set has problems; the old set stays in force."}},
    )
    async def reload_policies() -> Response:
        """Read the policy files again. A set with any problem is refused with 422, every problem
        named, and the set in force stays in force."""
        result = await deps.policies.reload()
        if result.ok:
            return JSONResponse(
                {
                    "version": result.version,
                    "previous": result.previous,
                    "changed": result.changed,
                }
            )
        return JSONResponse(
            {
                "error": "invalid_policies",
                "errors": list(result.errors),
                "version": result.version,
            },
            status_code=422,
        )

    return app
