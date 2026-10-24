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

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
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
    ApprovalDetail,
    ApprovalItem,
    ApprovalStatus,
    ApproveChange,
    AuditPage,
    AuditRecord,
    BudgetInfo,
    DecisionBody,
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
from keystone.approvals.service import (
    ApprovalNotFound,
    ApprovalRecord,
    ApprovalService,
    NotAnApprover,
    NotPending,
    OwnRequest,
)
from keystone.audit.redact import is_masked
from keystone.audit.verify import export_record, verify_chain
from keystone.core.types import Principal, SessionState
from keystone.db.models import AuditEvent, Tool, Upstream
from keystone.defense.description_check import Screener
from keystone.gateway.sessions import SessionDirectory
from keystone.metering.budgets import BudgetService
from keystone.policy.store import PolicyStore
from keystone.registry.naming import is_reserved
from keystone.registry.pinning import pending_fingerprint, schema_text, unified_diff
from keystone.registry.repo import ToolRepo, UpstreamRepo

PREFIX = "/admin/api/v1"
DEFAULT_PAGE = 50
MAX_PAGE = 200
DEFAULT_VERIFY = 10_000
# A request that checks more than this takes too long to wait for; the CLI checks the whole log.
MAX_VERIFY = 100_000
MAX_SESSIONS = 200
RECENT_CALLS = 10


@dataclass(frozen=True)
class AdminDeps:
    auth: AdminAuth
    sessions: async_sessionmaker[AsyncSession]
    tools: ToolAdmin
    policies: PolicyStore
    console_origin: str
    # Where live sessions are listed from. Without one the list is empty.
    session_directory: SessionDirectory | None = None
    # The approval service. Without one (no master keys) the approvals routes answer 503.
    approvals: ApprovalService | None = None
    # The budgets and what is spent against them (KS-805). Without one the list is empty.
    budgets: BudgetService | None = None
    # What reads the descriptions of a tool for the screening a reviewer is shown (KS-706). The
    # default is the first check alone, which is what the gateway does with the scanner off.
    screener: Screener = field(default_factory=Screener)


class ApprovalsUnavailable(Exception):
    """There is no approval service: Keystone has no master keys."""


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


async def _forbidden(_request: Request, exc: Exception) -> Response:
    return _error(403, "forbidden", str(exc))


async def _no_longer_pending(_request: Request, exc: Exception) -> Response:
    status = exc.status if isinstance(exc, NotPending) else None
    body = {"error": "conflict", "reason": str(exc), "status": status}
    return JSONResponse(body, status_code=409)


async def _unavailable(_request: Request, _exc: Exception) -> Response:
    return _error(503, "unavailable", "approvals need KEYSTONE_MASTER_KEYS, and Keystone has none")


def _summary(row: Tool) -> ToolSummary:
    return ToolSummary(
        name=row.name,
        upstream=row.upstream_id,
        status=row.status,  # type: ignore[arg-type]
        risk=row.risk,
        tags=sorted(row.tags),
        # Without trailing zeros (0.0 is 0), and as plain digits, so that 1E-7 reads 0.0000001.
        cost_per_call_usd=format(row.cost_per_call_usd.normalize(), "f"),
        reason=row.quarantine_reason,
        pending=row.pending_description is not None,
        description_hash=row.description_hash,
        schema_hash=row.schema_hash,
    )


def _detail(row: Tool, screener: Screener) -> ToolDetail:
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
        description_screening=list(screener.screen(row.description, row.input_schema).hits),
        pending_description=row.pending_description,
        pending_schema=row.pending_schema,
        pending_screening=(
            list(screener.screen(row.pending_description, row.pending_schema).hits)
            if row.pending_description
            else []
        ),
        fingerprint=fingerprint,
        diff=diff,
    )


def _target(row: Upstream) -> str:
    """Where an upstream is, without anything that could be a credential: a URL loses its user
    info and query, a stdio server shows its program and how many arguments it has, a container
    shows its image, and a built-in upstream says so."""
    if row.transport == "builtin":
        return "built in"
    if row.transport == "container_stdio":
        return f"image {row.image}" if row.image else "-"
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


def _dollars(amount: Decimal) -> str:
    """Plain digits without trailing zeros, like a tool's cost (0 is 0, 1E-7 is 0.0000001)."""
    return format(amount.normalize(), "f")


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
    app.add_exception_handler(ApprovalNotFound, _not_found)
    app.add_exception_handler(NotAnApprover, _forbidden)
    app.add_exception_handler(OwnRequest, _forbidden)
    app.add_exception_handler(NotPending, _no_longer_pending)
    app.add_exception_handler(ApprovalsUnavailable, _unavailable)
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

    def approval_service() -> ApprovalService:
        if deps.approvals is None:
            raise ApprovalsUnavailable
        return deps.approvals

    async def present(
        records: Sequence[ApprovalRecord], principal: Principal
    ) -> list[ApprovalItem]:
        """The requests as the API shows them: with the tool's risk and tags, and the flags and
        taint of the session that asked, read without keeping the session alive."""
        tools = {
            t.name: t for t in await ToolRepo(deps.sessions).list_by_tenant(principal.tenant_id)
        }
        states: dict[str, SessionState | None] = {}
        if deps.session_directory is not None:
            for session_id in {r.session_id for r in records}:
                try:
                    found = await deps.session_directory.peek(session_id)
                except Exception:
                    found = None
                mine = found is not None and found.principal.tenant_id == principal.tenant_id
                states[session_id] = found if mine else None
        items = []
        for r in records:
            tool, state = tools.get(r.tool_name), states.get(r.session_id)
            items.append(
                ApprovalItem(
                    id=r.id,
                    status=r.status,
                    tool=r.tool_name,
                    risk=tool.risk if tool else None,
                    tags=sorted(tool.tags) if tool else [],
                    arguments=r.args_redacted,
                    arguments_masked=is_masked(r.args_redacted),
                    args_digest=r.args_digest,
                    reasons=list(r.reasons),
                    requested_by_user=r.requested_by_user,
                    requested_by_agent=r.requested_by_agent,
                    own_request=r.requested_by_user == principal.user_id,
                    session_id=r.session_id,
                    call_id=r.call_id,
                    requested_at=_moment(r.requested_at) or "",
                    expires_at=_moment(r.expires_at) or "",
                    expires_in_s=r.expires_in_s,
                    decided_by=r.decided_by,
                    decision_note=r.decision_note,
                    decided_at=_moment(r.decided_at),
                    flags=sorted(flag.value for flag in state.flags) if state else [],
                    tainted=state.tainted if state else False,
                )
            )
        return items

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
        return _detail(await deps.tools.get(principal.tenant_id, name), deps.screener)

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

    # -- approvals

    @app.get(
        "/approvals",
        tags=["approvals"],
        summary="The tenant's approval requests in one state, pending by default",
        responses={503: {"model": ErrorBody, "description": "Keystone has no master keys."}},
    )
    async def list_approvals(
        principal: admin,
        status: ApprovalStatus = "pending",
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
    ) -> list[ApprovalItem]:
        """Pending requests come oldest first, the one that has waited longest on top. The other
        states come newest first."""
        found = await approval_service().list_for_tenant(principal.tenant_id, status, limit)
        return await present(found, principal)

    @app.get(
        "/approvals/{approval_id}",
        tags=["approvals"],
        summary="One request, with the last calls of the session that asked",
        responses={
            404: {"model": ErrorBody, "description": "No such request in the caller's tenant."},
            503: {"model": ErrorBody, "description": "Keystone has no master keys."},
        },
    )
    async def get_approval(principal: admin, approval_id: str) -> ApprovalDetail:
        record = await approval_service().get(principal.tenant_id, approval_id)
        if record is None:
            raise NotFound(f"there is no approval request {approval_id!r}")
        [item] = await present([record], principal)
        table = AuditEvent.__table__
        recent = (
            select(table)
            .where(
                table.c.tenant_id == principal.tenant_id, table.c.session_id == record.session_id
            )
            .order_by(table.c.seq.desc())
            .limit(RECENT_CALLS)
        )
        async with deps.sessions() as session:
            rows = [dict(row) for row in (await session.execute(recent)).mappings()]
        return ApprovalDetail(
            **item.model_dump(), recent_calls=[AuditRecord(**export_record(row)) for row in rows]
        )

    @app.post(
        "/approvals/{approval_id}/decision",
        tags=["approvals"],
        summary="Approve or reject a pending request",
        responses={
            403: {
                "model": ErrorBody,
                "description": "Not an approver, or the caller's own request.",
            },
            404: {"model": ErrorBody, "description": "No such request in the caller's tenant."},
            409: {"model": ErrorBody, "description": "The request is no longer pending."},
            503: {"model": ErrorBody, "description": "Keystone has no master keys."},
        },
    )
    async def decide_approval(
        principal: admin, approval_id: str, body: DecisionBody
    ) -> ApprovalItem:
        """One statement decides it: the request must be pending, unexpired, of the caller's
        tenant and not the caller's own. A second decision, or one after the time ran out, is a 409
        that names what the request is now."""
        record = await approval_service().decide(approval_id, principal, body.approve, body.note)
        [item] = await present([record], principal)
        return item

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
            if not is_reserved(r.id)  # the LLM proxy's provider keys are not MCP servers
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

    @app.get(
        "/budgets",
        tags=["budgets"],
        summary="The spending limits of the tenant and what each has spent",
    )
    async def list_budgets(principal: admin) -> list[BudgetInfo]:
        """Every budget of the tenant in the order a call is checked against them (the tenant's,
        then each user's, then each agent's; a day before a month), with the spend its window holds
        now and when the window ends. The spend is the counter the pre-check reads."""
        if deps.budgets is None:
            return []
        return [
            BudgetInfo(
                scope=s.budget.scope,
                scope_id=s.budget.scope_id,
                window=s.budget.window,
                limit_usd=_dollars(s.budget.limit_usd),
                spent_usd=_dollars(s.spent),
                window_start=_moment(s.window_start) or "",
                resets_at=_moment(s.resets_at) or "",
            )
            for s in await deps.budgets.status(principal.tenant_id)
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
