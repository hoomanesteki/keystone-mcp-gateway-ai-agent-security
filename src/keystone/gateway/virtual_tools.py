"""The tools Keystone offers itself: `keystone__await_approval` and `keystone__whoami` (KS-603).

They belong to the pseudo-upstream `keystone`, an id no configured upstream can have (the config
loader, the CLI and the registry refuse it), so a name that starts with `keystone__` is one of
these and never an upstream's. The gateway lists them for every caller and builds a call context
for them like any other, and the call goes through the whole pipeline:

- the policy slot gives them `Decision(allow, source="virtual")` and does not ask Cedar,
- the pinning and credential slots have no registry row and no upstream credential to look up,
- rate limits and the audit sink apply as for any call, and
- the dispatcher hands the call to `VirtualTools.call`, which is what runs here.

`keystone__await_approval` is the one that does something with consequences. It runs the call that
was waiting for approval, after the approval came, through the full pipeline again, so the tool
must still be active, the policy decides again and anything added to the pipeline later applies.
That inner call leaves an audit record of its own, next to the record of the await.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Protocol

import structlog

from keystone.approvals.service import ApprovalError, ApprovalRecord, Outcome
from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.errors import Code, Reject
from keystone.core.ids import new_id
from keystone.core.types import CallContext, Principal, Risk, ToolRef, ToolResult
from keystone.gateway.interceptors.approval import NOT_VALID, pending_rejection
from keystone.gateway.sessions import SessionStore, refresh
from keystone.registry.naming import SEPARATOR, VIRTUAL_UPSTREAM, is_virtual

log = structlog.get_logger()

AWAIT_APPROVAL = f"{VIRTUAL_UPSTREAM}{SEPARATOR}await_approval"
WHOAMI = f"{VIRTUAL_UPSTREAM}{SEPARATOR}whoami"
DEFAULT_WAIT_S = 60
MAX_WAIT_S = 120
MAX_ID_CHARS = 64

AWAIT_DESCRIPTION = (
    "Wait for a person to decide a call that returned KS_APPROVAL_PENDING. Pass the approval_id "
    "from that result. If the request is approved, the original call runs now and its result is "
    "returned; if it is rejected or has expired you are told so; if it is still pending after "
    "wait_seconds you get KS_APPROVAL_PENDING again and can call this tool again."
)
AWAIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "approval_id": {"type": "string", "minLength": 1, "maxLength": MAX_ID_CHARS},
        "wait_seconds": {
            "type": "integer",
            "minimum": 0,
            "maximum": MAX_WAIT_S,
            "default": DEFAULT_WAIT_S,
        },
    },
    "required": ["approval_id"],
    "additionalProperties": False,
}
WHOAMI_DESCRIPTION = (
    "Show who Keystone thinks you are in this session: your user, tenant, agent and roles, and the "
    "session's flags, taint, call count and spend. It shows no token or credential."
)
WHOAMI_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}

NOT_YOURS = "there is no such approval request for this session"


class Runner(Protocol):
    """What the await tool needs of the pipeline: to run the call that was waiting."""

    async def run(self, ctx: CallContext) -> ToolResult: ...


class Approvals(Protocol):
    async def get(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None: ...

    async def wait(self, approval_id: str, timeout_s: float) -> Outcome: ...

    async def load_args(self, approval_id: str, *, tenant_id: str) -> dict[str, Any] | None: ...


class Tools(Protocol):
    async def get(self, tenant_id: str, name: str) -> ToolRef | None: ...


def _definition(name: str, description: str, schema: dict[str, Any], tenant_id: str) -> ToolRef:
    return ToolRef(
        name=f"{VIRTUAL_UPSTREAM}{SEPARATOR}{name}",
        upstream_id=VIRTUAL_UPSTREAM,
        upstream_tool_name=name,
        tenant_id=tenant_id,
        description=description,
        input_schema=schema,
        risk=Risk.LOW,
        # The await tool waits on purpose, and then runs a call that has a timeout of its own.
        timeout_s=MAX_WAIT_S + 30.0,
        description_hash=sha256_hex(description.encode()),
        schema_hash=sha256_hex(canonical_json(schema)),
    )


class VirtualTools:
    def __init__(self, approvals: Approvals | None, registry: Tools) -> None:
        self._approvals = approvals
        self._registry = registry
        self._pipeline: Runner | None = None
        self._sessions: SessionStore | None = None

    def bind(self, pipeline: Runner, sessions: SessionStore | None = None) -> None:
        """Give the await tool the pipeline it runs the waiting call through, and the store it
        reads the session from again before it does (KS-705). The pipeline holds the dispatcher
        and the dispatcher holds this, so it is set after both are built."""
        self._pipeline = pipeline
        self._sessions = sessions

    def tools_for(self, principal: Principal) -> list[ToolRef]:
        """Every caller sees the tools that work: the await tool only where there are approvals."""
        found = [_definition("whoami", WHOAMI_DESCRIPTION, WHOAMI_SCHEMA, principal.tenant_id)]
        if self._approvals is not None:
            found.insert(
                0,
                _definition("await_approval", AWAIT_DESCRIPTION, AWAIT_SCHEMA, principal.tenant_id),
            )
        return found

    def tool(self, name: str, principal: Principal) -> ToolRef | None:
        for tool in self.tools_for(principal):
            if tool.name == name:
                return tool
        return None

    async def call(self, ctx: CallContext) -> ToolResult:
        try:
            if ctx.tool.name == WHOAMI:
                return self.whoami(ctx)
            if ctx.tool.name == AWAIT_APPROVAL and self._approvals is not None:
                return await self._await_approval(ctx, self._approvals)
            raise Reject(Code.TOOL_NOT_FOUND, f"there is no tool named {ctx.tool.name!r}")
        except Reject:
            # The pipeline marks a call as dispatched before it gets here. A refusal here means
            # nothing ran, and the audit record should say so.
            ctx.dispatched = False
            raise

    # -- keystone__whoami

    @staticmethod
    def whoami(ctx: CallContext) -> ToolResult:
        """The principal's fields and the session's state. The principal holds no token, and
        nothing else is added to what this returns."""
        principal, session = ctx.principal, ctx.session
        found: dict[str, Any] = {
            "principal": {
                "tenant_id": principal.tenant_id,
                "user_id": principal.user_id,
                "groups": list(principal.groups),
                "agent_id": principal.agent_id,
                "agent_trust": principal.agent_trust,
                "scopes": list(principal.scopes),
                "roles": list(principal.roles),
            },
            "flags": sorted(flag.value for flag in session.flags),
            "tainted": session.tainted,
            "call_count": session.call_count,
            "spent_usd": session.spent_usd,
        }
        return ToolResult(
            content=[{"type": "text", "text": json.dumps(found, sort_keys=True)}],
            structured_content=found,
        )

    # -- keystone__await_approval

    async def _await_approval(self, ctx: CallContext, approvals: Approvals) -> ToolResult:
        tenant_id = ctx.principal.tenant_id
        approval_id = str(ctx.arguments["approval_id"])
        wait_s = int(ctx.arguments.get("wait_seconds", DEFAULT_WAIT_S))
        record = await approvals.get(tenant_id, approval_id)
        # An id that does not exist, one of another tenant and one of another session get the
        # same answer, so the id cannot be probed for.
        if (
            record is None
            or record.session_id != ctx.session.session_id
            or record.requested_by_user != ctx.principal.user_id
            or record.requested_by_agent != ctx.principal.agent_id
        ):
            raise Reject(Code.DENIED, NOT_YOURS)
        if record.status == "consumed":
            raise Reject(Code.APPROVAL_EXPIRED, "this approval has been used already")
        outcome = await approvals.wait(approval_id, wait_s)
        if outcome == "pending":
            raise pending_rejection(await approvals.get(tenant_id, approval_id) or record)
        if outcome == "rejected":
            decided = await approvals.get(tenant_id, approval_id)
            note = decided.decision_note if decided else None
            raise Reject(Code.APPROVAL_REJECTED, note or "the request was rejected")
        if outcome == "expired":
            raise Reject(Code.APPROVAL_EXPIRED, "the request expired before it was used")
        return await self._run_approved(ctx, approvals, record)

    async def _run_approved(
        self, ctx: CallContext, approvals: Approvals, record: ApprovalRecord
    ) -> ToolResult:
        tenant_id = ctx.principal.tenant_id
        try:
            arguments = await approvals.load_args(record.id, tenant_id=tenant_id)
        except ApprovalError:
            raise Reject(Code.DENIED, "the stored request cannot be read") from None
        if arguments is None:
            # Used or expired between the answer and now.
            raise Reject(Code.APPROVAL_EXPIRED, NOT_VALID)
        tool = await self._registry.get(tenant_id, record.tool_name)
        if tool is None or tool.tenant_id != tenant_id or is_virtual(tool):
            raise Reject(Code.TOOL_NOT_FOUND, f"there is no tool named {record.tool_name!r}")
        if self._pipeline is None:
            raise RuntimeError("the virtual tools are not bound to a pipeline")
        await self._read_the_session_again(ctx)
        # The same principal and session, new call id and time, the original arguments, and the
        # id as a claim: the approval slot uses it, or refuses the call.
        inner = CallContext(
            call_id=new_id(),
            received_at=datetime.now(UTC),
            principal=ctx.principal,
            session=ctx.session,
            tool=tool,
            arguments=arguments,
            approval_id=record.id,
        )
        return await self._pipeline.run(inner)

    async def _read_the_session_again(self, ctx: CallContext) -> None:
        """The session this call carries was read when the await began, and the await may have
        waited for two minutes. In that time another call of the session can have read an
        injection, and the call that runs now is decided on the session as it is now, not as it
        was: a critical tool that a person approved before the taint does not run after it
        (invariant I8, ADR-0015). A session that cannot be read stops the call, and the approval
        stays unused."""
        if self._sessions is None:
            return
        try:
            await refresh(self._sessions, ctx.session)
        except Exception:
            log.error("session_store_failed", call_id=ctx.call_id, exc_info=True)
            raise Reject(Code.DENIED, "session state is unavailable") from None
