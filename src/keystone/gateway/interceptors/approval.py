"""The approval slot: a call the policy sent to approval waits for a person (KS-602, ADR-0010).

For a `require_approval` decision the slot does one of two things.

A new call is stored as a request, and held in line for `approvals.wait_seconds`. If a person
approves it in that time it is used (once) and the call goes on. If a person rejects it the agent
gets `KS_APPROVAL_REJECTED` with the note; if it expires, `KS_APPROVAL_EXPIRED`. If nobody decides
in time the agent gets `KS_APPROVAL_PENDING` with the id, in the text and in `_meta`, and calls
`keystone__await_approval` to wait longer.

A call that arrives with an approval id on it is the re-entry from `keystone__await_approval`. The
id is a claim and not yet an approval. The slot takes it off the context, uses the approval, and
puts the id back only if that worked. The pipeline dispatches a `require_approval` call only when
`ctx.approval_id` is set (KS-191), so the id is on the context at dispatch exactly when this slot
consumed an approval for these arguments, this tool, this session and this user (invariant I7).
A pending call's id travels in the rejection, never on the context.
"""

from __future__ import annotations

from typing import Protocol

import structlog

from keystone.approvals.service import ApprovalRecord, Outcome
from keystone.audit.redact import args_digest
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Effect

log = structlog.get_logger()

NOT_VALID = "approval not valid for these arguments"
NEXT = "call keystone__await_approval"
ID_KEY = "keystone/approval_id"
EXPIRES_KEY = "keystone/expires_at"
NEXT_KEY = "keystone/next"


class ApprovalGate(Protocol):
    """The part of the approval service this slot uses."""

    async def request(self, ctx: CallContext, reasons: list[str]) -> str: ...

    async def wait(self, approval_id: str, timeout_s: float) -> Outcome: ...

    async def consume(
        self,
        approval_id: str,
        args_digest: str,
        *,
        tenant_id: str,
        tool_name: str,
        session_id: str,
        user_id: str,
    ) -> bool: ...

    async def get(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None: ...


def pending_rejection(record: ApprovalRecord) -> Reject:
    """What an agent is told while a request waits: the id where a model reads it (the text) and
    where a program does (`_meta`). Also what `keystone__await_approval` says when its own wait
    runs out."""
    expires = record.expires_at.isoformat()
    return Reject(
        Code.APPROVAL_PENDING,
        f"approval {record.id} was requested and no one has decided it yet. Call "
        f"keystone__await_approval with approval_id {record.id} to wait for the decision; the "
        f"request expires at {expires}",
        {ID_KEY: record.id, EXPIRES_KEY: expires, NEXT_KEY: NEXT},
    )


class ApprovalInterceptor:
    name = "approval"

    def __init__(self, service: ApprovalGate, *, wait_seconds: float) -> None:
        self._service = service
        self._wait_seconds = wait_seconds

    async def before_call(self, ctx: CallContext) -> None:
        # Off the context first, whatever happens next: an id that is on the context at dispatch
        # must be one this slot consumed.
        claimed, ctx.approval_id = ctx.approval_id, None
        decision = ctx.decision
        if decision is None or decision.effect is not Effect.REQUIRE_APPROVAL:
            return
        digest = args_digest(ctx.arguments)
        if digest is None:
            raise Reject(Code.DENIED, "the arguments cannot be approved")
        if claimed:
            await self._use(ctx, claimed, digest)
            return
        approval_id = await self._service.request(ctx, list(decision.reasons))
        outcome = await self._service.wait(approval_id, self._wait_seconds)
        if outcome == "approved":
            await self._use(ctx, approval_id, digest)
            return
        record = await self._service.get(ctx.principal.tenant_id, approval_id)
        if outcome == "rejected":
            note = record.decision_note if record else None
            raise Reject(Code.APPROVAL_REJECTED, note or "the request was rejected")
        if outcome == "expired" or record is None:
            raise Reject(Code.APPROVAL_EXPIRED, "the request expired before it was decided")
        raise pending_rejection(record)

    async def after_call(self, ctx: CallContext) -> None:
        return None

    async def _use(self, ctx: CallContext, approval_id: str, digest: str) -> None:
        used = await self._service.consume(
            approval_id,
            digest,
            tenant_id=ctx.principal.tenant_id,
            tool_name=ctx.tool.name,
            session_id=ctx.session.session_id,
            user_id=ctx.principal.user_id,
        )
        if not used:
            raise Reject(Code.APPROVAL_EXPIRED, NOT_VALID)
        # The one place the id goes back on the context.
        ctx.approval_id = approval_id
