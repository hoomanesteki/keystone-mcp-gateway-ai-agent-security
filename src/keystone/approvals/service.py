"""Approval requests: each one is specific, time-limited and used once (KS-601, ADR-0010).

A call that the policy sends to approval becomes a row in `approvals`. The row holds what a person
needs to decide (the tool, the arguments with secrets masked, who asked, which rules asked) and
what the call needs to run later: the original arguments, encrypted, and the digest of them. The
digest is the one the audit log writes as `args_digest` (KS-502), so an approval is for exactly
those arguments and no others.

Four rules make an approval safe to hand out, and each is one SQL statement, so it holds however
many gateways run and however they interleave:

- `decide` changes a row only while it is pending, unexpired, in the approver's tenant and not
  requested by the approver (separation of duties). Two decisions at once leave one.
- `consume` changes a row only while it is approved, unexpired, and for this tenant, tool, session,
  user and arguments digest. It returns whether it did, so a second use finds nothing.
- Neither can act on an expired row, even in a race. They compare `expires_at` with
  `clock_timestamp()`, the wall clock at the moment the row is checked, and not with `now()`, which
  is the start of the transaction. A statement that waits for a row lock (a second decision, the
  sweeper) is judged by `now()` as of before it waited, and so could change a row after its
  expiry. `tests/integration/test_approvals_service.py` holds a lock across an expiry to show it.
- `expires_at` comes from the database clock too, so gateways with clocks that differ agree.

A message on Redis wakes a waiter early, and the database is what it believes: the message carries
no verdict, and a waiter reads the row again whenever it wakes, on a message or after
`poll_interval_s`. Redis being away costs the early wake-up and nothing else.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

import anyio
import structlog
from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from sqlalchemy import ColumnElement, DateTime, and_, case, extract, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.audit.normalize import clean_text
from keystone.audit.redact import RedactionConfig, audit_arguments
from keystone.audit.redact import args_digest as digest_of
from keystone.core.ids import new_id
from keystone.core.types import CallContext, Principal
from keystone.db.models import APPROVALS
from keystone.identity.vault import Cipher, VaultError
from keystone.telemetry.metrics import Metrics

log = structlog.get_logger()

Status = Literal["pending", "approved", "rejected", "expired", "consumed"]
# What `wait` reports. A used approval is "expired" to a waiter: it can no longer be used.
Outcome = Literal["approved", "rejected", "expired", "pending"]

APPROVER_ROLES = frozenset({"approver", "admin"})
MAX_NOTE_CHARS = 500
PUBLISH_TIMEOUT_S = 1.0
SUBSCRIBE_TIMEOUT_S = 1.0
CLOSE_TIMEOUT_S = 1.0
# Rows that can still be used, and so can run out of time.
OPEN_STATUSES = ("pending", "approved")


def request_channel(tenant_id: str) -> str:
    """New requests of a tenant (plan section 3.7 names it `ks:approvals:{tenant}`)."""
    return f"ks:approvals:{tenant_id}"


def decision_channel(approval_id: str) -> str:
    """The decision on one request: `ks:approval:{id}`."""
    return f"ks:approval:{approval_id}"


class ApprovalError(Exception):
    """Something about an approval that the caller cannot go on with. The message is for a log or
    for an API answer, and never holds an argument."""


class ApprovalNotFound(ApprovalError):
    """There is no such request in the caller's tenant. A request of another tenant looks the same,
    so the answer does not say it exists."""


class NotAnApprover(ApprovalError):
    """The caller does not have the `approver` or `admin` role."""


class OwnRequest(ApprovalError):
    """The caller made the request. Nobody approves their own (separation of duties)."""


class NotPending(ApprovalError):
    """The request is no longer waiting for a decision: it was decided, used or it expired."""

    def __init__(self, status: str) -> None:
        super().__init__(f"the request is {status}")
        self.status = status


@dataclass(frozen=True)
class ApprovalRecord:
    """A request as it can be shown: no ciphertext, and the arguments with secrets masked.
    `status` is the effective one, so a request past its time reads "expired" before the sweeper
    has marked it. `expires_in_s` is counted by the database and is negative once it has passed."""

    id: str
    tenant_id: str
    session_id: str
    call_id: str
    tool_name: str
    args_redacted: Any
    args_digest: str
    reasons: tuple[str, ...]
    status: Status
    requested_by_user: str
    requested_by_agent: str
    decided_by: str | None
    decision_note: str | None
    requested_at: datetime
    decided_at: datetime | None
    expires_at: datetime
    expires_in_s: float


def _now() -> ColumnElement[datetime]:
    return func.clock_timestamp(type_=DateTime(timezone=True))


def _effective_status() -> ColumnElement[str]:
    """The status with time taken into account: an open request past its time is expired."""
    return case(
        (
            and_(APPROVALS.c.status.in_(OPEN_STATUSES), APPROVALS.c.expires_at <= _now()),
            "expired",
        ),
        else_=APPROVALS.c.status,
    )


def _columns() -> list[ColumnElement[Any]]:
    c = APPROVALS.c
    return [
        c.id,
        c.tenant_id,
        c.session_id,
        c.call_id,
        c.tool_name,
        c.args_redacted,
        c.args_digest,
        c.reasons,
        _effective_status().label("status"),
        c.requested_by_user,
        c.requested_by_agent,
        c.decided_by,
        c.decision_note,
        c.requested_at,
        c.decided_at,
        c.expires_at,
        extract("epoch", c.expires_at - _now()).label("expires_in_s"),
    ]


def _record(row: Mapping[Any, Any]) -> ApprovalRecord:
    return ApprovalRecord(
        id=row["id"],
        tenant_id=row["tenant_id"],
        session_id=row["session_id"],
        call_id=row["call_id"],
        tool_name=row["tool_name"],
        args_redacted=row["args_redacted"],
        args_digest=row["args_digest"],
        reasons=tuple(row["reasons"]),
        status=row["status"],
        requested_by_user=row["requested_by_user"],
        requested_by_agent=row["requested_by_agent"],
        decided_by=row["decided_by"],
        decision_note=row["decision_note"],
        requested_at=row["requested_at"],
        decided_at=row["decided_at"],
        expires_at=row["expires_at"],
        expires_in_s=float(row["expires_in_s"]),
    )


def _outcome(status: str) -> Outcome:
    if status in ("approved", "rejected", "pending"):
        return status  # type: ignore[return-value]
    return "expired"


class ApprovalService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        cipher: Cipher,
        *,
        redis: Redis | None = None,
        ttl_s: float = 900.0,
        poll_interval_s: float = 2.0,
        sweep_interval_s: float = 30.0,
        redaction: RedactionConfig | None = None,
        metrics: Metrics | None = None,
        on_request: Callable[[ApprovalRecord], None] | None = None,
    ) -> None:
        self._sessions = sessions
        self._cipher = cipher
        self._redis = redis
        self._ttl_s = ttl_s
        self._poll_interval_s = poll_interval_s
        self._sweep_interval_s = sweep_interval_s
        self._redaction = redaction
        self._metrics = metrics
        # Told of each new request after it is stored. It must not block (the webhook notifier
        # queues and returns), and an exception from it is logged and goes no further.
        self._on_request = on_request

    # -- asking

    async def request(self, ctx: CallContext, reasons: list[str]) -> str:
        """Store a pending request for this call and return its id. The arguments are kept
        encrypted, and masked for the people who read them."""
        digest = digest_of(ctx.arguments)
        if digest is None:
            raise ApprovalError("the arguments are not JSON, so they cannot be approved")
        shown, _ = audit_arguments(ctx.arguments, self._redaction)
        approval_id = new_id()
        statement = (
            insert(APPROVALS)
            .values(
                id=approval_id,
                tenant_id=clean_text(ctx.principal.tenant_id),
                session_id=clean_text(ctx.session.session_id),
                call_id=clean_text(ctx.call_id),
                tool_name=clean_text(ctx.tool.name),
                args_redacted=shown,
                args_digest=digest,
                args_ciphertext=self._cipher.encrypt_json(ctx.arguments),
                reasons=[clean_text(reason) for reason in reasons],
                status="pending",
                requested_by_user=clean_text(ctx.principal.user_id),
                requested_by_agent=clean_text(ctx.principal.agent_id),
                expires_at=_now() + timedelta(seconds=self._ttl_s),
            )
            .returning(*_columns())
        )
        async with self._sessions() as session, session.begin():
            record = _record((await session.execute(statement)).mappings().one())
        log.info(
            "approval_requested",
            approval=approval_id,
            tenant=record.tenant_id,
            tool=record.tool_name,
            reasons=list(record.reasons),
        )
        await self._publish(
            request_channel(record.tenant_id), {"event": "requested", "id": approval_id}
        )
        self._tell_the_listener(record)
        await self.refresh_pending()
        return approval_id

    # -- deciding

    async def decide(
        self, approval_id: str, approver: Principal, approve: bool, note: str | None = None
    ) -> ApprovalRecord:
        """Approve or reject a pending request. One statement: the row changes only if it is
        pending, unexpired, of the approver's tenant and not the approver's own."""
        if not APPROVER_ROLES.intersection(approver.roles):
            raise NotAnApprover("the approver or admin role is required")
        user = clean_text(approver.user_id)
        wanted: Status = "approved" if approve else "rejected"
        statement = (
            update(APPROVALS)
            .where(
                APPROVALS.c.id == approval_id,
                APPROVALS.c.tenant_id == clean_text(approver.tenant_id),
                APPROVALS.c.status == "pending",
                APPROVALS.c.expires_at > _now(),
                APPROVALS.c.requested_by_user != user,
            )
            .values(
                status=wanted,
                decided_by=user,
                decision_note=_clean_note(note),
                decided_at=_now(),
            )
            .returning(*_columns())
        )
        async with self._sessions() as session, session.begin():
            row = (await session.execute(statement)).mappings().first()
        if row is None:
            raise await self._why_not_decided(approval_id, approver)
        record = _record(row)
        log.info(
            "approval_decided", approval=approval_id, tenant=record.tenant_id, status=record.status
        )
        await self._publish(decision_channel(approval_id), {"status": record.status})
        await self.refresh_pending()
        return record

    async def _why_not_decided(self, approval_id: str, approver: Principal) -> ApprovalError:
        """Which refusal fits a decision that changed nothing. The statement above is what decides;
        this only reads the row afterwards to pick the words, and a row that moved in between is
        reported as it is then."""
        statement = select(
            APPROVALS.c.tenant_id,
            APPROVALS.c.requested_by_user,
            _effective_status().label("status"),
        ).where(APPROVALS.c.id == approval_id)
        async with self._sessions() as session:
            row = (await session.execute(statement)).first()
        if row is None or row.tenant_id != clean_text(approver.tenant_id):
            return ApprovalNotFound(f"there is no approval request {approval_id!r}")
        if row.requested_by_user == clean_text(approver.user_id):
            return OwnRequest("you cannot decide a request you made")
        return NotPending("expired" if row.status == "pending" else row.status)

    # -- using

    async def consume(
        self,
        approval_id: str,
        args_digest: str,
        *,
        tenant_id: str,
        tool_name: str,
        session_id: str,
        user_id: str,
    ) -> bool:
        """Use an approval, once. True only if it was approved, has not expired, and was made for
        this tenant, tool, session, user and arguments digest. One UPDATE, so of two calls that
        present the same approval at once exactly one gets True."""
        statement = (
            update(APPROVALS)
            .where(
                APPROVALS.c.id == approval_id,
                APPROVALS.c.tenant_id == clean_text(tenant_id),
                APPROVALS.c.status == "approved",
                APPROVALS.c.args_digest == args_digest,
                APPROVALS.c.tool_name == clean_text(tool_name),
                APPROVALS.c.session_id == clean_text(session_id),
                APPROVALS.c.requested_by_user == clean_text(user_id),
                APPROVALS.c.expires_at > _now(),
            )
            .values(status="consumed")
            .returning(APPROVALS.c.id)
        )
        async with self._sessions() as session, session.begin():
            return (await session.execute(statement)).first() is not None

    async def load_args(self, approval_id: str, *, tenant_id: str) -> dict[str, Any] | None:
        """The original arguments of an approval that can still be used, decrypted. None for any
        other state, so the stored arguments do not leave the table for a request that was not
        approved, was used or expired. They are checked against the digest before they are
        returned. Raises ApprovalError when they cannot be read."""
        statement = select(APPROVALS.c.args_ciphertext, APPROVALS.c.args_digest).where(
            APPROVALS.c.id == approval_id,
            APPROVALS.c.tenant_id == clean_text(tenant_id),
            APPROVALS.c.status == "approved",
            APPROVALS.c.expires_at > _now(),
        )
        async with self._sessions() as session:
            row = (await session.execute(statement)).first()
        if row is None:
            return None
        try:
            arguments = self._cipher.decrypt_json(bytes(row.args_ciphertext))
        except VaultError:
            log.error("approval_arguments_unreadable", approval=approval_id)
            raise ApprovalError("the stored arguments cannot be read") from None
        if not isinstance(arguments, dict) or digest_of(arguments) != row.args_digest:
            log.error("approval_arguments_changed", approval=approval_id)
            raise ApprovalError("the stored arguments do not match their digest")
        return arguments

    # -- reading

    async def get(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None:
        statement = select(*_columns()).where(
            APPROVALS.c.id == approval_id, APPROVALS.c.tenant_id == clean_text(tenant_id)
        )
        async with self._sessions() as session:
            row = (await session.execute(statement)).mappings().first()
        return _record(row) if row is not None else None

    async def list_for_tenant(
        self, tenant_id: str, status: Status = "pending", limit: int = 100
    ) -> list[ApprovalRecord]:
        """The tenant's requests in one state. A queue is oldest first, so the request that has
        waited longest is on top; a history is newest first."""
        order = (
            (APPROVALS.c.requested_at.asc(), APPROVALS.c.id.asc())
            if status == "pending"
            else (APPROVALS.c.requested_at.desc(), APPROVALS.c.id.desc())
        )
        statement = (
            select(*_columns())
            .where(APPROVALS.c.tenant_id == clean_text(tenant_id), _effective_status() == status)
            .order_by(*order)
            .limit(limit)
        )
        async with self._sessions() as session:
            return [_record(row) for row in (await session.execute(statement)).mappings()]

    async def _status(self, approval_id: str) -> str | None:
        statement = select(_effective_status()).where(APPROVALS.c.id == approval_id)
        async with self._sessions() as session:
            return (await session.execute(statement)).scalar_one_or_none()

    # -- waiting

    async def wait(self, approval_id: str, timeout_s: float) -> Outcome:
        """Wait up to `timeout_s` for a decision. Returns "approved", "rejected", "expired", or
        "pending" if the time ran out first. A message wakes it at once; without Redis it looks
        at the row every `poll_interval_s`. A verdict is always read from the row, never from a
        message."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        async with self._subscribed(approval_id) as pause:
            while True:
                status = await self._status(approval_id)
                if status is None:
                    return "expired"
                if status != "pending":
                    return _outcome(status)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "pending"
                await pause(min(self._poll_interval_s, remaining))

    @asynccontextmanager
    async def _subscribed(
        self, approval_id: str
    ) -> AsyncIterator[Callable[[float], Awaitable[None]]]:
        """A way to pause until a decision is announced or `seconds` pass, whichever is first. The
        subscription is made before the caller reads the row, so a decision cannot fall between
        the read and the wait. If Redis fails the pause becomes a plain sleep."""
        pubsub: PubSub | None = None
        if self._redis is not None:
            pubsub = self._redis.pubsub()
            try:
                with anyio.fail_after(SUBSCRIBE_TIMEOUT_S):
                    await pubsub.subscribe(decision_channel(approval_id))
            except Exception as exc:
                log.warning("approval_subscribe_failed", error=type(exc).__name__)
                await self._close(pubsub)
                pubsub = None

        async def pause(seconds: float) -> None:
            nonlocal pubsub
            if pubsub is None:
                await anyio.sleep(seconds)
                return
            try:
                with anyio.fail_after(seconds + SUBSCRIBE_TIMEOUT_S):
                    await pubsub.get_message(ignore_subscribe_messages=True, timeout=seconds)
            except Exception as exc:
                log.warning("approval_wait_degraded", error=type(exc).__name__)
                await self._close(pubsub)
                pubsub = None
                await anyio.sleep(seconds)

        try:
            yield pause
        finally:
            await self._close(pubsub)

    @staticmethod
    async def _close(pubsub: PubSub | None) -> None:
        if pubsub is None:
            return
        # A cancelled waiter (the agent went away) still gives its connection back.
        with anyio.CancelScope(shield=True), anyio.move_on_after(CLOSE_TIMEOUT_S):
            try:
                await pubsub.aclose()  # type: ignore[no-untyped-call]
            except Exception as exc:
                log.debug("approval_unsubscribe_failed", error=type(exc).__name__)

    # -- time

    async def sweep(self) -> int:
        """Mark every open request that ran out of time as expired, and wake whoever waits for
        it. Returns how many it marked. Nothing depends on this for safety: `decide` and
        `consume` refuse an expired row whether or not it has been marked."""
        statement = (
            update(APPROVALS)
            .where(APPROVALS.c.status.in_(OPEN_STATUSES), APPROVALS.c.expires_at <= _now())
            .values(status="expired")
            .returning(APPROVALS.c.id, APPROVALS.c.tenant_id)
        )
        async with self._sessions() as session, session.begin():
            marked = [(row.id, row.tenant_id) for row in await session.execute(statement)]
        for approval_id, _tenant in marked:
            await self._publish(decision_channel(approval_id), {"status": "expired"})
        if marked:
            log.info("approvals_expired", count=len(marked))
            await self.refresh_pending()
        return len(marked)

    async def run_sweeper(self) -> None:
        """Sweep every `sweep_interval_s`, forever. A failed sweep is logged and tried again at
        the next interval. Cancel it to stop."""
        await self.refresh_pending()
        while True:
            await anyio.sleep(self._sweep_interval_s)
            try:
                await self.sweep()
            except Exception as exc:
                log.error("approval_sweep_failed", error=type(exc).__name__)

    # -- telling others

    async def refresh_pending(self) -> None:
        """Set `keystone_approvals_pending` from the table. A failure is logged and changes
        nothing else."""
        if self._metrics is None:
            return
        statement = (
            select(APPROVALS.c.tenant_id, func.count())
            .where(APPROVALS.c.status == "pending", APPROVALS.c.expires_at > _now())
            .group_by(APPROVALS.c.tenant_id)
        )
        try:
            async with self._sessions() as session:
                counts = {str(t): int(n) for t, n in (await session.execute(statement)).all()}
            self._metrics.approvals_changed(counts)
        except Exception as exc:
            log.warning("approval_gauge_not_set", error=type(exc).__name__)

    async def _publish(self, channel: str, message: Mapping[str, Any]) -> None:
        if self._redis is None:
            return
        try:
            with anyio.fail_after(PUBLISH_TIMEOUT_S):
                await self._redis.publish(channel, json.dumps(message))
        except Exception as exc:
            # The row is the truth and waiters poll, so a lost message only costs a short delay.
            log.warning("approval_publish_failed", error=type(exc).__name__)

    def _tell_the_listener(self, record: ApprovalRecord) -> None:
        if self._on_request is None:
            return
        try:
            self._on_request(record)
        except Exception as exc:
            log.error("approval_listener_failed", error=type(exc).__name__)


def _clean_note(note: str | None) -> str | None:
    if note is None:
        return None
    cleaned = clean_text(note.strip())[:MAX_NOTE_CHARS]
    return cleaned or None


__all__ = [
    "APPROVER_ROLES",
    "ApprovalError",
    "ApprovalNotFound",
    "ApprovalRecord",
    "ApprovalService",
    "NotAnApprover",
    "NotPending",
    "Outcome",
    "OwnRequest",
    "Status",
    "decision_channel",
    "request_channel",
]
