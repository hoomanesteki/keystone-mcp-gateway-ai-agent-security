"""Helpers for tests of approvals: a person who decides, and a pipeline over a real service.

The app under test runs in a thread with an event loop of its own, and its approval service is
bound to that loop. A test cannot call it, and should not: the person at the console reaches the
app through the table and a message on Redis, never through a call into its process. `Approver`
is that person. It is an `ApprovalService` of the test's own, on the same database and the same
Redis as the app, and a decision it makes wakes the app's waiting call the way the console's does.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import anyio
import pytest
from cryptography.fernet import Fernet
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.approvals.service import ApprovalRecord, ApprovalService
from keystone.audit.sink import InMemoryAuditSink
from keystone.core.types import CallContext, Decision, Effect, Principal, ToolResult
from keystone.gateway.pipeline import Pipeline
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.identity.vault import Cipher
from keystone.settings import ApprovalSettings, Settings

LENA = Principal(
    tenant_id="acme",
    user_id="lena",
    groups=("approvers",),
    agent_id="keystone-cli",
    roles=("approver",),
)
ROOT = Principal(
    tenant_id="acme",
    user_id="root",
    groups=("admins",),
    agent_id="keystone-cli",
    roles=("admin",),
)
POLL_S = 0.1
FIND_TIMEOUT_S = 15.0


class Approver:
    def __init__(self, service: ApprovalService) -> None:
        self.service = service

    async def pending(self, count: int = 1, tenant: str = "acme") -> list[ApprovalRecord]:
        """The tenant's pending requests, once there are at least `count` of them."""
        with anyio.fail_after(FIND_TIMEOUT_S):
            while True:
                found = await self.service.list_for_tenant(tenant, "pending")
                if len(found) >= count:
                    return found
                await anyio.sleep(POLL_S)

    async def approve(
        self, note: str | None = None, *, who: Principal = LENA, which: int = 0
    ) -> ApprovalRecord:
        """Approve the oldest pending request, or the `which`-th, when it appears."""
        found = await self.pending(which + 1)
        return await self.service.decide(found[which].id, who, True, note)

    async def reject(
        self, note: str | None = None, *, who: Principal = LENA, which: int = 0
    ) -> ApprovalRecord:
        found = await self.pending(which + 1)
        return await self.service.decide(found[which].id, who, False, note)


@pytest.fixture
def approval_service(
    sessionmaker: async_sessionmaker[AsyncSession], redis: Redis
) -> ApprovalService:
    """A service of the test's own. Its keys are its own: it can ask, decide and read, and it
    cannot open what the app under test encrypted."""
    cipher = Cipher(Fernet.generate_key().decode())
    return ApprovalService(sessionmaker, cipher, redis=redis, poll_interval_s=POLL_S)


@pytest.fixture
def approver(approval_service: ApprovalService) -> Approver:
    return Approver(approval_service)


class SpyDispatcher:
    """Stands in for the upstream, and notes every call that reaches it: the tool, the arguments
    and the approval id the context held at that moment."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str | None]] = []

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        self.calls.append((ctx.tool.name, dict(ctx.arguments), ctx.approval_id))
        return ToolResult(content=[{"type": "text", "text": "dispatched"}])


class AsksForApproval:
    """A policy slot that sends every call to approval, the way the transfer rule sends the ones
    over 500."""

    name = "policy"

    def __init__(self, reasons: Sequence[str] = ("approve-transfer-over-500",)) -> None:
        self.reasons = list(reasons)

    async def before_call(self, ctx: CallContext) -> None:
        ctx.decision = Decision(
            effect=Effect.REQUIRE_APPROVAL, reasons=list(self.reasons), source="policy"
        )

    async def after_call(self, ctx: CallContext) -> None:
        return None


def approval_pipeline(
    settings: Settings,
    service: ApprovalService,
    dispatcher: SpyDispatcher,
    *,
    wait_seconds: float = 0.0,
    audit: InMemoryAuditSink | None = None,
) -> Pipeline:
    """The real approval slot over `service`, behind a policy that asks for every call, in front
    of `dispatcher`. A wait of 0 sends a new call straight to KS_APPROVAL_PENDING."""
    configured = settings.model_copy(
        update={"approvals": ApprovalSettings(wait_seconds=wait_seconds)}
    )
    return build_pipeline(
        configured,
        PipelineDeps(dispatcher=dispatcher, audit=audit or InMemoryAuditSink(), approvals=service),
        {"policy": AsksForApproval()},
    )
