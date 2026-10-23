"""KS-602: the approval slot, with a stand-in for the service.

What matters here is the order of things on the context: an id is off it while the approval is
used and on it afterwards only if that worked, because the pipeline dispatches a call that needs
approval exactly when `approval_id` is set (KS-191, invariant I7).
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from keystone.approvals.service import ApprovalRecord, Outcome
from keystone.audit.redact import args_digest
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect
from keystone.gateway.interceptors.approval import ApprovalInterceptor
from tests.fixtures.calls import make_ctx, make_tool

pytestmark = pytest.mark.phase(6)

ARGS = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}
NEEDS_APPROVAL = Decision(
    effect=Effect.REQUIRE_APPROVAL, reasons=["approve-transfer-over-500"], source="policy"
)
WAIT = 7.5


def record(approval_id: str = "01JAPPROVAL", note: str | None = None) -> ApprovalRecord:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    return ApprovalRecord(
        id=approval_id,
        tenant_id="acme",
        session_id="session-1",
        call_id="01JCALL",
        tool_name="bank__transfer",
        args_redacted=ARGS,
        args_digest="d",
        reasons=("approve-transfer-over-500",),
        status="pending",
        requested_by_user="olivia",
        requested_by_agent="ops-agent",
        decided_by=None,
        decision_note=note,
        requested_at=now,
        decided_at=None,
        expires_at=now + timedelta(minutes=15),
        expires_in_s=900.0,
    )


class Gate:
    """A service that says what it is told to, and notes what the context held when it was asked."""

    def __init__(
        self, outcome: Outcome = "approved", consumes: bool | Exception = True, note: str = ""
    ) -> None:
        self.outcome: Outcome = outcome
        self.consumes = consumes
        self.note = note
        self.calls: list[tuple[str, Any]] = []
        self.ctx: CallContext | None = None
        self.id_on_context_at_consume: object = "not asked"
        self.missing = False

    async def request(self, ctx: CallContext, reasons: list[str]) -> str:
        self.calls.append(("request", reasons))
        return "01JAPPROVAL"

    async def wait(self, approval_id: str, timeout_s: float) -> Outcome:
        self.calls.append(("wait", (approval_id, timeout_s)))
        return self.outcome

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
        binding = {
            "tenant_id": tenant_id,
            "tool_name": tool_name,
            "session_id": session_id,
            "user_id": user_id,
        }
        self.calls.append(("consume", (approval_id, args_digest, binding)))
        assert self.ctx is not None
        self.id_on_context_at_consume = self.ctx.approval_id
        if isinstance(self.consumes, Exception):
            raise self.consumes
        return self.consumes

    async def get(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None:
        self.calls.append(("get", (tenant_id, approval_id)))
        return None if self.missing else record(note=self.note or None)


def call(gate: Gate, decision: Decision | None = NEEDS_APPROVAL, **fields: Any) -> CallContext:
    ctx = make_ctx(ARGS, make_tool("bank", "transfer"), decision=decision, **fields)
    gate.ctx = ctx
    return ctx


def slot(gate: Gate) -> ApprovalInterceptor:
    return ApprovalInterceptor(gate, wait_seconds=WAIT)


async def test_a_call_that_needs_no_approval_is_left_alone() -> None:
    gate = Gate()
    for decision in (None, Decision(effect=Effect.ALLOW, source="policy")):
        ctx = call(gate, decision)

        await slot(gate).before_call(ctx)

        assert ctx.approval_id is None
    assert gate.calls == []


async def test_an_id_on_a_call_that_needs_no_approval_is_dropped() -> None:
    """A claim means nothing when the policy allows the call outright, and an id left on the
    context would read as a consumed approval to anything that looks."""
    gate = Gate()
    ctx = call(gate, Decision(effect=Effect.ALLOW, source="policy"), approval_id="01JCLAIM")

    await slot(gate).before_call(ctx)

    assert ctx.approval_id is None
    assert gate.calls == []


async def test_a_claimed_id_is_off_the_context_while_it_is_used_and_on_it_after() -> None:
    gate = Gate()
    ctx = call(gate, approval_id="01JCLAIM")

    await slot(gate).before_call(ctx)

    [(name, (approval_id, digest, binding))] = gate.calls
    assert name == "consume" and approval_id == "01JCLAIM"
    assert digest == args_digest(ARGS)
    assert binding == {
        "tenant_id": "acme",
        "tool_name": "bank__transfer",
        "session_id": "session-1",
        "user_id": "olivia",
    }
    assert gate.id_on_context_at_consume is None
    assert ctx.approval_id == "01JCLAIM"


async def test_a_claimed_id_that_cannot_be_used_is_refused_and_leaves_nothing_on_the_context() -> (
    None
):
    gate = Gate(consumes=False)
    ctx = call(gate, approval_id="01JCLAIM")

    with pytest.raises(Reject) as refused:
        await slot(gate).before_call(ctx)

    assert refused.value.code is Code.APPROVAL_EXPIRED
    assert refused.value.message == "approval not valid for these arguments"
    assert ctx.approval_id is None


async def test_an_error_while_using_the_approval_leaves_nothing_on_the_context() -> None:
    gate = Gate(consumes=ConnectionError("the database went away"))
    ctx = call(gate, approval_id="01JCLAIM")

    with pytest.raises(ConnectionError):
        await slot(gate).before_call(ctx)

    assert ctx.approval_id is None


async def test_a_new_call_is_requested_with_the_reasons_and_held_for_the_wait() -> None:
    gate = Gate(outcome="pending")
    ctx = call(gate)

    with pytest.raises(Reject) as pending:
        await slot(gate).before_call(ctx)

    assert gate.calls[0] == ("request", ["approve-transfer-over-500"])
    assert gate.calls[1] == ("wait", ("01JAPPROVAL", WAIT))
    assert pending.value.code is Code.APPROVAL_PENDING
    # The id is where a program reads it and in the words a model reads, and not on the context.
    assert pending.value.data == {
        "keystone/approval_id": "01JAPPROVAL",
        "keystone/expires_at": "2026-10-23T12:15:00+00:00",
        "keystone/next": "call keystone__await_approval",
    }
    assert "01JAPPROVAL" in pending.value.message
    assert "keystone__await_approval" in pending.value.message
    assert ctx.approval_id is None


async def test_an_approval_that_comes_in_the_wait_is_used_and_the_call_goes_on() -> None:
    gate = Gate(outcome="approved")
    ctx = call(gate)

    await slot(gate).before_call(ctx)

    names = [name for name, _ in gate.calls]
    assert names == ["request", "wait", "consume"]
    assert gate.id_on_context_at_consume is None
    assert ctx.approval_id == "01JAPPROVAL"


async def test_an_approval_that_cannot_be_used_right_after_it_came_is_refused() -> None:
    gate = Gate(outcome="approved", consumes=False)
    ctx = call(gate)

    with pytest.raises(Reject) as refused:
        await slot(gate).before_call(ctx)

    assert refused.value.code is Code.APPROVAL_EXPIRED
    assert ctx.approval_id is None


@pytest.mark.parametrize(
    ("note", "message"),
    [("not this quarter", "not this quarter"), ("", "the request was rejected")],
)
async def test_a_rejection_carries_the_note(note: str, message: str) -> None:
    gate = Gate(outcome="rejected", note=note)
    ctx = call(gate)

    with pytest.raises(Reject) as rejected:
        await slot(gate).before_call(ctx)

    assert rejected.value.code is Code.APPROVAL_REJECTED
    assert rejected.value.message == message
    assert ctx.approval_id is None
    assert "consume" not in [name for name, _ in gate.calls]


async def test_a_request_that_expired_is_reported_as_expired() -> None:
    for gate in (Gate(outcome="expired"), Gate(outcome="pending")):
        gate.missing = gate.outcome == "pending"  # a row that has vanished is no longer waiting
        ctx = call(gate)

        with pytest.raises(Reject) as expired:
            await slot(gate).before_call(ctx)

        assert expired.value.code is Code.APPROVAL_EXPIRED
        assert ctx.approval_id is None


async def test_arguments_that_are_not_json_cannot_be_approved() -> None:
    gate = Gate()
    ctx = call(gate)
    ctx.arguments = {"amount": float("nan")}

    with pytest.raises(Reject) as refused:
        await slot(gate).before_call(ctx)

    assert refused.value.code is Code.DENIED
    assert gate.calls == []
