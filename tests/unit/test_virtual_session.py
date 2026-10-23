"""KS-705: the call an approval runs is decided on the session as it is when it runs.

`keystone__await_approval` can wait for two minutes, and the session it read when it began can be
tainted in that time by another call. The call it then runs through the pipeline must see the
taint, or an approval given before the taint would run a critical tool after it (invariant I8).
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from keystone.approvals.service import ApprovalRecord, Outcome
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Risk, SessionState, ToolRef, ToolResult
from keystone.gateway.sessions import InMemorySessionStore
from keystone.gateway.virtual_tools import AWAIT_APPROVAL, VirtualTools
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool

pytestmark = pytest.mark.phase(7)

SESSION_ID = "session-1"
APPROVAL_ID = "01JAPPROVEDREQUEST00000000"
TARGET = make_tool("echo", "echo", risk=Risk.LOW)


class Approvals:
    """A person has approved the one request, which is this session's."""

    async def get(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None:
        now = datetime.now(UTC)
        return ApprovalRecord(
            id=APPROVAL_ID,
            tenant_id="acme",
            session_id=SESSION_ID,
            call_id="01JCALL",
            tool_name=TARGET.name,
            args_redacted={"text": "x"},
            args_digest="d",
            reasons=("a-rule",),
            status="approved",
            requested_by_user=OLIVIA.user_id,
            requested_by_agent=OLIVIA.agent_id,
            decided_by="lena",
            decision_note=None,
            requested_at=now,
            decided_at=now,
            expires_at=now + timedelta(minutes=5),
            expires_in_s=300.0,
        )

    async def wait(self, approval_id: str, timeout_s: float) -> Outcome:
        return "approved"

    async def load_args(self, approval_id: str, *, tenant_id: str) -> dict[str, Any] | None:
        return {"text": "x"}


class Registry:
    async def get(self, tenant_id: str, name: str) -> ToolRef | None:
        return TARGET


class Pipeline:
    """What the call that the approval runs went through: the taint it saw when it began."""

    def __init__(self) -> None:
        self.ran: list[bool] = []

    async def run(self, ctx: CallContext) -> ToolResult:
        self.ran.append(ctx.session.tainted)
        return ToolResult(content=[{"type": "text", "text": "done"}])


class Unreadable(InMemorySessionStore):
    async def get(self, session_id: str) -> SessionState | None:
        raise ConnectionError("the store is down")


def await_call(session: SessionState) -> CallContext:
    ctx = make_ctx(
        {"approval_id": APPROVAL_ID, "wait_seconds": 1},
        make_tool("keystone", "await_approval", risk=Risk.LOW),
        session=session,
    )
    assert ctx.tool.name == AWAIT_APPROVAL
    return ctx


async def test_the_call_it_runs_sees_a_taint_recorded_since_the_await_began() -> None:
    store, pipeline = InMemorySessionStore(), Pipeline()
    tools = VirtualTools(Approvals(), Registry())
    tools.bind(pipeline, store)
    ctx = await_call(await store.create(SESSION_ID, OLIVIA))
    await store.mark_tainted(SESSION_ID)  # another call read an injection while the await waited
    assert ctx.session.tainted is False  # the copy the await holds is out of date

    await tools.call(ctx)

    assert pipeline.ran == [True]
    assert ctx.session.tainted is True


async def test_without_a_taint_the_call_runs_as_before() -> None:
    store, pipeline = InMemorySessionStore(), Pipeline()
    tools = VirtualTools(Approvals(), Registry())
    tools.bind(pipeline, store)

    await tools.call(await_call(await store.create(SESSION_ID, OLIVIA)))

    assert pipeline.ran == [False]


async def test_a_session_that_cannot_be_read_stops_the_call() -> None:
    pipeline = Pipeline()
    tools = VirtualTools(Approvals(), Registry())
    tools.bind(pipeline, Unreadable())
    ctx = await_call(await InMemorySessionStore().create(SESSION_ID, OLIVIA))

    with pytest.raises(Reject) as raised:
        await tools.call(ctx)

    # Nothing ran, so the approval was not used, and the agent is told why.
    assert raised.value.code is Code.DENIED and "session state" in raised.value.message
    assert pipeline.ran == []


async def test_without_a_store_the_call_runs_on_the_copy_it_has() -> None:
    pipeline = Pipeline()
    tools = VirtualTools(Approvals(), Registry())
    tools.bind(pipeline)

    await tools.call(await_call(await InMemorySessionStore().create(SESSION_ID, OLIVIA)))

    assert pipeline.ran == [False]
