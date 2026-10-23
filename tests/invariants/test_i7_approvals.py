"""I7: a `require_approval` call never dispatches without a matching approved, unexpired, unused
approval for the same arguments digest.

The real approval slot and the real service run in front of a dispatcher that only counts. A
policy sends every call to approval, and each call is then made with an approval id in every state
an id can be in, against arguments, a tool, a session and a user that are either the ones the
approval was made for or not. The call may dispatch in exactly one of those cases: an id that is
approved and unexpired, presented once, for the arguments, tool, session and user it was made
for. Everything else (an id nobody issued, one still pending, rejected, expired, already used, or
the right one presented for something else) must stop at the slot.

The same facts are checked once more through the MCP endpoint in `test_virtual_tools.py`, where
the only way to present an id is `keystone__await_approval`.
"""

import itertools
from collections.abc import Callable
from typing import Any

import anyio
import pytest
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.approvals.service import ApprovalService
from keystone.audit.redact import args_digest
from keystone.audit.sink import InMemoryAuditSink
from keystone.core.ids import new_id
from keystone.core.types import CallContext, Principal, SessionState
from keystone.db.models import APPROVALS
from keystone.identity.vault import Cipher
from keystone.settings import ApprovalSettings, Settings
from tests.fixtures.approvals import LENA, Approver, SpyDispatcher, approval_pipeline
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool
from tests.fixtures.keystone import TEST_MASTER_KEY, KeystoneApp, McpConnect
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(6), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]

ARGUMENTS = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}
OTHER_ARGUMENTS = {**ARGUMENTS, "amount": 90_000}
TRANSFER = make_tool("bank", "transfer", schema={"type": "object"})
OTHER_TOOL = make_tool("bank", "wire", schema={"type": "object"})  # the same arguments fit it
ALICE = Principal(tenant_id="acme", user_id="alice", agent_id="support-agent")
STATES = ["forged", "pending", "rejected", "approved", "used", "expired"]


async def expire(sessions: Sessions, approval_id: str) -> None:
    async with sessions() as session, session.begin():
        await session.execute(
            update(APPROVALS)
            .where(APPROVALS.c.id == approval_id)
            .values(expires_at=text("clock_timestamp() - interval '1 second'"))
        )


async def id_in_state(state: str, service: ApprovalService, sessions: Sessions) -> str:
    """An approval id that is in `state`, for a transfer of 900 by olivia in session-1."""
    if state == "forged":
        return new_id()  # well formed, and nobody issued it
    original = make_ctx(ARGUMENTS, TRANSFER)
    approval_id = await service.request(original, ["approve-transfer-over-500"])
    if state == "pending":
        return approval_id
    if state == "rejected":
        await service.decide(approval_id, LENA, False, "no")
        return approval_id
    await service.decide(approval_id, LENA, True)
    if state == "approved":
        return approval_id
    if state == "used":
        used = await service.consume(
            approval_id,
            args_digest(ARGUMENTS) or "",
            tenant_id="acme",
            tool_name="bank__transfer",
            session_id=original.session.session_id,
            user_id="olivia",
        )
        assert used
        return approval_id
    assert state == "expired"
    await expire(sessions, approval_id)
    return approval_id


def presented(
    approval_id: str, same_arguments: bool, same_tool: bool, same_session: bool, same_user: bool
) -> CallContext:
    """A call that presents `approval_id`, in the way the arguments, the tool, the session and the
    user are the same as the approval's or are not."""
    who = OLIVIA if same_user else ALICE
    session = SessionState(
        session_id="session-1" if same_session else "session-2",
        principal=who,
        created_at=make_ctx().received_at,
    )
    return make_ctx(
        ARGUMENTS if same_arguments else OTHER_ARGUMENTS,
        TRANSFER if same_tool else OTHER_TOOL,
        principal=who,
        session=session,
        approval_id=approval_id,
    )


async def test_i7(
    settings: Settings, approval_service: ApprovalService, sessionmaker: Sessions
) -> None:
    spy = SpyDispatcher()
    audit = InMemoryAuditSink()
    pipeline = approval_pipeline(settings, approval_service, spy, audit=audit)
    expected_dispatches = 0
    tried = 0

    for state in STATES:
        for same in itertools.product((True, False), repeat=4):
            approval_id = await id_in_state(state, approval_service, sessionmaker)
            ctx = presented(approval_id, *same)

            result = await pipeline.run(ctx)
            tried += 1

            valid = state == "approved" and all(same)
            where = f"{state}, same arguments/tool/session/user = {same}"
            if valid:
                expected_dispatches += 1
                assert not result.is_error, where
                assert ctx.dispatched and ctx.approval_id == approval_id, where
            else:
                assert result.is_error, where
                assert not ctx.dispatched and ctx.approval_id is None, where
            assert len(spy.calls) == expected_dispatches, where

    assert tried == len(STATES) * 16
    assert expected_dispatches == 1
    # What did dispatch did so under the id it consumed, with the arguments that were approved.
    [(tool, arguments, dispatched_under)] = spy.calls
    assert (tool, arguments) == ("bank__transfer", ARGUMENTS)
    consumed = [a.id for a in await approval_service.list_for_tenant("acme", "consumed")]
    assert dispatched_under in consumed
    # Every refusal is an expired approval, and each left its audit record.
    refusals = [r for r in audit.records if r["outcome"] == "rejected"]
    assert len(refusals) == tried - 1
    assert {r["reject_code"] for r in refusals} == {"KS_APPROVAL_EXPIRED"}
    assert not any(r["dispatched"] for r in refusals)


async def test_i7_an_approval_is_used_by_one_of_two_calls_that_present_it_together(
    settings: Settings, approval_service: ApprovalService, sessionmaker: Sessions
) -> None:
    """Eight calls present the same approved id at once. Exactly one reaches the upstream."""
    spy = SpyDispatcher()
    pipeline = approval_pipeline(settings, approval_service, spy)
    approval_id = await id_in_state("approved", approval_service, sessionmaker)
    results: list[Any] = []

    async def present() -> None:
        results.append(await pipeline.run(presented(approval_id, True, True, True, True)))

    async with anyio.create_task_group() as tasks:
        for _ in range(8):
            tasks.start_soon(present)

    assert len(spy.calls) == 1
    assert sorted(r.is_error for r in results) == [False] + [True] * 7


async def test_i7_a_call_with_no_id_is_held_not_dispatched(
    settings: Settings, approval_service: ApprovalService
) -> None:
    spy = SpyDispatcher()
    pipeline = approval_pipeline(settings, approval_service, spy)

    ctx = make_ctx(ARGUMENTS, TRANSFER)
    result = await pipeline.run(ctx)

    assert result.is_error and spy.calls == [] and ctx.approval_id is None
    [waiting] = await approval_service.list_for_tenant("acme", "pending")
    assert waiting.args_digest == args_digest(ARGUMENTS)


# -- the same, through the MCP endpoint, where an id can only be presented to the await tool

Factory = Callable[..., KeystoneApp]
AWAIT = "keystone__await_approval"
TRANSFER_CALL = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}


async def test_i7_through_the_await_tool(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
    sessionmaker: Sessions,
) -> None:
    """An agent has one way to present an approval id: keystone__await_approval. Every bad id it
    can bring leaves the bank untouched, and the one good id moves 900 once."""
    app = keystone_app_factory(
        settings={"approvals": ApprovalSettings(wait_seconds=0, poll_interval_s=0.2)}
    )
    cipher = Cipher(TEST_MASTER_KEY)
    refused: dict[str, str] = {}

    def transfers() -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = demo_upstreams.state("bank")["transfers"]  # type: ignore[assignment]
        return found

    async def present(olivia: Any, approval_id: str, name: str) -> Any:
        result = await olivia.call_tool(AWAIT, {"approval_id": approval_id, "wait_seconds": 0})
        assert result.is_error, name
        refused[name] = result.meta["keystone/code"]
        assert transfers() == [], name
        return result

    async def asked(olivia: Any, amount: int = 900) -> str:
        result = await olivia.call_tool("bank__transfer", {**TRANSFER_CALL, "amount": amount})
        return str(result.meta["keystone/approval_id"])

    async with mcp_client(app, user="olivia") as olivia:
        await present(olivia, new_id(), "forged")

        waiting = await asked(olivia)
        await present(olivia, waiting, "pending")

        rejected = await asked(olivia)
        await approver.service.decide(rejected, LENA, False, "no")
        await present(olivia, rejected, "rejected")

        stale = await asked(olivia)
        await approver.service.decide(stale, LENA, True)
        await expire(sessionmaker, stale)
        await present(olivia, stale, "expired")

        # Arguments swapped in the table for others, encrypted under the right key: the digest
        # that was approved is no longer the digest of what would run.
        swapped = await asked(olivia)
        await approver.service.decide(swapped, LENA, True)
        async with sessionmaker() as session, session.begin():
            await session.execute(
                update(APPROVALS)
                .where(APPROVALS.c.id == swapped)
                .values(args_ciphertext=cipher.encrypt_json({**TRANSFER_CALL, "amount": 90_000}))
            )
        await present(olivia, swapped, "changed arguments")

        # The one good id: approved, unexpired, unused, for exactly what was asked.
        good = await asked(olivia)
        await approver.service.decide(good, LENA, True)
        done = await olivia.call_tool(AWAIT, {"approval_id": good, "wait_seconds": 5})
        assert not done.is_error
        assert [t["amount"] for t in transfers()] == [900.0]
        again = await olivia.call_tool(AWAIT, {"approval_id": good, "wait_seconds": 0})

    assert again.is_error and again.meta is not None
    assert again.meta["keystone/code"] == "KS_APPROVAL_EXPIRED"
    assert refused == {
        "forged": "KS_DENIED",
        "pending": "KS_APPROVAL_PENDING",
        "rejected": "KS_APPROVAL_REJECTED",
        "expired": "KS_APPROVAL_EXPIRED",
        "changed arguments": "KS_DENIED",
    }
    # 900 moved once. The rest never reached the bank.
    assert [t["amount"] for t in transfers()] == [900.0]
    dispatched = [
        r for r in app.audit.records if r["tool_name"] == "bank__transfer" and r["dispatched"]
    ]
    assert len(dispatched) == 1
