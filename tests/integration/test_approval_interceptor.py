"""KS-602: a call that needs approval waits for a person and then completes.

The app runs the real policy files, so olivia's transfer of 900 is sent to approval by
`approve-transfer-over-500`. A test plays the approver with `Approver`, which decides through the
table and Redis as the console would. The last tests put the real slot and service behind a
policy that asks about everything and in front of a dispatcher that only counts.
"""

import time
from collections.abc import Callable
from typing import Any

import anyio
import pytest

from keystone.approvals.service import ApprovalService, OwnRequest
from keystone.audit.redact import args_digest
from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect
from keystone.gateway.pipeline import Pipeline
from keystone.settings import ApprovalSettings, Settings
from tests.fixtures.approvals import LENA, Approver, SpyDispatcher, approval_pipeline
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(6), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
BIG = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}


def waits(seconds: float, **more: Any) -> dict[str, Any]:
    return {"approvals": ApprovalSettings(wait_seconds=seconds, poll_interval_s=0.2, **more)}


async def test_approved_within_wait_dispatches(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
) -> None:
    app = keystone_app_factory(settings=waits(20))
    decided_at: list[float] = []

    async def approve_when_it_is_asked() -> None:
        await approver.approve("looks right")
        decided_at.append(time.monotonic())

    async with mcp_client(app, user="olivia") as olivia, anyio.create_task_group() as tasks:
        tasks.start_soon(approve_when_it_is_asked)
        result = await olivia.call_tool("bank__transfer", BIG)
        answered_at = time.monotonic()

    # The call was held, then it ran and returned what the bank said.
    assert not result.is_error
    assert "completed" in texts(result)[0]
    transfers: list[dict[str, Any]] = demo_upstreams.state("bank")["transfers"]  # type: ignore[assignment]
    assert [(t["amount"], t["to"]) for t in transfers] == [(900.0, "SAV-002")]
    # The agent had its answer within a second of the decision.
    assert answered_at - decided_at[0] < 1.0
    [used] = await approver.service.list_for_tenant("acme", "consumed")
    assert used.status == "consumed" and used.decided_by == "lena"
    assert await approver.service.list_for_tenant("acme", "pending") == []
    # The record says which approval the call ran under (KS-691), so "who allowed this" is
    # answered by the record and the approval row together.
    [record] = app.audit.records
    assert (record["effect"], record["reasons"], record["outcome"], record["dispatched"]) == (
        "require_approval",
        ["approve-transfer-over-500", f"approval:{used.id}"],
        "ok",
        True,
    )


async def test_a_call_that_needs_no_approval_does_not_wait(
    keystone_app_factory: Factory, mcp_client: McpConnect, approver: Approver
) -> None:
    app = keystone_app_factory(settings=waits(20))
    started = time.monotonic()

    async with mcp_client(app, user="olivia") as olivia:
        result = await olivia.call_tool("bank__transfer", {**BIG, "amount": 100})

    assert not result.is_error and time.monotonic() - started < 5
    assert await approver.service.list_for_tenant("acme", "pending") == []


async def test_rejected_returns_note(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
) -> None:
    app = keystone_app_factory(settings=waits(20))

    async with mcp_client(app, user="olivia") as olivia, anyio.create_task_group() as tasks:
        tasks.start_soon(approver.reject, "not this quarter")
        result = await olivia.call_tool("bank__transfer", BIG)

    assert result.is_error and result.meta is not None
    assert result.meta["keystone/code"] == "KS_APPROVAL_REJECTED"
    assert texts(result)[0].endswith("was rejected by an approver: not this quarter")
    assert demo_upstreams.state("bank")["transfers"] == []
    [record] = app.audit.records
    assert (record["outcome"], record["reject_code"], record["dispatched"]) == (
        "rejected",
        "KS_APPROVAL_REJECTED",
        False,
    )


async def test_timeout_returns_pending_with_id(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
) -> None:
    app = keystone_app_factory(settings=waits(1))
    started = time.monotonic()

    async with mcp_client(app, user="olivia") as olivia:
        result = await olivia.call_tool("bank__transfer", BIG)

    assert time.monotonic() - started >= 1
    assert result.is_error and result.meta is not None
    assert result.meta["keystone/code"] == "KS_APPROVAL_PENDING"
    approval_id = result.meta["keystone/approval_id"]
    assert result.meta["keystone/next"] == "call keystone__await_approval"
    assert result.meta["keystone/expires_at"]
    # The model reads the id in the text, where `_meta` may not reach it.
    assert approval_id in texts(result)[0] and "keystone__await_approval" in texts(result)[0]
    # The request waits in the queue, for the same digest the audit record has.
    [waiting] = await approver.service.list_for_tenant("acme", "pending")
    assert waiting.id == approval_id
    assert waiting.requested_by_user == "olivia"
    assert waiting.reasons == ("approve-transfer-over-500",)
    assert demo_upstreams.state("bank")["transfers"] == []
    [record] = app.audit.records
    assert (record["outcome"], record["reject_code"], record["dispatched"]) == (
        "rejected",
        "KS_APPROVAL_PENDING",
        False,
    )
    assert record["args_digest"] == waiting.args_digest


async def test_a_request_that_expires_while_the_call_waits_ends_as_expired(
    keystone_app_factory: Factory, mcp_client: McpConnect, approver: Approver
) -> None:
    app = keystone_app_factory(settings=waits(30, ttl_seconds=1))

    async with mcp_client(app, user="olivia") as olivia:
        result = await olivia.call_tool("bank__transfer", BIG)

    assert result.is_error and result.meta is not None
    assert result.meta["keystone/code"] == "KS_APPROVAL_EXPIRED"
    assert await approver.service.list_for_tenant("acme", "pending") == []


async def test_the_requester_cannot_approve_the_call_they_are_waiting_on(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
) -> None:
    """Olivia holds the approver role in this test. For her own request the service refuses, the
    call keeps waiting, and it ends as pending."""
    app = keystone_app_factory(settings=waits(2))
    olivia_as_approver = LENA.model_copy(update={"user_id": "olivia"})
    refused: list[bool] = []

    async def try_to_approve_it() -> None:
        [found] = await approver.pending()
        with pytest.raises(OwnRequest):
            await approver.service.decide(found.id, olivia_as_approver, True)
        refused.append(True)

    async with mcp_client(app, user="olivia") as olivia, anyio.create_task_group() as tasks:
        tasks.start_soon(try_to_approve_it)
        result = await olivia.call_tool("bank__transfer", BIG)

    assert refused == [True]
    assert result.is_error and result.meta is not None
    assert result.meta["keystone/code"] == "KS_APPROVAL_PENDING"
    assert demo_upstreams.state("bank")["transfers"] == []


# -- the slot over a real service, in front of a dispatcher that only counts

SMALL = {**BIG, "amount": 100}
TRANSFER = make_tool("bank", "transfer", schema={"type": "object"})


async def test_digest_mismatch_never_dispatches(
    settings: Settings, approval_service: ApprovalService
) -> None:
    """An approval for a transfer of 100 is presented with other arguments."""
    spy = SpyDispatcher()
    audit = InMemoryAuditSink()
    pipeline = approval_pipeline(settings, approval_service, spy, audit=audit)
    asked = make_ctx(SMALL, TRANSFER)
    approval_id = await approval_service.request(asked, ["approve-transfer-over-500"])
    await approval_service.decide(approval_id, LENA, True)

    for arguments in ({**BIG, "amount": 90_000}, {**SMALL, "memo": "x"}, {}, {"amount": 100}):
        forged = make_ctx(arguments, TRANSFER, approval_id=approval_id)

        result = await pipeline.run(forged)

        assert result.is_error
        assert forged.approval_id is None and not forged.dispatched
    assert spy.calls == []
    assert {r["reject_code"] for r in audit.records} == {"KS_APPROVAL_EXPIRED"}

    # The failed tries did not use the approval up: the arguments it was made for still work.
    honest = make_ctx(SMALL, TRANSFER, approval_id=approval_id)
    assert not (await pipeline.run(honest)).is_error
    assert spy.calls == [("bank__transfer", SMALL, approval_id)]
    record = await approval_service.get("acme", approval_id)
    assert record is not None and record.args_digest == args_digest(SMALL)


async def test_a_new_call_that_needs_approval_is_held_and_does_not_dispatch(
    settings: Settings, approval_service: ApprovalService
) -> None:
    spy = SpyDispatcher()
    pipeline = approval_pipeline(settings, approval_service, spy)
    ctx = make_ctx(BIG, TRANSFER)

    result = await pipeline.run(ctx)

    assert result.is_error and spy.calls == [] and ctx.approval_id is None
    [waiting] = await approval_service.list_for_tenant("acme", "pending")
    assert waiting.call_id == ctx.call_id and waiting.args_digest == args_digest(BIG)


async def test_a_claimed_approval_is_named_in_the_record_of_the_call_it_allowed(
    settings: Settings, approval_service: ApprovalService
) -> None:
    spy = SpyDispatcher()
    audit = InMemoryAuditSink()
    pipeline = approval_pipeline(settings, approval_service, spy, audit=audit)
    approval_id = await approval_service.request(make_ctx(SMALL, TRANSFER), ["by-the-rule"])
    await approval_service.decide(approval_id, LENA, True)

    await pipeline.run(make_ctx(SMALL, TRANSFER, approval_id=approval_id))

    [record] = audit.records
    assert record["dispatched"] is True
    assert record["reasons"] == ["approve-transfer-over-500", f"approval:{approval_id}"]


# -- KS-691: the call is checked again after the wait, before the approval is used


class Counting:
    """A slot that lets everything through and counts how often it ran."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.runs = 0

    async def before_call(self, ctx: CallContext) -> None:
        self.runs += 1

    async def after_call(self, ctx: CallContext) -> None:
        return None


class Pinning(Counting):
    """The pinning slot of a registry whose tool can be quarantined while a call waits."""

    def __init__(self) -> None:
        super().__init__("pinning")
        self.quarantined = False

    async def before_call(self, ctx: CallContext) -> None:
        await super().before_call(ctx)
        if self.quarantined:
            raise Reject(Code.QUARANTINED, f"tool {ctx.tool.name} is quarantined")


class Policy(Counting):
    """A policy that can be reloaded while a call waits: it asks for approval until told not to."""

    def __init__(self) -> None:
        super().__init__("policy")
        self.effect = Effect.REQUIRE_APPROVAL

    async def before_call(self, ctx: CallContext) -> None:
        await super().before_call(ctx)
        if self.effect is Effect.DENY:
            raise Reject(Code.DENIED, "denied by policy: transfers-frozen")
        ctx.decision = Decision(
            effect=self.effect, reasons=["approve-transfer-over-500"], source="policy"
        )


async def held_then_approved(
    pipeline: Pipeline,
    service: ApprovalService,
    approver: Approver,
    ctx: CallContext,
    *,
    meanwhile: Callable[[], None] = lambda: None,
) -> None:
    """Run `ctx` through `pipeline` while a person approves it, after `meanwhile` has changed
    what the call was checked against."""

    async def decide_it() -> None:
        found = await approver.pending()
        meanwhile()
        await service.decide(found[0].id, LENA, True)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(decide_it)
        await pipeline.run(ctx)


async def test_a_tool_quarantined_while_the_call_waits_is_not_called_and_keeps_its_approval(
    settings: Settings, approval_service: ApprovalService, approver: Approver
) -> None:
    """The call passed pinning before it waited. By the time a person approved it the tool had
    been quarantined, and the person was not shown that."""
    spy, audit, pinning = SpyDispatcher(), InMemoryAuditSink(), Pinning()
    pipeline = approval_pipeline(
        settings,
        approval_service,
        spy,
        wait_seconds=20,
        audit=audit,
        overrides={"pinning": pinning},
    )
    ctx = make_ctx(BIG, TRANSFER)

    def quarantine() -> None:
        pinning.quarantined = True

    await held_then_approved(pipeline, approval_service, approver, ctx, meanwhile=quarantine)

    assert spy.calls == [] and ctx.approval_id is None and not ctx.dispatched
    [record] = audit.records
    assert (record["outcome"], record["reject_code"]) == ("rejected", "KS_QUARANTINED")
    # Refused before it was used: the approval is still there, and was not spent on nothing.
    assert [a.status for a in await approval_service.list_for_tenant("acme", "approved")] == [
        "approved"
    ]
    assert await approval_service.list_for_tenant("acme", "consumed") == []


async def test_a_policy_that_now_forbids_the_call_stops_it_after_the_wait(
    settings: Settings, approval_service: ApprovalService, approver: Approver
) -> None:
    spy, audit, policy = SpyDispatcher(), InMemoryAuditSink(), Policy()
    pipeline = approval_pipeline(
        settings,
        approval_service,
        spy,
        wait_seconds=20,
        audit=audit,
        overrides={"policy": policy},
    )
    ctx = make_ctx(BIG, TRANSFER)

    def freeze() -> None:
        policy.effect = Effect.DENY

    await held_then_approved(pipeline, approval_service, approver, ctx, meanwhile=freeze)

    assert spy.calls == [] and ctx.approval_id is None
    [record] = audit.records
    assert (record["outcome"], record["reject_code"]) == ("rejected", "KS_DENIED")
    assert await approval_service.list_for_tenant("acme", "consumed") == []


async def test_a_policy_that_no_longer_asks_lets_the_call_through_without_the_approval(
    settings: Settings, approval_service: ApprovalService, approver: Approver
) -> None:
    spy, audit, policy = SpyDispatcher(), InMemoryAuditSink(), Policy()
    pipeline = approval_pipeline(
        settings,
        approval_service,
        spy,
        wait_seconds=20,
        audit=audit,
        overrides={"policy": policy},
    )
    ctx = make_ctx(BIG, TRANSFER)

    def relax() -> None:
        policy.effect = Effect.ALLOW

    await held_then_approved(pipeline, approval_service, approver, ctx, meanwhile=relax)

    # It ran under the allow it has now, with no approval on the context, and the record says so.
    assert spy.calls == [("bank__transfer", BIG, None)]
    [record] = audit.records
    assert (record["decision"], record["reasons"], record["dispatched"]) == (
        "allow",
        ["approve-transfer-over-500"],
        True,
    )
    # The approval was not needed, so it was not used. It stays approved until it expires.
    assert [a.status for a in await approval_service.list_for_tenant("acme", "approved")] == [
        "approved"
    ]


async def test_a_call_that_waited_is_charged_to_the_rate_limit_once_and_checked_twice_elsewhere(
    settings: Settings, approval_service: ApprovalService, approver: Approver
) -> None:
    rate, pinning, budget, policy = (
        Counting("rate_limit"),
        Counting("pinning"),
        Counting("budget"),
        Policy(),
    )
    spy = SpyDispatcher()
    pipeline = approval_pipeline(
        settings,
        approval_service,
        spy,
        wait_seconds=20,
        overrides={"rate_limit": rate, "pinning": pinning, "budget": budget, "policy": policy},
    )

    await held_then_approved(pipeline, approval_service, approver, make_ctx(BIG, TRANSFER))

    assert len(spy.calls) == 1
    assert (rate.runs, pinning.runs, budget.runs, policy.runs) == (1, 2, 2, 2)


async def test_a_call_that_is_not_held_is_not_checked_a_second_time(
    settings: Settings, approval_service: ApprovalService
) -> None:
    """The check after the wait is for a call that waited. A claimed approval comes from
    `keystone__await_approval`, whose inner call has just been through every slot."""
    pinning = Counting("pinning")
    spy = SpyDispatcher()
    pipeline = approval_pipeline(settings, approval_service, spy, overrides={"pinning": pinning})
    approval_id = await approval_service.request(make_ctx(SMALL, TRANSFER), ["by-the-rule"])
    await approval_service.decide(approval_id, LENA, True)

    await pipeline.run(make_ctx(SMALL, TRANSFER, approval_id=approval_id))

    assert pinning.runs == 1 and len(spy.calls) == 1
