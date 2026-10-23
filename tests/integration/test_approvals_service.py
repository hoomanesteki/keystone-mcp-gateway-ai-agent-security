"""KS-601: an approval request is specific, time-limited and used once.

The service runs against Postgres and Redis. The statements that decide and consume are the thing
under test, so the expiry cases change `expires_at` in the table, as time passing would, and one
test holds a row lock across the moment of expiry to show that a waiting statement is judged by the
clock at the time it runs and not by the time it began.
"""

import time
from typing import Any

import anyio
import pytest
from cryptography.fernet import Fernet
from redis.asyncio import Redis
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.approvals.service import (
    ApprovalError,
    ApprovalNotFound,
    ApprovalService,
    NotAnApprover,
    NotPending,
    OwnRequest,
)
from keystone.audit.redact import args_digest
from keystone.core.types import Principal
from keystone.db.models import APPROVALS
from keystone.identity.vault import Cipher
from keystone.telemetry.metrics import Metrics
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool

pytestmark = [pytest.mark.phase(6), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]

TRANSFER = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900, "memo": "invoice 7"}
REASONS = ["approve-transfer-over-500"]
TOOL = make_tool("bank", "transfer", schema={"type": "object"})


def person(user: str, *roles: str, tenant: str = "acme") -> Principal:
    return Principal(
        tenant_id=tenant, user_id=user, groups=(), agent_id="keystone-cli", roles=tuple(roles)
    )


LENA = person("lena", "approver")
ROOT = person("root", "admin")
GINA = person("gina", "approver", tenant="globex")
OLIVIA_APPROVER = OLIVIA.model_copy(update={"roles": ("approver",)})


@pytest.fixture
def cipher() -> Cipher:
    return Cipher(Fernet.generate_key().decode())


@pytest.fixture
def service(sessionmaker: Sessions, cipher: Cipher, redis: Redis) -> ApprovalService:
    return ApprovalService(sessionmaker, cipher, redis=redis, poll_interval_s=0.1)


def transfer_call(arguments: dict[str, Any] | None = None, **fields: Any) -> Any:
    return make_ctx(TRANSFER if arguments is None else arguments, TOOL, **fields)


async def asked(service: ApprovalService, arguments: dict[str, Any] | None = None) -> str:
    return await service.request(transfer_call(arguments), REASONS)


async def approved(service: ApprovalService, arguments: dict[str, Any] | None = None) -> str:
    approval_id = await asked(service, arguments)
    await service.decide(approval_id, LENA, True, "fine")
    return approval_id


def binding(**changes: str) -> dict[str, str]:
    """What the call that holds the approval must match besides the digest."""
    ctx = transfer_call()
    found = {
        "tenant_id": "acme",
        "tool_name": "bank__transfer",
        "session_id": ctx.session.session_id,
        "user_id": "olivia",
    }
    return {**found, **changes}


def digest_of(arguments: dict[str, Any] | None = None) -> str:
    found = args_digest(TRANSFER if arguments is None else arguments)
    assert found is not None
    return found


async def stored(sessions: Sessions, approval_id: str) -> dict[str, Any]:
    async with sessions() as session:
        row = (
            (
                await session.execute(
                    text("SELECT * FROM approvals WHERE id = :id"), {"id": approval_id}
                )
            )
            .mappings()
            .one()
        )
    return dict(row)


async def expire(sessions: Sessions, approval_id: str) -> None:
    """Let the time run out, as waiting would."""
    async with sessions() as session, session.begin():
        await session.execute(
            update(APPROVALS)
            .where(APPROVALS.c.id == approval_id)
            .values(expires_at=text("clock_timestamp() - interval '1 second'"))
        )


async def test_request_creates_pending(service: ApprovalService, sessionmaker: Sessions) -> None:
    ctx = transfer_call()

    approval_id = await service.request(ctx, REASONS)

    record = await service.get("acme", approval_id)
    assert record is not None
    assert record.status == "pending"
    assert (record.tool_name, record.reasons) == ("bank__transfer", tuple(REASONS))
    assert (record.requested_by_user, record.requested_by_agent) == ("olivia", "ops-agent")
    assert (record.session_id, record.call_id) == (ctx.session.session_id, ctx.call_id)
    assert record.decided_by is None and record.decided_at is None
    # The digest is the one the audit log writes for the same arguments (KS-502).
    assert record.args_digest == digest_of()
    assert record.args_redacted == TRANSFER
    # The default life of a request is 15 minutes, counted by the database.
    assert 890 < record.expires_in_s <= 900
    # The arguments are in the table only as ciphertext, and they come back whole once approved.
    row = await stored(sessionmaker, approval_id)
    assert row["args_ciphertext"] and b"CHK-001" not in bytes(row["args_ciphertext"])
    assert b"invoice" not in bytes(row["args_ciphertext"])


async def test_requester_cannot_approve_own(service: ApprovalService) -> None:
    approval_id = await asked(service)

    # Olivia has the approver role and still cannot decide her own request, either way.
    for approve in (True, False):
        with pytest.raises(OwnRequest):
            await service.decide(approval_id, OLIVIA_APPROVER, approve, "me")
    # An admin who is the requester is no different.
    admin_ctx = make_ctx(TRANSFER, TOOL, principal=OLIVIA.model_copy(update={"roles": ("admin",)}))
    own = await service.request(admin_ctx, REASONS)
    with pytest.raises(OwnRequest):
        await service.decide(own, admin_ctx.principal, True)

    record = await service.get("acme", approval_id)
    assert record is not None and record.status == "pending" and record.decided_by is None
    decided = await service.decide(approval_id, LENA, True, "looks right")
    assert (decided.status, decided.decided_by, decided.decision_note) == (
        "approved",
        "lena",
        "looks right",
    )


async def test_cross_tenant_approver_rejected(service: ApprovalService) -> None:
    approval_id = await asked(service)

    with pytest.raises(ApprovalNotFound):
        await service.decide(approval_id, GINA, True)  # approver of globex

    record = await service.get("acme", approval_id)
    assert record is not None and record.status == "pending"
    # The other tenant cannot even read it.
    assert await service.get("globex", approval_id) is None
    assert await service.list_for_tenant("globex", "pending") == []
    assert await service.load_args(approval_id, tenant_id="globex") is None


async def test_consume_single_use(service: ApprovalService) -> None:
    approval_id = await approved(service)

    assert await service.consume(approval_id, digest_of(), **binding()) is True
    assert await service.consume(approval_id, digest_of(), **binding()) is False

    record = await service.get("acme", approval_id)
    assert record is not None and record.status == "consumed"


async def test_consume_requires_matching_digest(service: ApprovalService) -> None:
    approval_id = await approved(service)
    other = digest_of({**TRANSFER, "amount": 90_000})

    assert await service.consume(approval_id, other, **binding()) is False
    assert await service.consume(approval_id, "", **binding()) is False
    # A failed try does not use the approval up.
    assert await service.consume(approval_id, digest_of(), **binding()) is True


async def test_expired_cannot_be_approved(service: ApprovalService, sessionmaker: Sessions) -> None:
    approval_id = await asked(service)
    await expire(sessionmaker, approval_id)

    with pytest.raises(NotPending) as refused:
        await service.decide(approval_id, LENA, True)

    assert refused.value.status == "expired"
    # The sweeper has not run, and the answer is the same: the clock decides, not the sweeper.
    assert (await stored(sessionmaker, approval_id))["status"] == "pending"
    record = await service.get("acme", approval_id)
    assert record is not None and record.status == "expired"
    assert await service.list_for_tenant("acme", "pending") == []


async def test_an_expired_approval_cannot_be_consumed(
    service: ApprovalService, sessionmaker: Sessions
) -> None:
    approval_id = await approved(service)
    await expire(sessionmaker, approval_id)

    assert await service.consume(approval_id, digest_of(), **binding()) is False
    assert await service.load_args(approval_id, tenant_id="acme") is None
    record = await service.get("acme", approval_id)
    assert record is not None and record.status == "expired"


async def test_a_consume_that_waited_for_a_lock_past_the_expiry_fails(
    service: ApprovalService, sessionmaker: Sessions
) -> None:
    """The statement starts before the approval expires and is held up by a lock until after it.
    It is judged by the time it runs. `now()` would be the time it began, and would let it use
    an approval that has expired."""
    table = APPROVALS
    approval_id = await approved(service)
    async with sessionmaker() as session, session.begin():
        await session.execute(
            update(table)
            .where(table.c.id == approval_id)
            .values(expires_at=text("clock_timestamp() + interval '1200 milliseconds'"))
        )
    outcome: list[bool] = []

    async def consume() -> None:
        outcome.append(await service.consume(approval_id, digest_of(), **binding()))

    async with anyio.create_task_group() as tasks, sessionmaker() as locker, locker.begin():
        # A new version of the row, and the transaction stays open.
        await locker.execute(
            update(table).where(table.c.id == approval_id).values(decision_note="held")
        )
        tasks.start_soon(consume)
        await anyio.sleep(1.6)  # the approval expires while the consume is waiting
        assert outcome == []  # it is still waiting for the lock
    assert outcome == [False]
    assert (await stored(sessionmaker, approval_id))["status"] == "approved"


async def test_the_race_test_can_fail(service: ApprovalService, sessionmaker: Sessions) -> None:
    """The same wait with `now()` in place of the wall clock uses the expired approval, which is
    why the service does not compare against it."""
    table = APPROVALS
    approval_id = await approved(service)
    async with sessionmaker() as session, session.begin():
        await session.execute(
            update(table)
            .where(table.c.id == approval_id)
            .values(expires_at=text("clock_timestamp() + interval '1200 milliseconds'"))
        )
    outcome: list[int] = []

    async def consume_by_transaction_time() -> None:
        async with sessionmaker() as session, session.begin():
            result = await session.execute(
                text(
                    "UPDATE approvals SET status = 'consumed' "
                    "WHERE id = :id AND status = 'approved' AND expires_at > now() RETURNING id"
                ),
                {"id": approval_id},
            )
            outcome.append(len(result.all()))

    async with anyio.create_task_group() as tasks, sessionmaker() as locker, locker.begin():
        await locker.execute(
            update(table).where(table.c.id == approval_id).values(decision_note="held")
        )
        tasks.start_soon(consume_by_transaction_time)
        await anyio.sleep(1.6)
    assert outcome == [1]  # consumed after it expired


async def test_consume_binds_the_tenant_the_tool_the_session_and_the_user(
    service: ApprovalService,
) -> None:
    approval_id = await approved(service)

    for wrong in (
        binding(tenant_id="globex"),
        binding(tool_name="bank__get_balance"),
        binding(session_id="another-session"),
        binding(user_id="alice"),
    ):
        assert await service.consume(approval_id, digest_of(), **wrong) is False, wrong

    assert await service.consume(approval_id, digest_of(), **binding()) is True


async def test_only_a_pending_request_can_be_decided_once(service: ApprovalService) -> None:
    approval_id = await asked(service)
    await service.decide(approval_id, LENA, False, "not this one")

    with pytest.raises(NotPending) as again:
        await service.decide(approval_id, ROOT, True)

    assert again.value.status == "rejected"
    record = await service.get("acme", approval_id)
    assert record is not None
    assert (record.status, record.decided_by, record.decision_note) == (
        "rejected",
        "lena",
        "not this one",
    )
    # A rejected request is not an approval, whatever is asked of it afterwards.
    assert await service.consume(approval_id, digest_of(), **binding()) is False
    assert await service.load_args(approval_id, tenant_id="acme") is None


async def test_two_approvers_deciding_at_once_leave_one_decision(service: ApprovalService) -> None:
    approval_id = await asked(service)
    results: list[object] = []

    async def decide(who: Principal, approve: bool) -> None:
        try:
            results.append((await service.decide(approval_id, who, approve)).status)
        except NotPending as exc:
            results.append(exc)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(decide, LENA, True)
        tasks.start_soon(decide, ROOT, False)

    winners = [r for r in results if isinstance(r, str)]
    losers = [r for r in results if isinstance(r, NotPending)]
    assert len(winners) == 1 and len(losers) == 1
    record = await service.get("acme", approval_id)
    assert record is not None and record.status == winners[0]


@pytest.mark.parametrize("roles", [(), ("viewer",)])
async def test_a_decision_needs_the_approver_or_admin_role(
    service: ApprovalService, roles: tuple[str, ...]
) -> None:
    approval_id = await asked(service)

    with pytest.raises(NotAnApprover):
        await service.decide(approval_id, person("mallory", *roles), True)

    record = await service.get("acme", approval_id)
    assert record is not None and record.status == "pending"
    # Both roles that may decide can.
    assert (await service.decide(approval_id, ROOT, True)).status == "approved"


async def test_load_args_returns_what_was_asked_only_while_the_approval_can_be_used(
    service: ApprovalService,
) -> None:
    approval_id = await asked(service)
    assert await service.load_args(approval_id, tenant_id="acme") is None  # still pending

    await service.decide(approval_id, LENA, True)
    assert await service.load_args(approval_id, tenant_id="acme") == TRANSFER

    assert await service.consume(approval_id, digest_of(), **binding()) is True
    assert await service.load_args(approval_id, tenant_id="acme") is None  # used up


async def test_arguments_that_do_not_match_their_digest_are_not_returned(
    service: ApprovalService, sessionmaker: Sessions, cipher: Cipher
) -> None:
    """A row whose ciphertext was swapped for other arguments keeps the digest of the first."""
    approval_id = await approved(service)
    swapped = cipher.encrypt_json({**TRANSFER, "amount": 90_000})
    table = APPROVALS
    async with sessionmaker() as session, session.begin():
        await session.execute(
            update(table).where(table.c.id == approval_id).values(args_ciphertext=swapped)
        )

    with pytest.raises(ApprovalError, match="digest"):
        await service.load_args(approval_id, tenant_id="acme")


async def test_the_view_for_approvers_masks_secrets_but_the_digest_covers_the_original(
    service: ApprovalService,
) -> None:
    arguments = {"to": "SAV-002", "amount": 900, "api_key": "sk-live-1234567890abcdef"}
    approval_id = await asked(service, arguments)

    record = await service.get("acme", approval_id)

    assert record is not None
    assert record.args_redacted == {"to": "SAV-002", "amount": 900, "api_key": "[redacted]"}
    assert "sk-live" not in str(record)
    assert record.args_digest == digest_of(arguments)


async def test_wait_wakes_at_once_on_a_decision(
    sessionmaker: Sessions, cipher: Cipher, redis: Redis
) -> None:
    """The poll is set to a minute, so only the message can end the wait this soon."""
    service = ApprovalService(sessionmaker, cipher, redis=redis, poll_interval_s=60.0)
    approval_id = await asked(service)

    async def approve_soon() -> None:
        await anyio.sleep(0.3)
        await service.decide(approval_id, LENA, True)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approve_soon)
        started = time.monotonic()
        outcome = await service.wait(approval_id, 20)

    assert outcome == "approved"
    assert time.monotonic() - started < 3


async def test_wait_polls_when_there_is_no_redis(sessionmaker: Sessions, cipher: Cipher) -> None:
    service = ApprovalService(sessionmaker, cipher, redis=None, poll_interval_s=0.1)
    approval_id = await asked(service)

    async def reject_soon() -> None:
        await anyio.sleep(0.3)
        await service.decide(approval_id, LENA, False, "no")

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(reject_soon)
        assert await service.wait(approval_id, 10) == "rejected"


async def test_wait_polls_when_redis_is_down(sessionmaker: Sessions, cipher: Cipher) -> None:
    gone = Redis.from_url("redis://127.0.0.1:1/0", decode_responses=True)
    service = ApprovalService(sessionmaker, cipher, redis=gone, poll_interval_s=0.1)
    approval_id = await asked(service)

    async def approve_soon() -> None:
        await anyio.sleep(0.3)
        await service.decide(approval_id, LENA, True)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approve_soon)
        assert await service.wait(approval_id, 10) == "approved"
    await gone.aclose()


async def test_wait_gives_up_at_the_time_limit_and_reports_how_it_ended(
    service: ApprovalService, sessionmaker: Sessions
) -> None:
    approval_id = await asked(service)
    started = time.monotonic()

    assert await service.wait(approval_id, 0.5) == "pending"
    assert 0.45 < time.monotonic() - started < 3
    assert await service.wait(approval_id, 0) == "pending"

    await service.decide(approval_id, LENA, True)
    assert await service.wait(approval_id, 0) == "approved"
    await expire(sessionmaker, approval_id)
    assert await service.wait(approval_id, 0) == "expired"
    assert await service.wait("01JNOSUCHAPPROVAL000000000", 0) == "expired"


async def test_the_sweeper_marks_expired_requests(
    service: ApprovalService, sessionmaker: Sessions
) -> None:
    waiting = await asked(service)
    stale = await asked(service)
    unused = await approved(service)
    used = await approved(service)
    assert await service.consume(used, digest_of(), **binding()) is True
    for approval_id in (stale, unused, used):
        await expire(sessionmaker, approval_id)

    marked = await service.sweep()

    assert marked == 2  # the pending one and the approved one nobody used
    assert (await stored(sessionmaker, stale))["status"] == "expired"
    assert (await stored(sessionmaker, unused))["status"] == "expired"
    assert (await stored(sessionmaker, used))["status"] == "consumed"  # history is not rewritten
    assert (await stored(sessionmaker, waiting))["status"] == "pending"
    assert await service.sweep() == 0


async def test_the_sweeper_loop_runs_until_it_is_stopped(
    sessionmaker: Sessions, cipher: Cipher, redis: Redis
) -> None:
    service = ApprovalService(sessionmaker, cipher, redis=redis, sweep_interval_s=0.1)
    approval_id = await asked(service)
    await expire(sessionmaker, approval_id)

    async def marked() -> None:
        while True:
            if (await stored(sessionmaker, approval_id))["status"] == "expired":
                return
            await anyio.sleep(0.05)

    with anyio.fail_after(10):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(service.run_sweeper)
            await marked()
            tasks.cancel_scope.cancel()


async def test_listing_follows_the_status_and_the_tenant(service: ApprovalService) -> None:
    first = await asked(service)
    second = await asked(service)
    third = await asked(service)
    await service.decide(second, LENA, False, "no")
    await service.decide(third, LENA, True)

    pending = await service.list_for_tenant("acme", "pending")
    rejected = await service.list_for_tenant("acme", "rejected")
    approved_now = await service.list_for_tenant("acme", "approved")

    assert [r.id for r in pending] == [first]
    assert [r.id for r in rejected] == [second]
    assert [r.id for r in approved_now] == [third]
    assert await service.list_for_tenant("acme", "consumed") == []
    # A queue shows the one that has waited longest first.
    older = await asked(service)
    newer = await asked(service)
    assert [r.id for r in await service.list_for_tenant("acme", "pending")] == [first, older, newer]


async def test_the_pending_gauge_follows_requests_and_decisions(
    sessionmaker: Sessions, cipher: Cipher, redis: Redis
) -> None:
    metrics = Metrics(tenants=["acme", "globex"])
    service = ApprovalService(sessionmaker, cipher, redis=redis, metrics=metrics)

    def gauge(tenant: str) -> float | None:
        return metrics.registry.get_sample_value("keystone_approvals_pending", {"tenant": tenant})

    first = await asked(service)
    await asked(service)
    assert (gauge("acme"), gauge("globex")) == (2, 0)

    await service.decide(first, LENA, True)
    assert gauge("acme") == 1


async def test_a_request_is_announced_to_the_tenant_channel(
    service: ApprovalService, redis: Redis
) -> None:
    channel = redis.pubsub()
    await channel.subscribe("ks:approvals:acme")
    await channel.get_message(timeout=1)  # the subscription itself

    approval_id = await asked(service)

    message = await channel.get_message(ignore_subscribe_messages=True, timeout=3)
    await channel.aclose()
    assert message is not None and approval_id in message["data"]


async def test_the_time_to_live_comes_from_the_service(
    sessionmaker: Sessions, cipher: Cipher
) -> None:
    short = ApprovalService(sessionmaker, cipher, ttl_s=30)

    record = await short.get("acme", await asked(short))

    assert record is not None and 25 < record.expires_in_s <= 30
