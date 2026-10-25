"""KS-501: the audit writer. Records go to Postgres in one chain that continues across restarts
and across writers, a batch that fails is kept and written later, and a pipeline that fails
closed refuses calls while the writer is unhealthy (ADR-0009)."""

import asyncio
import hashlib
import itertools
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from keystone.audit.chain import GENESIS, record_fields
from keystone.audit.sink import AuditUnavailable, PostgresAuditSink
from keystone.core.canonical import canonical_json
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ScanResult, ToolResult
from keystone.db.models import AuditEvent
from keystone.gateway.pipeline import Dispatcher
from keystone.settings import AuditSettings
from keystone.telemetry.metrics import Metrics
from tests.fixtures.audit import chain_problems
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.keystone import KeystoneApp, McpConnect

pytestmark = [pytest.mark.phase(5), pytest.mark.services]

Sessionmaker = async_sessionmaker[AsyncSession]


async def rows_of(sessions: Sessionmaker) -> list[dict[str, Any]]:
    async with sessions() as session:
        table = AuditEvent.__table__
        result = await session.execute(select(table).order_by(table.c.seq))
        return [dict(row) for row in result.mappings()]


def call(n: int, **fields: Any) -> CallContext:
    return make_ctx({"text": f"call {n}"}, **fields)


def awkward_call(n: int) -> CallContext:
    """A call whose values are the ones that read back from Postgres as something else if they are
    hashed as they were written: a time in another zone with microseconds, a float cost, a score
    with more places than the column keeps, text with a NUL character and non-ASCII letters."""
    return make_ctx(
        {"text": "x"},
        make_tool(tool=f"ec\x00ho{n}"),
        received_at=datetime(
            2026, 10, 22, 5, 4, 3, 100_000 + n, tzinfo=timezone(timedelta(hours=-7))
        ),
        decision=Decision(effect=Effect.ALLOW, reasons=["régle-ñ", f"rule {n}"], source="policy"),
        scan=ScanResult(score=n / 7, label="benign", action="pass"),
        cost_usd=0.1 + 0.2 * n,
        dispatched=True,
    )


def outcomes(n: int) -> tuple[Any, Reject | None]:
    if n % 3 == 0:
        return "rejected", Reject(Code.DENIED, "no", {"keystone/reason": "default-deny"})
    return ("error" if n % 3 == 1 else "ok"), None


class Flaky(PostgresAuditSink):
    """A writer whose database can be switched off."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.failing = False
        self.attempts = 0

    async def _insert(self, part: list[dict[str, Any]]) -> None:
        if self.failing:
            self.attempts += 1
            raise OperationalError("INSERT INTO audit_events", {}, OSError("connection refused"))
        await super()._insert(part)


def failures(metrics: Metrics, reason: str) -> float:
    return (
        metrics.registry.get_sample_value("keystone_audit_failures_total", {"reason": reason}) or 0
    )


async def until(condition: Callable[[], bool], timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not condition():
        assert time.monotonic() < deadline, "the condition did not come true"
        await asyncio.sleep(0.005)


async def test_records_written_with_chain(sessionmaker: Sessionmaker) -> None:
    async with PostgresAuditSink(sessionmaker) as sink:
        for n in range(50):
            outcome, reject = outcomes(n)
            await sink.record(awkward_call(n) if n % 2 else call(n), outcome, reject)
        await sink.flush()

    rows = await rows_of(sessionmaker)
    assert len(rows) == 50
    assert [row["seq"] for row in rows] == list(range(1, 51))
    assert rows[0]["prev_hash"] == GENESIS
    for earlier, later in itertools.pairwise(rows):
        assert later["prev_hash"] == earlier["hash"]
    # The hashes are recomputed from what the database returned, not from what was written.
    assert chain_problems(rows) == []
    awkward = rows[1]
    assert awkward["cost_usd"] == Decimal("0.30000000") and str(awkward["cost_usd"]) == "0.30000000"
    assert awkward["scan_score"] == Decimal("0.142857")
    assert awkward["tool_name"] == "echo__ec\\u0000ho1"
    assert awkward["reasons"] == ["régle-ñ", "rule 1"]
    assert awkward["ts"] == datetime(2026, 10, 22, 12, 4, 3, 100_001, tzinfo=UTC)


async def test_chain_continues_after_restart(sessionmaker: Sessionmaker) -> None:
    first = PostgresAuditSink(sessionmaker)
    await first.start()
    for n in range(10):
        await first.record(call(n), "ok", None)
    await first.stop()
    before = await rows_of(sessionmaker)
    assert len(before) == 10

    # A new process: a new sink that knows nothing but the database.
    second = PostgresAuditSink(sessionmaker)
    await second.start()
    for n in range(10, 20):
        await second.record(call(n), "ok", None)
    await second.stop()

    rows = await rows_of(sessionmaker)
    assert len(rows) == 20
    assert rows[10]["prev_hash"] == before[9]["hash"]
    assert [row["hash"] for row in rows[:10]] == [row["hash"] for row in before]
    assert chain_problems(rows) == []


async def test_concurrent_writers_single_chain(test_database_url: str, clean_db: None) -> None:
    engines = [create_async_engine(test_database_url, poolclass=NullPool) for _ in range(2)]
    sinks = [
        # Small batches and a short window, so the two writers take turns often.
        PostgresAuditSink(
            async_sessionmaker(engine, expire_on_commit=False), batch_size=7, flush_interval_s=0.002
        )
        for engine in engines
    ]
    sent: list[set[str]] = [set(), set()]

    async def feed(index: int) -> None:
        for n in range(100):
            ctx = call(index * 1000 + n)
            sent[index].add(ctx.call_id)
            await sinks[index].record(ctx, "ok", None)
            if n % 5 == 0:
                await asyncio.sleep(0)

    try:
        for sink in sinks:
            await sink.start()
        await asyncio.gather(feed(0), feed(1))
        await asyncio.gather(*(sink.flush() for sink in sinks))
        rows = await rows_of(async_sessionmaker(engines[0], expire_on_commit=False))
    finally:
        for sink in sinks:
            await sink.stop()
        for engine in engines:
            await engine.dispose()

    assert len(rows) == 200
    assert chain_problems(rows) == []  # one chain: no gap, no fork, every link in place
    assert {row["call_id"] for row in rows} == sent[0] | sent[1]
    writer = [0 if row["call_id"] in sent[0] else 1 for row in rows]
    assert sum(a != b for a, b in itertools.pairwise(writer)) > 1, "no interleaving"


async def test_fail_closed_when_sink_unhealthy(
    keystone_app_factory: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ran: list[str] = []
    dispatched: list[str] = []

    class Watching:
        name = "rate_limit"

        async def before_call(self, ctx: CallContext) -> None:
            ran.append(ctx.tool.name)

        async def after_call(self, ctx: CallContext) -> None:
            return None

    class Spy:
        def __init__(self, inner: Dispatcher) -> None:
            self.inner = inner

        async def dispatch(self, ctx: CallContext) -> ToolResult:
            dispatched.append(ctx.tool.name)
            return await self.inner.dispatch(ctx)

    app = keystone_app_factory(interceptors={"rate_limit": Watching()}, wrap_dispatcher=Spy)
    broken = [True]
    monkeypatch.setattr(app.app.state.audit, "healthy", lambda: not broken[0])

    async with mcp_client(app) as client:
        refused = await client.call_tool("echo__echo", {"payload": "x"})
        broken[0] = False
        allowed = await client.call_tool("echo__echo", {"payload": "x"})

    assert refused.is_error
    assert refused.meta is not None
    assert refused.meta["keystone/code"] == "KS_DENIED"
    assert refused.meta["keystone/reason"] == "audit-unavailable"
    # Nothing ran for the refused call: no interceptor, no upstream. The call after it did.
    assert ran == ["echo__echo"] and dispatched == ["echo__echo"]
    assert not allowed.is_error
    first, second = app.audit.records
    assert (first["outcome"], first["reject_code"], first["dispatched"]) == (
        "rejected",
        "KS_DENIED",
        False,
    )
    assert first["effect"] is None and first["reasons"] == ["audit-unavailable"]
    assert (second["outcome"], second["dispatched"]) == ("ok", True)


async def test_an_unhealthy_sink_does_not_stop_calls_when_fail_closed_is_off(
    keystone_app_factory: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = keystone_app_factory(settings={"audit": AuditSettings(fail_closed=False)})
    monkeypatch.setattr(app.app.state.audit, "healthy", lambda: False)

    async with mcp_client(app) as client:
        result = await client.call_tool("echo__echo", {"payload": "x"})

    assert not result.is_error
    [record] = app.audit.records
    assert (record["outcome"], record["dispatched"]) == ("ok", True)


async def test_the_pipeline_refuses_while_flushes_fail_and_resumes_when_they_work(
    keystone_app_factory: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    test_database_url: str,
) -> None:
    engine = create_async_engine(test_database_url, poolclass=NullPool)
    sink = Flaky(
        async_sessionmaker(engine, expire_on_commit=False), retry_min_s=0.05, retry_max_s=0.1
    )
    try:
        app = keystone_app_factory(audit=sink)
        async with mcp_client(app) as client:
            assert not (await client.call_tool("echo__echo", {"payload": "before"})).is_error
            await sink.flush()
            sink.failing = True
            # This call is accepted and recorded, but its flush fails.
            assert not (await client.call_tool("echo__echo", {"payload": "unlucky"})).is_error
            await until(lambda: not sink.healthy())
            refused = await client.call_tool("echo__echo", {"payload": "refused"})
            assert refused.is_error and refused.meta is not None
            assert refused.meta["keystone/reason"] == "audit-unavailable"
            sink.failing = False
            await until(sink.healthy)
            assert not (await client.call_tool("echo__echo", {"payload": "after"})).is_error
        rows = app.audit.records
    finally:
        await engine.dispose()

    # Nothing was lost: the call that was accepted while the database was away is in the chain
    # in its place, the refusal is there, and the chain is whole.
    assert [(r["outcome"], r["reject_code"]) for r in rows] == [
        ("ok", None),
        ("ok", None),
        ("rejected", "KS_DENIED"),
        ("ok", None),
    ]
    assert chain_problems(rows) == []


async def test_a_failed_batch_is_requeued_in_order_and_counted(sessionmaker: Sessionmaker) -> None:
    metrics = Metrics()
    sink = Flaky(sessionmaker, metrics=metrics, retry_min_s=0.01, retry_max_s=0.02)
    await sink.start()
    sink.failing = True
    sent = [call(n) for n in range(5)]
    for ctx in sent:
        await sink.record(ctx, "ok", None)

    await until(lambda: sink.attempts >= 3)
    assert not sink.healthy()
    assert await rows_of(sessionmaker) == []  # nothing was written, and nothing was dropped
    assert sink.depth == 5

    sink.failing = False
    await sink.flush()
    rows = await rows_of(sessionmaker)
    await sink.stop()

    assert [row["call_id"] for row in rows] == [ctx.call_id for ctx in sent]
    assert chain_problems(rows) == []
    assert failures(metrics, "flush_failed") >= 3
    assert failures(metrics, "record_dropped") == 0
    assert sink.healthy() is False  # stopped
    assert metrics.registry.get_sample_value("keystone_audit_queue_depth") == 0


async def test_a_record_the_database_refuses_is_dropped_alone(sessionmaker: Sessionmaker) -> None:
    metrics = Metrics()
    sink = PostgresAuditSink(sessionmaker, metrics=metrics)
    await sink.start()
    sent = [call(n) for n in range(7)]
    for n, ctx in enumerate(sent):
        # An outcome the table's CHECK refuses: every retry of that record would fail.
        await sink.record(ctx, "weird" if n == 3 else "ok", None)  # type: ignore[arg-type]
    await sink.flush()
    rows = await rows_of(sessionmaker)

    assert [row["call_id"] for row in rows] == [c.call_id for c in sent if c is not sent[3]]
    assert chain_problems(rows) == []
    assert failures(metrics, "record_dropped") == 1
    assert failures(metrics, "flush_failed") == 0
    assert sink.healthy()  # a bad record is not a sick database
    await sink.stop()


async def test_shutdown_flushes_the_queue(sessionmaker: Sessionmaker) -> None:
    # A long batch window and small batches: stop() must not wait for the window, and must write
    # the records that are still queued as well as the batch the writer holds.
    sink = PostgresAuditSink(sessionmaker, batch_size=100, flush_interval_s=30.0)
    await sink.start()
    for n in range(250):
        await sink.record(call(n), "ok", None)

    started = time.monotonic()
    await sink.stop()

    assert time.monotonic() - started < 10
    rows = await rows_of(sessionmaker)
    assert len(rows) == 250
    assert chain_problems(rows) == []


async def test_shutdown_gives_up_when_the_database_stays_away_and_counts_the_loss(
    sessionmaker: Sessionmaker,
) -> None:
    metrics = Metrics()
    sink = Flaky(sessionmaker, metrics=metrics, retry_min_s=0.01, retry_max_s=0.02)
    await sink.start()
    sink.failing = True
    for n in range(3):
        await sink.record(call(n), "ok", None)

    started = time.monotonic()
    await sink.stop(timeout_s=0.3)

    assert time.monotonic() - started < 3
    assert failures(metrics, "shutdown_dropped") == 3
    assert await rows_of(sessionmaker) == []
    with pytest.raises(AuditUnavailable):
        await sink.record(call(9), "ok", None)
    assert failures(metrics, "not_running") == 1


async def test_a_full_queue_refuses_the_record_and_counts_it(sessionmaker: Sessionmaker) -> None:
    release = asyncio.Event()

    class Stalled(PostgresAuditSink):
        async def _insert(self, part: list[dict[str, Any]]) -> None:
            await release.wait()
            await super()._insert(part)

    metrics = Metrics()
    sink = Stalled(
        sessionmaker, metrics=metrics, queue_size=3, batch_size=1, enqueue_timeout_s=0.05
    )
    await sink.start()
    await sink.record(call(0), "ok", None)
    await until(lambda: sink.depth == 1 and sink._queue.empty())  # the writer holds it
    for n in range(1, 4):
        await sink.record(call(n), "ok", None)
    assert not sink.healthy()  # four of three: over 90% of the queue

    with pytest.raises(AuditUnavailable):
        await sink.record(call(4), "ok", None)
    assert failures(metrics, "queue_full") == 1

    release.set()
    await sink.flush()
    await sink.stop()
    assert len(await rows_of(sessionmaker)) == 4  # the refused one was never accepted
    assert sink.accepted == 4 and sink.settled == 4


async def test_the_sink_is_unhealthy_for_five_seconds_after_a_failed_flush(
    sessionmaker: Sessionmaker,
) -> None:
    now = [1000.0]
    # A long pause between retries, so the one failure stays the last thing that happened.
    sink = Flaky(sessionmaker, retry_min_s=100.0, retry_max_s=100.0, clock=lambda: now[0])
    assert not sink.healthy()  # not started
    await sink.start()
    assert sink.healthy()

    sink.failing = True
    await sink.record(call(0), "ok", None)
    await until(lambda: sink.attempts == 1)
    await asyncio.sleep(0.02)
    assert not sink.healthy()
    now[0] += 4.9
    assert not sink.healthy()
    now[0] += 0.2
    assert sink.healthy()

    await sink.stop(timeout_s=0.1)


async def test_a_sink_that_was_never_started_refuses_records(sessionmaker: Sessionmaker) -> None:
    sink = PostgresAuditSink(sessionmaker)

    with pytest.raises(AuditUnavailable):
        await sink.record(call(0), "ok", None)
    assert not sink.healthy()


async def test_the_chain_check_can_fail(sessionmaker: Sessionmaker) -> None:
    async with PostgresAuditSink(sessionmaker) as sink:
        for n in range(5):
            await sink.record(call(n), "ok", None)
        await sink.flush()
    rows = await rows_of(sessionmaker)
    assert chain_problems(rows) == []

    edited = [dict(row) for row in rows]
    edited[2]["tool_name"] = "x"
    deleted = rows[:2] + rows[3:]

    assert chain_problems(edited) == ["seq 3 does not match its own hash"]
    assert chain_problems(deleted) == [
        "seq 3 is missing",
        "seq 4 does not follow the hash before it",
    ]


AWKWARD_ARGUMENTS: dict[str, Any] = {
    "big": 1e22,
    "zero": -0.0,
    "small": 1.5e-7,
    "whole": 5.0,
    "third": 1 / 3,
    "huge_int": 10**30,
    "text": "a\x00b \u00e9 \U0001f600",
    "nested": {"z": 1, "a": [1.0, 2, None, True], "m": {"y": "x"}},
    "api_key": "sk-live-abcdef",
    "note": "card 4111 1111 1111 1111 and ssn 123-45-6789",
}


async def test_arguments_are_stored_masked_and_hash_the_same_after_postgres(
    sessionmaker: Sessionmaker,
) -> None:
    ctx = make_ctx(AWKWARD_ARGUMENTS)
    async with PostgresAuditSink(sessionmaker) as sink:
        await sink.record(ctx, "ok", None)
        await sink.record(make_ctx({}), "ok", None)
        await sink.flush()

    rows = await rows_of(sessionmaker)

    assert chain_problems(rows) == []  # recomputed from the jsonb Postgres returned
    stored = rows[0]["args_redacted"]
    assert stored["big"] == 10**22 and isinstance(stored["big"], int)  # what jsonb returns
    assert stored["zero"] == 0.0 and stored["small"] == 1.5e-7 and stored["whole"] == 5.0
    assert stored["third"] == 1 / 3 and stored["huge_int"] == 10**30
    assert stored["text"] == "a\\u0000b \u00e9 \U0001f600"
    assert stored["nested"] == {"z": 1, "a": [1.0, 2, None, True], "m": {"y": "x"}}
    assert stored["api_key"] == "[redacted]"
    assert stored["note"] == "card [redacted:card] and ssn [redacted:ssn]"
    assert rows[0]["args_digest"] == hashlib.sha256(canonical_json(AWKWARD_ARGUMENTS)).hexdigest()
    assert rows[1]["args_redacted"] == {}
    assert not any(secret in str(rows) for secret in ("sk-live-abcdef", "4111 1111", "123-45-6789"))


async def test_jsonb_does_return_a_big_float_as_an_integer(sessionmaker: Sessionmaker) -> None:
    # The reason the writer stores numbers in the form jsonb returns: this is what it returns.
    async with sessionmaker() as session:
        answer = (await session.execute(text('SELECT \'{"a": 1e22, "b": -0.0}\'::jsonb'))).scalar()

    assert answer == {"a": 10**22, "b": 0.0} and isinstance(answer["a"], int)
    assert canonical_json({"a": 1e22}) != canonical_json(answer)


async def test_the_app_stores_the_arguments_of_a_call_masked(
    keystone_app_factory: Callable[..., KeystoneApp], mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(settings={"audit": AuditSettings(redact_keys=["Payload"])})
    secret_call = {"payload": 7, "extra": "unlisted"}

    async with mcp_client(app) as client:
        refused = await client.call_tool("echo__echo", secret_call)  # payload must be text
        ok = await client.call_tool("echo__echo", {"payload": "card 4111 1111 1111 1111"})

    assert refused.is_error and not ok.is_error
    first, second = app.audit.records
    assert first["args_redacted"] == {"payload": "[redacted]", "extra": "unlisted"}
    assert first["args_digest"] == hashlib.sha256(canonical_json(secret_call)).hexdigest()
    assert second["args_redacted"] == {"payload": "[redacted]"}
    # The card as it was sent, with its spaces: the hex of a hash, a session id or a ULID never
    # holds a space, so a random "4111" inside one of them cannot fail the test (it did once in CI).
    assert "4111 1111" not in str(app.audit.records)


async def test_a_row_hashed_without_the_normalization_is_caught_on_the_way_back(
    sessionmaker: Sessionmaker,
) -> None:
    # The drift the normalization prevents, made to happen: a float with no fraction goes into
    # jsonb as 1e+22 and comes back as an integer, so a hash taken of what was written does not
    # match what a SELECT returns. If the round-trip tests could not see that, they would prove
    # nothing.
    sink = PostgresAuditSink(sessionmaker)
    row = record_fields(call(0), "ok", None)
    row["args_redacted"] = {"big": 1e22}  # not passed through stable_json

    await sink._insert([row])

    rows = await rows_of(sessionmaker)
    assert rows[0]["args_redacted"] == {"big": 10**22}
    assert chain_problems(rows) == ["seq 1 does not match its own hash"]
