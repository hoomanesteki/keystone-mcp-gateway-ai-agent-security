"""Audit sinks: the Postgres writer the app uses (KS-501, ADR-0009) and the in-memory one the
pipeline's unit tests use.

The writer takes a record from the pipeline, puts it on a bounded queue and returns. One task
reads the queue in batches. Each batch is one transaction: take an advisory lock, read the last
hash, chain the batch, insert. The lock keeps one chain across replicas.

What happens to a record that cannot be written (the gate reads this, ADR-0009):
- A batch that fails is kept, in order, and tried again after a pause. It is logged
  (`audit_flush_failed`) and counted (`keystone_audit_failures_total{reason="flush_failed"}`).
  Nothing is dropped because the database was away.
- A record the database refuses as data (a constraint, a type) would fail every retry and block
  the log behind it. The batch is halved until that record is alone. It is dropped, logged with
  its call id (`audit_record_dropped`) and counted (`reason="record_dropped"`). The others go in.
- A record that does not fit on a full queue is refused after a wait (`reason="queue_full"`).
- At shutdown the queue is flushed. Whatever is left at the time limit is logged and counted
  (`reason="shutdown_dropped"`).
A process that is killed loses what was queued and not yet written, at most one batch window of
50 ms of calls. That is the price of not writing on the call's path.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any, Literal, Self

import structlog
from sqlalchemy import insert, select, text
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.audit.chain import GENESIS, Outcome, compute_hash, record_fields
from keystone.audit.redact import RedactionConfig
from keystone.core.errors import Reject
from keystone.core.types import CallContext
from keystone.db.models import AuditEvent
from keystone.telemetry.metrics import Metrics

log = structlog.get_logger()

MAX_RECORDS = 100_000

QUEUE_SIZE = 10_000
BATCH_SIZE = 200
FLUSH_INTERVAL_S = 0.05
# Over this share of the queue, the sink is unhealthy and a fail-closed pipeline refuses calls.
UNHEALTHY_QUEUE_SHARE = 0.9
# A failed flush, or one still running after this long, makes the sink unhealthy.
UNHEALTHY_WINDOW_S = 5.0
ENQUEUE_TIMEOUT_S = 5.0
SHUTDOWN_TIMEOUT_S = 10.0
RETRY_MIN_S = 0.2
RETRY_MAX_S = 3.0
ATTEMPT_TIMEOUT_S = 15.0
LOCK_TIMEOUT = "5s"
# Taken by every writer for the length of its transaction: "KSAUDIT" and a zero byte. Nothing
# else in Keystone may take an advisory lock with this key.
AUDIT_LOCK_KEY = 0x4B53415544495400
# SQLSTATE classes of an error that belongs to the record, not to the connection: 22 data
# exception, 23 integrity violation. 23505 (unique) is the race of two writers, which a retry
# settles after it reads the new last hash.
RECORD_ERROR_CLASSES = ("22", "23")
RETRY_STATES = ("23505",)

FailureReason = Literal[
    "flush_failed", "record_dropped", "queue_full", "shutdown_dropped", "not_running"
]

Row = dict[str, Any]


class AuditUnavailable(Exception):
    """A record could not be handed to the writer."""


def sqlstate(error: BaseException) -> str | None:
    """The Postgres SQLSTATE behind a driver error, if there is one."""
    original = getattr(error, "orig", None) or error
    for candidate in (original, getattr(original, "__cause__", None)):
        code = getattr(candidate, "sqlstate", None) or getattr(candidate, "pgcode", None)
        if isinstance(code, str):
            return code
    return None


def is_record_error(error: BaseException) -> bool:
    """True when retrying the same record can never work, so it must be set apart."""
    code = sqlstate(error)
    if code is not None:
        return code[:2] in RECORD_ERROR_CLASSES and code not in RETRY_STATES
    if isinstance(error, DBAPIError):
        return isinstance(error, DataError | IntegrityError)
    # A record that cannot be turned into bytes or a hash fails in this process, every time.
    return isinstance(error, ValueError | TypeError)


class InMemoryAuditSink:
    """One dict per call. It holds identifiers and outcomes, never arguments or results,
    because an audit record must not become a second copy of the data (CONTRIBUTING rule 6).
    It keeps the newest `max_records`, so a long-running process does not fill memory. The
    pipeline's unit tests use it; the app uses the Postgres writer."""

    def __init__(self, max_records: int = MAX_RECORDS) -> None:
        self.records: list[dict[str, Any]] = []
        self._max = max_records

    def healthy(self) -> bool:
        return True

    async def record(
        self,
        ctx: CallContext,
        outcome: Outcome,
        reject: Reject | None,
    ) -> None:
        self.records.append(
            {
                "call_id": ctx.call_id,
                "received_at": ctx.received_at,
                "tenant_id": ctx.principal.tenant_id,
                "user_id": ctx.principal.user_id,
                "agent_id": ctx.principal.agent_id,
                "session_id": ctx.session.session_id,
                "tool": ctx.tool.name,
                "upstream_id": ctx.tool.upstream_id,
                "decision": ctx.decision.effect.value if ctx.decision else None,
                "decision_source": ctx.decision.source if ctx.decision else None,
                "reasons": list(ctx.decision.reasons) if ctx.decision else [],
                "policy_version": ctx.decision.policy_version if ctx.decision else None,
                "dispatched": ctx.dispatched,
                "outcome": outcome,
                "reject_code": reject.code.value if reject else None,
                "timings_ms": dict(ctx.timings_ms),
            }
        )
        if len(self.records) > self._max:
            del self.records[: len(self.records) - self._max]


class PostgresAuditSink:
    """Writes audit records to `audit_events`, chained by hash. Start it before the first call
    and stop it after the last one; `async with sink:` does both."""

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        metrics: Metrics | None = None,
        redaction: RedactionConfig | None = None,
        queue_size: int = QUEUE_SIZE,
        batch_size: int = BATCH_SIZE,
        flush_interval_s: float = FLUSH_INTERVAL_S,
        enqueue_timeout_s: float = ENQUEUE_TIMEOUT_S,
        shutdown_timeout_s: float = SHUTDOWN_TIMEOUT_S,
        retry_min_s: float = RETRY_MIN_S,
        retry_max_s: float = RETRY_MAX_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sessions = sessions
        self._metrics = metrics if metrics is not None else Metrics()
        self._redaction = redaction
        self._queue_size = queue_size
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._enqueue_timeout_s = enqueue_timeout_s
        self._shutdown_timeout_s = shutdown_timeout_s
        self._retry_min_s = retry_min_s
        self._retry_max_s = retry_max_s
        self._clock = clock
        # None is the signal to stop: the writer reads it after every record queued before it.
        self._queue: asyncio.Queue[Row | None] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._stopping = False
        self._deadline: float | None = None
        self._stop_seen = False
        # Records taken off the queue and not yet written or dropped.
        self._held = 0
        # Counted for the whole life of the sink. Both only grow, so another thread can compare
        # them without a lock (the test helper that waits for the writer does).
        self.accepted = 0
        self.settled = 0
        self._last_failure_at: float | None = None
        self._flushing_since: float | None = None
        self._metrics.audit_queue_depth.set_function(lambda: self.depth)

    @property
    def depth(self) -> int:
        """Records accepted and not yet written."""
        return self._queue.qsize() + self._held

    def healthy(self) -> bool:
        """False when a record handed to the sink might not be written: the writer is not
        running, the queue is over 90% full, or a flush failed less than 5 s ago (or has run
        longer than that). A pipeline that fails closed refuses calls meanwhile."""
        if not self._running or self._stopping:
            return False
        if self.depth > self._queue_size * UNHEALTHY_QUEUE_SHARE:
            return False
        now = self._clock()
        if self._last_failure_at is not None and now - self._last_failure_at < UNHEALTHY_WINDOW_S:
            return False
        started = self._flushing_since
        return not (started is not None and now - started > UNHEALTHY_WINDOW_S)

    async def start(self) -> None:
        if self._task is not None:
            return
        self._running = True
        self._stopping = False
        self._stop_seen = False
        self._task = asyncio.get_running_loop().create_task(self._run(), name="audit-writer")
        self._task.add_done_callback(self._writer_ended)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()

    async def record(self, ctx: CallContext, outcome: Outcome, reject: Reject | None) -> None:
        if not self._running or self._stopping:
            self._count("not_running")
            raise AuditUnavailable("the audit writer is not running")
        try:
            row = record_fields(ctx, outcome, reject, redaction=self._redaction)
        except Exception:
            # A call this process cannot describe would fail the same way again. It is counted and
            # logged here, and the pipeline logs it once more as a failed audit.
            self._count("record_dropped")
            log.error("audit_record_dropped", call_id=ctx.call_id, error="record_fields")
            raise
        # Counted before the put so that, from any thread, written never passes accepted.
        self.accepted += 1
        try:
            self._queue.put_nowait(row)
        except asyncio.QueueFull:
            try:
                await asyncio.wait_for(self._queue.put(row), self._enqueue_timeout_s)
            except TimeoutError:
                self.accepted -= 1
                self._count("queue_full")
                log.error("audit_queue_full", call_id=ctx.call_id, depth=self.depth)
                raise AuditUnavailable("the audit queue is full") from None
            except BaseException:
                self.accepted -= 1
                raise

    async def flush(self, timeout_s: float = 10.0) -> None:
        """Wait until every record accepted so far is written or dropped."""
        target = self.accepted
        deadline = time.monotonic() + timeout_s
        while self.settled < target:
            if time.monotonic() > deadline:
                raise TimeoutError(f"{target - self.settled} audit records are still queued")
            await asyncio.sleep(0.01)

    async def stop(self, timeout_s: float | None = None) -> None:
        """Write what is queued, then end the writer. Whatever is left when the time is up is
        logged and counted, not written."""
        task = self._task
        if task is None:
            return
        limit = self._shutdown_timeout_s if timeout_s is None else timeout_s
        self._stopping = True
        self._deadline = time.monotonic() + limit
        try:
            async with asyncio.timeout(limit):
                await self._queue.put(None)
                await task
        except TimeoutError:
            pass
        except Exception as error:
            log.error("audit_writer_failed", error=type(error).__name__)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            lost = self.accepted - self.settled
            if lost > 0:
                self._count("shutdown_dropped", lost)
                log.error("audit_shutdown_dropped", records=lost)
                self.settled = self.accepted
            self._held = 0
            self._task = None
            self._running = False

    def _writer_ended(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            self._running = False
            log.error("audit_writer_died", error=type(error).__name__, exc_info=error)

    def _count(self, reason: FailureReason, amount: int = 1) -> None:
        self._metrics.audit_failures.labels(reason=reason).inc(amount)

    async def _run(self) -> None:
        while True:
            batch = await self._next_batch()
            if batch is None:
                return
            await self._write(batch)
            if self._stop_seen:
                return

    async def _next_batch(self) -> list[Row] | None:
        first = await self._queue.get()
        if first is None:
            return None
        batch = [first]
        self._held = 1
        loop = asyncio.get_running_loop()
        window_ends = loop.time() + self._flush_interval_s
        while len(batch) < self._batch_size:
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                remaining = window_ends - loop.time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self._queue.get(), remaining)
                except TimeoutError:
                    break
            if item is None:
                self._stop_seen = True
                break
            batch.append(item)
            self._held = len(batch)
        return batch

    async def _write(self, batch: list[Row]) -> None:
        parts = [batch]
        pause = self._retry_min_s
        while parts:
            part = parts[0]
            self._flushing_since = self._clock()
            try:
                async with asyncio.timeout(ATTEMPT_TIMEOUT_S):
                    await self._insert(part)
            except Exception as error:
                self._flushing_since = None
                if is_record_error(error):
                    if len(part) > 1:
                        middle = len(part) // 2
                        parts[0:1] = [part[:middle], part[middle:]]
                    else:
                        self._drop(part[0], error)
                        parts.pop(0)
                    continue
                self._note_failure(error, len(part))
                if self._deadline is not None and time.monotonic() >= self._deadline:
                    return  # stop() counts what is left
                await asyncio.sleep(pause)
                pause = min(pause * 2, self._retry_max_s)
            else:
                self._flushing_since = None
                self._last_failure_at = None
                pause = self._retry_min_s
                self.settled += len(part)
                self._held -= len(part)
                parts.pop(0)
        self._held = 0

    async def _insert(self, part: list[Row]) -> None:
        """One transaction: lock, read the last hash, chain the records, insert them. The lock is
        released by the commit, and the next writer reads the rows this one wrote."""
        async with self._sessions() as session, session.begin():
            await session.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": AUDIT_LOCK_KEY}
            )
            tip = (
                await session.execute(
                    select(AuditEvent.seq, AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)
                )
            ).first()
            seq, previous = (tip.seq, tip.hash) if tip is not None else (0, GENESIS)
            rows: list[Row] = []
            for fields in part:
                seq += 1
                digest = compute_hash(previous, fields)
                rows.append({**fields, "seq": seq, "prev_hash": previous, "hash": digest})
                previous = digest
            await session.execute(insert(AuditEvent), rows)

    def _note_failure(self, error: BaseException, records: int) -> None:
        self._last_failure_at = self._clock()
        self._count("flush_failed")
        original = getattr(error, "orig", None) or error
        log.error(
            "audit_flush_failed",
            error=type(error).__name__,
            sqlstate=sqlstate(error),
            # The first line of the driver's own message. SQLAlchemy's text would add the
            # statement and its parameters, which are the records.
            detail=str(original).splitlines()[0][:200] if str(original) else "",
            records=records,
            queued=self.depth,
        )

    def _drop(self, row: Row, error: BaseException) -> None:
        self._count("record_dropped")
        self.settled += 1
        self._held -= 1
        log.error(
            "audit_record_dropped",
            call_id=row.get("call_id"),
            error=type(error).__name__,
            sqlstate=sqlstate(error),
        )
