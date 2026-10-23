"""Reading the audit log back from Postgres, for tests that check what a call left behind.

The app under test writes through its own engine in its own thread, so a test cannot see a record
until the writer has flushed it. `AuditView.records` waits for that, then reads the table with a
connection of its own, in a helper thread (the caller is usually inside a running event loop).
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from keystone.audit.chain import GENESIS, compute_hash, fields_from_row
from keystone.db.models import AuditEvent

WAIT_TIMEOUT_S = 15.0


async def fetch_audit_rows(url: str) -> list[dict[str, Any]]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            table = AuditEvent.__table__
            result = await connection.execute(select(table).order_by(table.c.seq))
            return [dict(row) for row in result.mappings()]
    finally:
        await engine.dispose()


def read_audit_rows(url: str) -> list[dict[str, Any]]:
    """Every row of audit_events in seq order, as dicts keyed by column."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, fetch_audit_rows(url)).result(timeout=30)


def chain_problems(rows: list[dict[str, Any]]) -> list[str]:
    """What is wrong with the chain in these rows, recomputed from the rows alone. Empty when the
    chain is whole: seq runs 1, 2, 3 without a gap, each prev_hash is the hash before it (the
    first is the genesis), and each hash is the hash of its own columns."""
    problems: list[str] = []
    previous = GENESIS
    expected = 1
    for row in rows:
        if row["seq"] != expected:
            problems.append(f"seq {expected} is missing")
        if row["prev_hash"] != previous:
            problems.append(f"seq {row['seq']} does not follow the hash before it")
        if row["hash"] != compute_hash(row["prev_hash"], fields_from_row(row)):
            problems.append(f"seq {row['seq']} does not match its own hash")
        previous = row["hash"]
        expected = row["seq"] + 1
    return problems


class AuditView:
    """The audit rows of one test app."""

    def __init__(self, sink: Any, database_url: str) -> None:
        self.sink = sink
        self.database_url = database_url

    def wait(self, timeout_s: float = WAIT_TIMEOUT_S) -> None:
        """Wait until the writer has written every record it accepted so far. The pipeline
        records a call before the client gets its answer, so a test that has its answers has
        nothing more to wait for than the writer's batch window."""
        accepted = getattr(self.sink, "accepted", None)
        if accepted is None:
            return
        deadline = time.monotonic() + timeout_s
        while self.sink.settled < accepted:
            if time.monotonic() > deadline:
                raise TimeoutError("the audit writer did not catch up")
            time.sleep(0.01)

    @property
    def records(self) -> list[dict[str, Any]]:
        self.wait()
        return read_audit_rows(self.database_url)
