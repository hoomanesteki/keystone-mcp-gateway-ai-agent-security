#!/usr/bin/env python3
"""Measure how fast the audit writer takes records and writes them (KS-501).

    uv run python scripts/bench_audit.py [--records 20000]

It makes a scratch database next to the configured one, migrates it, and runs three things against
PostgresAuditSink with the default queue, batch size and batch window:

1. record(): how long the pipeline waits to hand a record over. The call returns once the record
   is queued, so this is what auditing adds to a call.
2. One writer: records per second from the first record() to the last row committed, and how long
   each batch transaction takes (advisory lock, read of the last hash, chain, insert, commit).
3. Two writers on one chain, each with a pool of its own, as two replicas would be.

The Postgres in `make up-core` runs in Docker on the same machine, so the figures include no
network. Run it on a quiet machine. The numbers in docs/adr/0009-audit-chain.md come from here.
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from typing import Any

import asyncpg
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from keystone.admin.cli import migrate_database
from keystone.audit.chain import GENESIS, compute_hash, fields_from_row
from keystone.audit.sink import PostgresAuditSink
from keystone.core.ids import new_id
from keystone.core.types import (
    CallContext,
    Decision,
    Effect,
    Principal,
    SessionState,
    ToolRef,
)
from keystone.db.models import AuditEvent
from keystone.settings import Settings

SCRATCH = "keystone_bench_audit"
PRINCIPAL = Principal(
    tenant_id="acme", user_id="olivia", groups=("operators",), agent_id="ops-agent"
)
TOOL = ToolRef(
    name="bank__get_balance",
    upstream_id="bank",
    upstream_tool_name="get_balance",
    tenant_id="acme",
    description="",
    input_schema={},
    description_hash="d",
    schema_hash="s",
)


async def make_database(admin_url: str, name: str, *, create: bool) -> None:
    dsn = admin_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(dsn, timeout=10)
    try:
        await connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        if create:
            await connection.execute(f'CREATE DATABASE "{name}"')
    finally:
        await connection.close()


def make_call() -> CallContext:
    now = datetime.now(UTC)
    return CallContext(
        call_id=new_id(),
        received_at=now,
        principal=PRINCIPAL,
        session=SessionState(session_id="bench", principal=PRINCIPAL, created_at=now),
        tool=TOOL,
        arguments={"account": "CHK-001"},
        decision=Decision(
            effect=Effect.ALLOW,
            reasons=["same-tenant-low-medium"],
            source="policy",
            policy_version="v",
        ),
        dispatched=True,
    )


class Timed(PostgresAuditSink):
    """Notes how long each batch transaction took and how many records it held."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.batches: list[tuple[float, int]] = []

    async def _insert(self, part: list[dict[str, Any]]) -> None:
        started = time.perf_counter()
        await super()._insert(part)
        self.batches.append(((time.perf_counter() - started) * 1000, len(part)))


def percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * share))]


async def run_writers(url: str, writers: int, records: int) -> dict[str, Any]:
    engines = [create_async_engine(url, pool_size=2) for _ in range(writers)]
    sinks = [
        Timed(async_sessionmaker(engine, expire_on_commit=False), queue_size=records + 1)
        for engine in engines
    ]
    calls = [[make_call() for _ in range(records // writers)] for _ in range(writers)]
    handover_ms: list[float] = []
    try:
        for sink in sinks:
            await sink.start()

        async def feed(sink: PostgresAuditSink, mine: list[CallContext]) -> None:
            for ctx in mine:
                started = time.perf_counter()
                await sink.record(ctx, "ok", None)
                handover_ms.append((time.perf_counter() - started) * 1000)
                if len(handover_ms) % 50 == 0:
                    await asyncio.sleep(0)  # a real caller yields to the loop between calls

        started = time.perf_counter()
        await asyncio.gather(*(feed(sink, mine) for sink, mine in zip(sinks, calls, strict=True)))
        queued_s = time.perf_counter() - started
        await asyncio.gather(*(sink.flush(timeout_s=300) for sink in sinks))
        elapsed = time.perf_counter() - started
    finally:
        for sink in sinks:
            await sink.stop()
    async with engines[0].connect() as connection:
        written = (await connection.execute(select(func.count()).select_from(AuditEvent))).scalar()
    for engine in engines:
        await engine.dispose()
    batch_ms = [ms for sink in sinks for ms, _ in sink.batches]
    sizes = [size for sink in sinks for _, size in sink.batches]
    return {
        "written": written,
        "records_per_s": records / elapsed,
        "queued_in_s": queued_s,
        "handover_p50_ms": statistics.median(handover_ms),
        "handover_p95_ms": percentile(handover_ms, 0.95),
        "handover_max_ms": max(handover_ms),
        "batch_p50_ms": statistics.median(batch_ms),
        "batch_p95_ms": percentile(batch_ms, 0.95),
        "batches": len(batch_ms),
        "mean_batch_size": statistics.mean(sizes),
    }


async def check_chain(url: str) -> int:
    """Recompute every hash from the rows. Returns the number of problems."""
    engine = create_async_engine(url)
    problems = 0
    previous = GENESIS
    try:
        async with engine.connect() as connection:
            table = AuditEvent.__table__
            result = await connection.stream(select(table).order_by(table.c.seq))
            expected = 1
            async for mapped in result.mappings():
                row = dict(mapped)
                if (
                    row["seq"] != expected
                    or row["prev_hash"] != previous
                    or row["hash"] != compute_hash(previous, fields_from_row(row))
                ):
                    problems += 1
                previous = row["hash"]
                expected += 1
    finally:
        await engine.dispose()
    return problems


async def clear(url: str) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as connection:
            await connection.exec_driver_sql("TRUNCATE audit_events")
    finally:
        await engine.dispose()


def show(label: str, figures: dict[str, Any]) -> None:
    print(f"\n{label}")
    print(f"  rows written              {figures['written']}")
    print(f"  records per second        {figures['records_per_s']:.0f}")
    print(f"  all queued after          {figures['queued_in_s']:.2f} s")
    print(
        f"  record() hand-over        p50 {figures['handover_p50_ms']:.3f} ms, "
        f"p95 {figures['handover_p95_ms']:.3f} ms, max {figures['handover_max_ms']:.1f} ms"
    )
    print(
        f"  batch transaction         p50 {figures['batch_p50_ms']:.1f} ms, "
        f"p95 {figures['batch_p95_ms']:.1f} ms, {figures['batches']} batches, "
        f"{figures['mean_batch_size']:.0f} records each"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--records", type=int, default=20000)
    args = parser.parse_args()
    admin_url = Settings().database_url.get_secret_value()
    url = make_url(admin_url).set(database=SCRATCH).render_as_string(hide_password=False)
    asyncio.run(make_database(admin_url, SCRATCH, create=True))
    try:
        migrate_database(url)
        print(f"python {platform.python_version()} on {platform.machine()}, {args.records} records")
        for writers in (1, 2):
            figures = asyncio.run(run_writers(url, writers, args.records))
            show(f"{writers} writer{'s' if writers > 1 else ''}", figures)
            problems = asyncio.run(check_chain(url))
            print(f"  chain recomputed from the rows: {problems} problems")
            if problems or figures["written"] != args.records:
                return 1
            asyncio.run(clear(url))
    finally:
        asyncio.run(make_database(admin_url, SCRATCH, create=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
