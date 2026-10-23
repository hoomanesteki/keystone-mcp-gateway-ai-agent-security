"""Checking the hash chain and exporting records (KS-503, ADR-0009).

`verify_chain` reads the rows in seq order and recomputes every hash from what the database
returns, which is what the writer hashed. A row is wrong when its seq is not the next one (a row
is missing), when it does not point at the hash of the row before it, or when its own hash is not
the hash of its columns. The first problem found ends the check and names the seq.

It proves the log is consistent with itself. Someone who can rewrite every row and every hash,
or who removes the newest rows, leaves a chain that verifies; publishing the latest hash
somewhere out of their reach is what closes that (ADR-0009).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.audit.chain import GENESIS, canonical_fields, compute_hash, fields_from_row
from keystone.db.models import AuditEvent

Problem = Literal["hash mismatch", "gap"]
STREAM_ROWS = 1000


@dataclass(frozen=True)
class Verdict:
    """The result of a check. `records` counts the rows that were good."""

    ok: bool
    records: int
    seq: int | None = None
    problem: Problem | None = None

    @property
    def message(self) -> str:
        if self.ok:
            return f"OK, {self.records} record{'' if self.records == 1 else 's'}"
        return f"broken at seq {self.seq}: {self.problem}"


async def verify_chain(
    sessions: async_sessionmaker[AsyncSession],
    *,
    from_seq: int | None = None,
    last: int | None = None,
) -> Verdict:
    """Check the whole chain, or from `from_seq` on, or the newest `last` records.

    Starting in the middle, the row before the start is the anchor: its stored hash is what the
    first row checked must point at. That row itself is not checked, so a check that starts at
    seq N says nothing about N-1 and before. The first record is anchored on the genesis hash."""
    table = AuditEvent.__table__
    async with sessions() as session:
        if last is not None:
            newest = (await session.execute(select(func.max(table.c.seq)))).scalar()
            from_seq = max(1, (newest or 0) - last + 1)
        start = from_seq or 1
        previous = GENESIS
        if start > 1:
            anchor = (
                await session.execute(select(table.c.hash).where(table.c.seq == start - 1))
            ).scalar()
            if anchor is None:
                return Verdict(ok=False, records=0, seq=start - 1, problem="gap")
            previous = anchor
        expected = start
        good = 0
        result = await session.stream(
            select(table)
            .where(table.c.seq >= start)
            .order_by(table.c.seq)
            .execution_options(yield_per=STREAM_ROWS)
        )
        async for mapped in result.mappings():
            row = dict(mapped)
            if row["seq"] != expected:
                return Verdict(ok=False, records=good, seq=expected, problem="gap")
            linked = row["prev_hash"] == previous
            if not linked or row["hash"] != _hash_of(row):
                return Verdict(ok=False, records=good, seq=row["seq"], problem="hash mismatch")
            previous = row["hash"]
            expected += 1
            good += 1
        return Verdict(ok=True, records=good)


def _hash_of(row: dict[str, Any]) -> str | None:
    """The hash the row's columns give, or None for a row whose own hash cannot be recomputed
    (a prev_hash that is not hex): that row is wrong, and verify says so, not crashes."""
    try:
        return compute_hash(row["prev_hash"], fields_from_row(row))
    except ValueError:
        return None


def export_record(row: dict[str, Any]) -> dict[str, Any]:
    """One record as the JSON an export writes. The columns are in the form the hash covers
    (timestamps and decimals as strings), so whoever holds the line can check it with a sha256
    and a JSON library: hash = sha256(bytes.fromhex(prev_hash) + canonical JSON of the line without
    seq, prev_hash and hash)."""
    return {
        "seq": row["seq"],
        **canonical_fields(fields_from_row(row)),
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
    }


async def export_records(
    sessions: async_sessionmaker[AsyncSession],
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    tenant: str | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """The records from `since` (inclusive) up to `until` (exclusive), in seq order, for one
    tenant or all, a thousand rows at a time."""
    table = AuditEvent.__table__
    statement = select(table).order_by(table.c.seq).execution_options(yield_per=STREAM_ROWS)
    if since is not None:
        statement = statement.where(table.c.ts >= since)
    if until is not None:
        statement = statement.where(table.c.ts < until)
    if tenant is not None:
        statement = statement.where(table.c.tenant_id == tenant)
    async with sessions() as session:
        result = await session.stream(statement)
        async for mapped in result.mappings():
            yield export_record(dict(mapped))
