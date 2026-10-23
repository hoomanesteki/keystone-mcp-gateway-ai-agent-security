# ADR-0009: A hash-chained audit log, written in batches

Status: accepted
Date: 2026-10-23

## Context

Every tool call has to leave a record that a reviewer can trust after an incident. Two things
get in the way. Anyone who can write to the table can edit a row, and a plain log would not show
it. And the writer has to stay off the call's path, survive a Postgres that blinks, and never let
a call run that it cannot record.

## Decision

**The chain.** Each row stores `prev_hash` and `hash`. `hash` is
`sha256(bytes.fromhex(prev_hash) + canonical_json(columns))`, where the columns are every column
except `seq`, `prev_hash` and `hash`. The first row's `prev_hash` is 64 zeros. Changing a row
changes its hash, and the row after it no longer points at it. Removing a row breaks the same
link. `seq` is outside the hash; `keystone audit verify` reads rows in `seq` order and checks the
links, so moving a row shows too.

**What is hashed is what a SELECT returns.** Verification recomputes hashes from rows read back
from Postgres, so the writer normalizes before it hashes and before it stores:

- `ts` is UTC with microseconds and is hashed as `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always six digits.
- `cost_usd`, `scan_score` and `latency_ms` are `numeric` columns written as Decimals with a fixed
  number of places (8, 6 and 3) and hashed as the plain decimal string. A float would come back
  as something else. Hashing quantizes again, so a column that returns another scale hashes the
  same.
- `args_redacted` goes through `stable_json`. jsonb stores numbers as `numeric` and prints them
  without an exponent, so a float with no fraction (`1e22`) comes back as an integer and `-0.0` as
  `0.0`; `stable_json` writes those the way jsonb returns them. A NUL character, which neither
  `text` nor jsonb can hold, becomes the six characters `\u0000`.
- `canonical_json` sorts the keys, so the order jsonb keeps does not matter.

`tests/integration/test_audit_sink.py` writes awkward values (a time in another zone, a float
cost, a NUL in a tool name) and recomputes every hash from rows read back from the database.

**One chain across writers.** A batch is one transaction: `pg_advisory_xact_lock`, read the last
`(seq, hash)`, extend the chain, insert, commit. The lock is released by the commit, and the next
writer reads the rows this one wrote. No coordinator and no single writer process are needed, and
batching keeps the lock short. `prev_hash` is unique, so a second row after the same row is
refused by the database even if the lock were bypassed; the loser retries and reads the new tip.

**`seq` is assigned by the writer**, as the last `seq` plus one, inside that transaction. The
column is a `bigserial` as the data model says, but a sequence is not rolled back: a failed batch
would leave a gap, and verify reads a gap as a deleted row. The unused default also means a
hand-written insert collides on the primary key instead of forking the chain.

**The writer.** `record()` builds the row from the call context at once, so a later change to the
context cannot reach it, puts it on a queue of 10,000 and returns. One task takes up to 200 rows
or 50 ms, whichever comes first. `AUDIT_LOCK_KEY` is a constant no other code may use.

**A batch that fails is kept, not dropped.** The gate reads this, so it is stated in full.

- A failure of the connection, the transaction or a lock (anything but a data error) leaves the
  batch where it is. The writer waits 0.2 s, doubling to 3 s, and tries again with the same
  records in the same order, ahead of everything queued since. Each failure is logged as
  `audit_flush_failed` with the error type and SQLSTATE, and counted in
  `keystone_audit_failures_total{reason="flush_failed"}`. A flush has 15 s to finish, so a
  connection that hangs counts as a failure too.
- A record that the database refuses as data (SQLSTATE class 22 or 23, except a unique violation,
  or a record that cannot be turned into a hash) would fail every retry and hold the log hostage:
  one call with an odd argument could stop the gateway. The writer halves the batch until that
  record is alone, then drops it, logs `audit_record_dropped` with its call id, and counts
  `reason="record_dropped"`. The rest of the batch is written. The normalization above exists so
  that this path stays a safety net.
- If the queue is full for 5 s, the new record is refused (`reason="queue_full"`, logged as
  `audit_queue_full`), and the pipeline logs the failure and counts it in its own
  `audit_failures`. With `fail_closed` the pipeline stops taking calls long before, at 90%.
- Shutdown puts a stop marker behind the queue and waits up to 10 s for the writer. Anything left
  at the limit is logged as `audit_shutdown_dropped` and counted with `reason="shutdown_dropped"`.
- A process that is killed (SIGKILL, a crash, power) loses the rows it had not yet written: those
  in the queue and the batch in flight, at most the last 50 ms of calls under light load. That is
  the price of not writing on the call's path. The alternative, a commit before every answer,
  puts a Postgres round trip on every call.

**Arguments (KS-502).** A row holds `args_redacted`, the call's arguments with secrets masked, and
`args_digest`, the sha256 of the canonical JSON of the original arguments. Whoever holds the
original can prove what was sent; nobody can read it back out of the log.

- A key that matches the log scrubber's rule (secret, token, password, api key, authorization) or
  is listed in `audit.redact_keys` has its value replaced by `[redacted]`, whatever the value is.
- In strings, these patterns are masked: a payment card number (13 to 19 digits that pass the Luhn
  check), a US social security number, `Bearer <token>`, an AWS access key id (`AKIA` or `ASIA`
  and 16 characters) and a private key block.
- A string over 2,048 characters becomes its first 256 characters and `...[sha256:<hex>]` of the
  whole. Masking runs on the whole string first, so a card number across the cut is masked.
- What one row keeps is capped at 16 KiB of canonical JSON. A call's arguments can be 1 MiB, and
  the queue holds 10,000 records.

The patterns are a net with holes: a number in a field no pattern knows, or one written in some
other grouping, is stored as it came. The way to cover a field is to list its key.

**Fail closed.** `AuditSink` gets one method, `healthy() -> bool`. It is false when the writer is
not running or is stopping, when the queue is over 90% full, when the last flush failed less than
5 s ago, or when a flush has run for more than 5 s. The pipeline asks it before the argument
check and before any interceptor. With `audit.fail_closed` true, which is the default unless
`env` is `dev`, an unhealthy sink makes the pipeline raise `Reject(DENIED, "audit unavailable")`
with `keystone/reason: audit-unavailable`. The refusal is audited like any other, as soon as the
writer can take it, with the reason in `reasons`. This is the one change to the contracts of
plan section 3.6 that KS-501 allows; `Pipeline.__init__` also takes `fail_closed` as a keyword
argument with the default `False`, which `build_pipeline` sets from the settings.

**Verification and the role (KS-503).** `keystone audit verify` streams the rows in `seq` order.
A row whose `seq` is not the next one means a row is missing (`gap`, naming the missing seq). A row
that does not point at the hash before it, or whose own hash is not the hash of its columns, is a
`hash mismatch` at its seq. The first problem ends the check. Exit code 2 means broken, 1 means the
check could not run. `export` writes the same columns in the form the hash covers, one JSON object
per line, so a recipient needs only sha256 and a JSON library to check a record.

The application's role, `keystone_app`, may insert and select on `audit_events`, with UPDATE,
DELETE and TRUNCATE revoked, and has full access to every other table (default privileges cover
the tables of later migrations). Migrations run as the owner of the tables, through
`KEYSTONE_MIGRATE_DATABASE_URL`. The role is created by a migration, because the tests and CI have
no other place to make it; roles belong to the cluster, so a migration leaves an existing one
alone, and refuses to create one with the development password when `KEYSTONE_ENV` is `prod`.

**Columns beyond the data model's list.** The table has `dispatched` (did the call reach the
upstream: `outcome` cannot say, because output blocked after the call is `rejected`) and
`decision_source` (which part decided: policy, pinning, a rate limit). It has no `created_at`:
`ts` is the time of the call, and a time the database chose would sit outside the hash.

## Consequences

- The chain proves the log is consistent with itself. An attacker who can rewrite the whole table
  can rewrite every hash too, and who deletes the newest rows leaves a shorter chain that still
  verifies. Publishing the latest hash somewhere the attacker cannot reach (an object-locked
  bucket, a separate log) closes both, and is post-v1.
- The app's database role may insert and select on `audit_events` and nothing else (KS-503), so
  a compromised gateway cannot edit what it wrote.
- Writing the chain is serial: one lock, one transaction at a time, across every replica. A
  second writer shares the throughput of the first and does not add to it:

  | Writers | Rows per second | Batch transaction p50 / p95 | `record()` p50 / p95 |
  |---|---|---|---|
  | 1 | 11,228 | 16.3 ms / 26.0 ms | 6 µs / 8 µs |
  | 2 | 11,493 | 29.7 ms / 62.9 ms | 6 µs / 8 µs |

  Measured with `scripts/bench_audit.py` on 20,000 records in batches of 200: Postgres 16.15 in
  Docker on the same Apple-silicon laptop, Python 3.12.13, no network. The second writer's batches
  take longer because they wait for the first one's lock. A real call is far below this rate
  (the demo makes a few per second), and the hand-over time is what a call pays.
- Every call pays one `record_fields` and a queue put. It reads no database.
- `healthy()` makes a Postgres outage a Keystone outage when `fail_closed` is on. That is the
  intent, and `dev` turns it off.

## Revisit when

A deployment needs more audit writes per second than the lock allows (then shard the chain per
tenant), or needs the latest hash published automatically, or a call must not be answered until
its row is committed.
