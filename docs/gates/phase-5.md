# Phase 5 gate: Audit and observability

Decision: PASS
Date: 2026-10-23
Commit: b643878 on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Unit, integration, invariants and e2e, phases 0 to 5 | 1469 | 0 | 0 |
| Policy cases | 39 | 0 | 0 |

`scripts/check_story_tests.py --phase 5`: 152 planned tests across 47 stories, 0 missing. CI run 39907283470 on the dev tip: 8 of 8 jobs green.

## Invariants

| ID | Status |
|---|---|
| I1, I4, I5, I6 | Pass |
| I2 one audit record per call | Pass, now counted in Postgres rows |
| I3 canary secret never leaks | Pass, now also searching every exported span |
| I7, I8 | Not yet applicable |

## Smoke and demo

```
== smoke: phase 5
== 2. a trace with every stage
20 spans in trace d3271d3cf018, leaks: none
== 3. metrics
Prometheus: sum(keystone_tool_calls_total) = 9
Grafana dashboard (provisioned, panels): True 22
== 4. the chain verifies
OK, 40 records
== 5. an edited record is found
broken at seq 10: hash mismatch (exit 2)
== 6. the record is put back
OK, 40 records
phase 5 smoke: ok (20 spans in a trace, metrics scraped, chain of 40 records verified, an edit at seq 10 found and undone)
```

Smokes 0 to 4 still pass, now reading decisions from the admin API instead of the removed dev route.

## Numbers measured this phase

| Measure | Value |
|---|---|
| Audit write throughput, one writer | 11,228 rows/s |
| Batch of 200 rows, write and commit | 16.3 ms p50 |
| `record()` hand-over to the queue | 6 µs p50 |
| Spans for one tool call | 20 |

Measured with `scripts/bench_audit.py` against the compose Postgres.

## Code read

`audit/sink.py`. One writer task drains the queue in batches of up to 200 records or 50 ms. Each batch is one transaction: `pg_advisory_xact_lock`, read the last hash, chain the batch, insert. Two writers therefore produce one chain, and a test runs exactly that. On a failure:

- A batch that fails to commit is kept and retried in order with backoff (0.2 s, doubling to 3 s), logged as `audit_flush_failed` and counted.
- A record the database refuses as data is isolated by halving the batch, then dropped alone, logged with its call id and counted as `record_dropped`. The rest of the batch goes in.
- A full queue, and anything left when the shutdown flush times out, are counted under their own reasons.
- While the queue is over 90 percent full or a flush failed in the last 5 s, `healthy()` is false, and with `audit.fail_closed` (the default outside dev) calls are refused with `audit-unavailable` before any interceptor runs.

Migration 0006 creates the `keystone_app` role the app runs as. It can insert and read audit records and nothing else: UPDATE, DELETE and TRUNCATE on `audit_events` are revoked, and a test proves an UPDATE fails. The password comes from `KEYSTONE_APP_DB_PASSWORD`, and the migration refuses to run in prod without it.

Span attributes carry `keystone.user_hash` and never a raw user id or an argument value.

## Findings

| Finding | Severity | Resolution |
|---|---|---|
| Two made-up secrets (a test key block and a test bearer token) were committed once in a redaction test; the test now builds them at run time | Low | `.gitleaksignore` lists those two findings by fingerprint, with the reason |
| The main app no longer serves `/docs` or `/openapi.json`; the admin API keeps its own schema at `/admin/api/v1/openapi.json` | Info | Intended: the gateway does not describe itself to strangers |
| The hash chain proves internal consistency. An attacker with superuser access can rewrite the whole chain from an edited row onward | Info | Known limit (Phase 5 "Defend it"). Publishing the chain head elsewhere is post-v1 |

## Contract changes

`AuditSink.healthy() -> bool` (`gateway/pipeline.py`), allowed by KS-501 and recorded in ADR-0009. `src/keystone/core` and `policies/schema.cedarschema` are unchanged since v0.4.0.
