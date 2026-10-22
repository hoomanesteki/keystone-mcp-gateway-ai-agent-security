# Phase 2 gate: Registry, multi-upstream and pinning

Decision: PASS
Date: 2026-10-22
Commit: 3b47457 on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Unit, integration, invariants and e2e, phases 0 to 2 | 646 | 0 | 0 |

`scripts/check_story_tests.py --phase 2`: 70 planned tests across 24 stories (including fix stories), 0 missing.

CI: run 39845931247 is green on all 7 jobs for commit 3b47457, the dev tip before this report. GitHub Actions did not start a run for the push to dev itself (runs were delayed for hours that day), so the same commit went through CI on a temporary branch. The trees are identical.

## Invariants

| ID | Status |
|---|---|
| I1 decision before dispatch | Pass. Since KS-191 the pipeline itself refuses to dispatch without an allow decision |
| I2 one audit record per call | Pass |
| I4 quarantined or disabled tools never listed, never dispatched | Pass |
| I3, I5 to I8 | Not yet applicable |

## Smoke and demo

```
$ make reset && make up && make gate PHASE=2
======================= 646 passed in 171.05s (0:02:51) ========================
== smoke: phase 1
1. ok   list tools: 15 tools (bank__get_balance, bank__list_transactions, bank__transfer, echo__echo ...)
== smoke: phase 2
tools: 15
  changed: echo__echo (quarantined)
[keystone:KS_QUARANTINED] call 01M5JMS2P4WD7K116ZZYYW462J blocked: tool echo__echo is quarantined (description_changed) and cannot be called until a person reviews it
== 3. a stopped upstream fails fast
[keystone:KS_UPSTREAM_ERROR] call 01M5JMSC42ET69RBE8PAQ1NW3Q failed: upstream bank is down
phase 2 smoke: ok (15 tools, quarantine and approval, a down upstream refused in 23.3 ms)
```

## Numbers measured this phase

- A call to an upstream marked down is refused in 23.3 ms (target 50 ms).
- Tools aggregated: 15 (12 over HTTP from mail, files, bank and echo, 3 from the stdio upstream `echostd`).

## Code read

`registry/sync.py`. `sync_upstream` never raises. A failed or partial tool list writes `last_error` and touches no tool, so an upstream that is down, slow or half broken cannot disable its own tools or anyone else's. Only a complete list can mark a tool as gone. `ToolRepo.refresh`, which runs on every sync, writes config overrides and `last_seen_at` only; the pinned definition, its hashes and the status are never touched outside `set_pending` and an approval.

The review during the phase also closed a gap: a held tool could have escaped review by vanishing and returning, or by an operator disabling and re-enabling it. A held tool now stays held, and `tool disable` refuses a quarantined tool (`fix/ks-205-vanished-quarantine`).

SSRF tests cover IPv4 private, loopback, link-local and CGNAT ranges, IPv6 loopback, unique local and link-local, the AWS metadata endpoint over both families, and a dual-stack host where one of the addresses is private.

## Findings

| Finding | Severity | Resolution |
|---|---|---|
| The SSRF check resolves the host at registration and sync time, not on the connection itself, so DNS rebinding is not stopped | Medium | Accepted for now and listed in the threat model; revisited in the KS-906 hardening pass |
| A stdio upstream's `command` runs on the Keystone host, so anyone who can write the `upstreams` table can run code | Medium | By design for admins; the containerized stdio transport (KS-803) becomes the default for third-party servers |
| The registry cache can be up to 2 s stale; pinning reads Postgres on every call | Low | Measured in the Phase 9 performance run |
| Two commits carry more than their subject says (KS-206 code in a docs commit on the ks-205 branch, part of the KS-203 tests in a docs commit), and one unmerged branch was force-pushed once | Low | Accepted. Shared history is not rewritten |

## Contract changes

`core/errors.py`: `to_tool_result` now returns `RejectionResult`, a `ToolResult` subclass that also carries the meta for the MCP result (KS-193, ADR-0007 updated). Additive: every existing caller still receives a `ToolResult`. Only Keystone builds this subclass, so an upstream cannot forge a Keystone rejection at the result level.
