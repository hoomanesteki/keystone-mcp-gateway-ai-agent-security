# Phase 1 gate: MCP proxy core

Decision: PASS, with three fix stories scheduled first in Phase 2
Date: 2026-10-21
Commit: 564502b on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Unit, integration, invariants and e2e, phases 0 and 1 | 292 | 0 | 0 |

`scripts/check_story_tests.py --phase 1`: 41 planned tests across 15 stories, 0 missing. CI on the dev tip: 7 of 7 jobs green.

## Invariants

| ID | Status |
|---|---|
| I1 decision before dispatch | Pass (stub level: a spy dispatcher sees `allow` at dispatch time) |
| I2 one audit record per call | Pass, including rejected calls and unknown tools |
| I3 to I8 | Not yet applicable |

## Smoke and demo

```
$ make reset && make demo
1. ok   list tools: 12 tools (bank__get_balance, bank__list_transactions, bank__transfer, echo__echo ...)
2. ok   bank__get_balance {"account": "CHK-001"}
      -> { "account": "CHK-001", "owner": "Olivia Reyes", "currency": "USD", "balance": 4825.5 }
3. ok   mail__send_email {"to": "colleague@acme.test", "subject": "Q3 budget review", ...}
      -> { "status": "sent", "id": "s1", "to": "colleague@acme.test" }
4. ok   mail__read_email {"email_id": "m02"}
audit records added: 3, tool calls made: 3, steps ok: 4 of 4
```

The equivalence test passes: 8 calls across mail, files, bank and echo return identical content blocks through Keystone and directly.

## What the spike found

The current MCP Python SDK is 2.3.0, a new major version. The low-level server and the streamable HTTP session manager still fit the plan, and the handler sees the Starlette request. The newest protocol era (2026-07-28) is stateless and carries no session id. Keystone binds state to sessions, so it answers that era with error -32022. Clients set to negotiate fall back to the session handshake; clients pinned to the new era are refused. ADR-0003 records this. Revisit when session state can move into a token or an explicit session tool.

## Code read

`gateway/pipeline.py`, line by line. The audit write runs in `finally` inside a shielded cancel scope, so a cancelled call still leaves its record. A crashing hook fails closed. Upstream exceptions are logged with the call id, and the agent gets a generic `KS_UPSTREAM_ERROR`.

## Findings

| Finding | Severity | Fix story |
|---|---|---|
| The pipeline dispatches whatever the interceptors allow through; nothing in the pipeline itself checks for an allow decision. I1 rests on the policy slot alone | Medium | KS-191 |
| Evicting a client from the upstream pool closes it even if a call is in flight | Medium | KS-192 |
| A rejection's machine-readable `_meta` sits on its text block, not on the MCP result, because `ToolResult` has no meta field | Low | KS-193 |
| `GET /_dev/audit` exists for the demo while the in-memory sink is in use (never in prod) | Low | Removed with the Postgres sink in KS-501 |

## Contract changes

Section 3.6 contracts were created in this phase (KS-102), verbatim. One addition: `Pipeline.reject(ctx, reject)` audits calls that cannot enter the pipeline (unknown tools), so I2 holds for them too.
