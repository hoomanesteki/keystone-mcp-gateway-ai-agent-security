# Phase 3 gate: Identity and credentials

Decision: PASS, with two fix stories scheduled first in Phase 4
Date: 2026-10-23
Commit: 438e375 on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Unit, integration, invariants and e2e, phases 0 to 3 | 965 | 0 | 0 |

`scripts/check_story_tests.py --phase 3`: 97 planned tests across 32 stories, 0 missing. CI run 39885721674 on the dev tip: 7 of 7 jobs green.

## Invariants

| ID | Status |
|---|---|
| I1 decision before dispatch | Pass |
| I2 one audit record per call | Pass |
| I3 canary secret never leaks | Pass for logs (structlog and the standard library), audit records, tool results and rejection texts, across a success, an upstream error, an upstream timeout, a rejection, invalid arguments, an unknown tool and a dispatch failure whose exception text holds the headers. Spans join the search in Phase 5 |
| I4 quarantined tools hidden and blocked | Pass |
| I5 tenants never see each other's tools | Pass |
| I6 to I8 | Not yet applicable |

## Smoke and demo

```
$ make reset && make up && make gate PHASE=3
======================= 965 passed in 328.58s (0:05:28) ========================
== smoke: phase 3
HTTP/1.1 401 Unauthorized
tools: 15          # alice, tenant acme
tools: 3           # bob, tenant globex
[keystone:KS_TOOL_NOT_FOUND] call 01M5K7P215WS60S48YR8A453NG failed: there is no tool named 'bank__get_balance'
phase 3 smoke: ok (401 without a token, two tenants kept apart, no key in the logs)
```

The 401 carries `WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource"`, and the metadata endpoint answers per RFC 9728.

## Code read

`identity/jwt.py`, `TokenValidator.validate`. The algorithm allowlist (RS256, ES256) runs first, on the unverified header alone, so nothing else runs for `none`, HMAC, RSA-PSS or a missing `alg`. Header fields that would let a token choose its own key (`jku`, `jwk`, `x5u`) are refused, as are `crit` and `b64`. The key must match the algorithm's family (RSA of at least 2048 bits, or EC on P-256), and the decoder receives exactly one algorithm. `exp`, `iat`, `iss`, `aud` and `sub` are required. An unknown `kid` refreshes the JWKS at most once a minute.

`.gitleaks.toml` allowlists are scoped to exact files and patterns (a curve name in `jwt.py`, fake values in three vault and settings tests).

## Findings

| Finding | Severity | Resolution |
|---|---|---|
| An upstream that echoes its own credential in a result would pass it to the agent; only logs are scrubbed | Medium | KS-392: scrub registered secret values from tool results |
| An upstream answering 401 or 403 goes through the reconnect backoff, about 4 s, before `KS_UPSTREAM_ERROR` | Low | KS-391: authentication failures are not retried |
| Session bindings live in the gateway process, like the SDK's own sessions, so a second replica would not know them | Low | Accepted for v1 (single replica). Revisit with multi-replica support |
| The plan's STRIDE table said a session mismatch returns 401; KS-304 says 403 | Low | Plan corrected to 403 in this branch |

## Contract changes

None. `git diff v0.2.0..dev -- src/keystone/core policies/schema.cedarschema` is empty.
