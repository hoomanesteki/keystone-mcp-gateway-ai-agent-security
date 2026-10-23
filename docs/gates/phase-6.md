# Phase 6 gate: Approvals and console

Decision: PASS, with one fix story scheduled first in Phase 7
Date: 2026-10-24
Commit: 85f84af on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Python: unit, integration, invariants and e2e, phases 0 to 6 | 1715 | 0 | 0 |
| Policy cases | 39 | 0 | 0 |
| Console unit tests (Vitest) | 122 | 0 | 0 |
| Console end to end (Playwright, chromium) | 1 | 0 | 0 |

`scripts/check_story_tests.py --phase 6`: 181 planned tests across 56 stories (11 of them TypeScript), 0 missing. CI run 39942853964 on the dev tip: 9 of 9 jobs green, including the new `console` job, which also fails if the generated API types drift from the admin API.

## Invariants

| ID | Status |
|---|---|
| I1 to I6 | Pass. I1 accepts `source == "virtual"` for the two `keystone__` tools only |
| I7 an approval-gated call never dispatches without a matching approval | Pass: a forged id, a reused id, changed arguments and an expired approval never dispatch |
| I8 | Not yet applicable |

## Smoke and demo

```
== Playwright
  ✓  1 [chromium] › e2e/approval.spec.ts:20:1 › lena approves a pending transfer (14.5s)
== smoke: phase 6
phase 6 smoke: ok (900 approved and completed, 700 rejected with its note, 600 pending then approved and awaited, 409 on a second decision, 403 for a non-approver)
```

Every earlier smoke passes on the same stack. The browser test signs in as lena on the Keycloak login page, approves olivia's 900 transfer in the console, and then checks both the agent's transcript and the bank's own state. It also runs an accessibility check (axe) in the light and dark themes.

## Numbers measured this phase

- Playwright approval loop: 14.5 s with the stack running, about 75 s when it has to start compose (budget 90 s).
- Full gate from `make reset`: about 13 minutes.

## Code read

`approvals/service.py`.

- `consume` is one UPDATE. It requires status `approved`, the same tenant, tool, session, requesting user and arguments digest, and an expiry still in the future, and it wipes the stored arguments in the same statement. Of two calls presenting one approval at once, exactly one wins.
- Expiry is compared with `clock_timestamp()`, not `now()`. In Postgres `now()` is the transaction's start time, so a statement that waited on a row lock could have used an approval that expired while it waited. The review during the phase found this, and a test holds it.
- `decide` is one UPDATE as well: pending, unexpired, the approver's tenant, and never the approver's own request (separation of duties, tested). A request from another tenant reads as "not found".

`Pipeline.run_before` (ADR-0010): a call approved during its hold runs the pinning, budget, policy and audit-health slots again before the approval is used, so a quarantine or a tighter policy in the meantime still wins. The rate limit is not charged twice.

The console keeps tokens in memory only (PKCE with S256, nothing in localStorage or sessionStorage) and renews them with refresh tokens. Roles in the ID token only hide menu entries; the API enforces every role.

## Findings

| Finding | Severity | Resolution |
|---|---|---|
| Session state is saved whole. A call held for approval can save an older copy over a newer one, which would drop a flag or a taint set by a concurrent call once Phase 7 adds them | High (for Phase 7) | KS-791, first story of Phase 7: session updates become merges |
| Nothing limits how many approval requests or waiters one agent can create | Medium | Rate limits in Phase 8 (KS-804) cover virtual tools and approval-gated calls |
| An approval is used before the credential slot runs, so a refusal there (no per-user credential) costs the approver a second decision | Low | Accepted. The slot order is fixed (section 3.4) |
| Approvals cannot be revoked once granted | Low | Post-v1 backlog. They expire after `approvals.ttl_seconds` |
| TypeScript stays on 6.0: version 7 drops the compiler API that `openapi-typescript` and `typescript-eslint` call | Info | ADR-0002 |

## Contract changes

`Pipeline.run_before(ctx, slot, skip)` added for the re-check after an approval (ADR-0010). `src/keystone/core` and `policies/schema.cedarschema` are unchanged since v0.5.0.
