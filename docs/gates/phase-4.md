# Phase 4 gate: Policy engine

Decision: PASS
Date: 2026-10-23
Commit: 9a1d90a on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Unit, integration, invariants and e2e, phases 0 to 4 | 1278 | 0 | 0 |
| Policy cases (`keystone policy test`) | 39 | 0 | 0 |

`scripts/check_story_tests.py --phase 4`: 126 planned tests, 0 missing. Policy coverage: every policy in the default, demo and acme sets is matched by at least one case. CI run 39897295089 on the dev tip: 8 of 8 jobs green, including the new `policy` job.

## Invariants

| ID | Status |
|---|---|
| I1 decision before dispatch | Pass, and the decision now comes from the policy engine (`source == "policy"`) |
| I2, I3, I4, I5 | Pass |
| I6 an empty policy set denies every call | Pass |
| I7, I8 | Not yet applicable |

## Smoke and demo

```
== smoke: phase 4
[keystone:KS_DENIED] call 01M5KEZ0WKHDTYFR0780Q1ZT1P denied: denied by policy: default-deny
audit: deny default-deny
audit: require_approval approve-transfer-over-500
== 4. a broken policy is refused and the version stays
reload: 422 {"error": "invalid_policies", "errors": ["default/access/base.cedar: unexpected end of input"], "version": "fbf54f412dd7..."}
phase 4 smoke: ok (alice denied by default-deny, 900 asks for approval, 100 goes through, a broken policy is refused with version fbf54f412dd7 kept)
```

## Numbers measured this phase

| Measure | p50 | p95 | Budget |
|---|---|---|---|
| Engine evaluation, shipped policy pack | 0.16 ms | 0.16 ms | 5 ms (CI), 2 ms (laptop) |
| Engine evaluation, 50 policies and 20 entities | 0.18 ms | 0.29 ms (worst run) | 5 ms |

Measured with `scripts/bench_policy.py` (cedarpy 4.12.2); method in `docs/spikes/cedarpy.md`.

## Code read

`policy/engine.py`. Allow is returned on two lines only: a listing after an explicit access permit, and a call whose access set allowed with a named permit and whose approval set matched nothing. Everything else denies. An unknown tenant, a Cedar evaluation error, a decision of "none", an allow that names no policy, or an exception all end in deny with reason `policy-error`, and the error is logged. This matters more than it looks: Cedar skips a policy that fails to evaluate, even a `forbid`, so treating any error as deny is what keeps a broken forbid from becoming an allow. The engine reads the policy set once per call, so a reload mid-call cannot mix two versions.

Two choices in the shipped policies go beyond the plan, and both make the rules stricter:

- Transfer amounts are read in cents (`$.amount | cents`) and compared with 50000. With whole units, `int` would truncate 500.99 to 500 and let it under the limit.
- When an approval rule cannot read the value it needs (no amount, or a recipient that is not one plain address), it asks for approval rather than staying silent.

## Findings

| Finding | Severity | Resolution |
|---|---|---|
| The plan's KS-407 example has alice send external mail, but `send_email` is high risk, so access denies alice before the approval set runs | Low | The test uses olivia (operators), which exercises the approval rule as intended |
| Ten earlier tests ran high-risk calls as alice; with real policy they now run as olivia | Info | Listed in the KS-406 commit body. No assertion and no policy was loosened |
| `session.call_count` stays 0 until the session flags interceptor lands | Info | Phase 7 (KS-704) |

## Contract changes

None. `policies/schema.cedarschema` is plan section 3.8 verbatim, and `src/keystone/core` is unchanged since v0.3.0.
