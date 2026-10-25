# Phase 9 gate: Proof and release

Decision: PASS. Release v1.0.0.
Date: 2026-10-25
Commit: 2c96c17 on dev (plus this report and the M9 numbers)

## Tests

From `make reset && make up && make gate PHASE=9`:

| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Python: unit, integration, invariants and e2e, phases 0 to 9 (Docker and real-model tests included) | 3274 | 0 | 0 |
| Policy cases | 67 | 0 | 0 |
| Console unit tests | 181 | 0 | 0 |
| Console end to end (Playwright) | 2 | 0 | 0 |

CI run 40175721276 on the dev tip: 10 of 10 jobs green (`lint-type`, `unit`, `integration`, `policy`, `console`, `security` with gitleaks, pip-audit and trivy, `docker`, `commits`, `docs`, `terraform`).

## Invariants

I1 to I8: pass.

## Smoke and demo

`scripts/smoke/phase_9.sh` runs the smokes of phases 0 to 8 in order against one stack:

```
6 services checked, 0 failed
phase 2 smoke: ok (20 tools, quarantine and approval, a down upstream refused in 17.0 ms)
phase 3 smoke: ok (401 without a token, two tenants kept apart, no key in the logs)
phase 4 smoke: ok (alice denied by default-deny, 900 asks for approval, 100 goes through, a broken policy is refused with version b7b34327e0cd kept)
phase 5 smoke: ok (12 spans in a trace, metrics scraped, chain of 52 records verified, an edit at seq 10 found and undone)
phase 6 smoke: ok (900 approved and completed, 700 rejected with its note, 600 pending then approved and awaited, 409 on a second decision, 403 for a non-approver)
phase 7 smoke: ok (direct: the attack lands; through Keystone: nothing sent, the email scored 0.88, the approval named rule-of-two and tainted-external-effect; a benign summary asked for no approval)
phase 8 smoke: ok (sandbox 42, lena stopped at $0.03, model calls booked at $0.000192 and counted in tokens, a stream byte for byte, no price 400, over budget 402, the provider key nowhere, 7 of 12 calls rate limited)
```

Fresh clone (`scripts/fresh_clone_test.sh`, from GitHub, branch dev, a new Python environment): `make demo` printed 4 of 4 steps ok in 51 s. Docker's image cache on this machine was warm; a cold first build takes about 20 minutes because of the scanner image.

## Scorecard

| ID | Target | Measured | Verdict |
|---|---|---|---|
| M1 | Attack success 0%, scripted agent, full Keystone | 0 of 48 (95% upper bound 7.4%) | met |
| M2 | At least 80% lower attack success with a real model | not run: needs an API key | not run |
| M3 | Benign utility drop of 10 points or less | 0 points (12 of 12) | met |
| M4 | Detector recall 0.90 at FPR 0.05 | 0.71 | not met |
| M5 | Added p50 10 ms, p95 25 ms at 200 sessions | p50 +1988 ms, p95 +2731 ms (one session: +8.6 / +11.7 ms at 1 KB) | not met |
| M6 | Added p95 150 ms with the classifier | the model scored none of the scans under load | not measured |
| M7 | Every call has a recorded decision | I1 passed at the gates of phases 1 to 9 | met |
| M8 | One edited audit row is detected | verify exits 2 and names the row | met |
| M9 | Fresh clone to demo in 10 minutes | 51 s with a warm cache, about 20 minutes cold | met warm, not met cold |

The misses are published with their causes in `docs/results.md`. The short version: the detector is weak on long documents (M4); one process serves about 88 calls a second, so 200 sessions calling back to back wait in a queue (M5); the classifier cannot keep up on a 4-CPU budget and the rules decide instead (M6); the scanner image makes a cold build slow (M9).

## Review

`docs/gates/final-review.md` lists 23 distinct findings from the numbers, security and public-surface reviews, every one fixed or accepted with a reason. No high finding is open. Two bugs found late were fixed before this gate:

- KS-997: a caller that hung up on a non-streamed model answer was booked at zero cost. The answer is now read and booked under a shield; 100 of 100 runs pass.
- KS-994: an audit test failed when a random hash contained the digits of the test card. It now looks for the card as sent.

## Deferred

- The LLM-agent red team (M2) and AgentDojo need an API key. The commands are in `docs/results.md` and `eval/agentdojo/NOTES.md`.
- `terraform plan` against AWS needs an account; `fmt`, `validate` and `tflint` run in CI.
- Branch protection, issues and GitHub releases need a signed-in GitHub CLI: `make github-setup`, then `scripts/publish_releases.sh v1.0.0`.
- Accepted gaps with stories: KS-995 (pin an upstream's resolved address against DNS rebinding) and KS-996 (publish the head of the audit chain).

## Contract changes

None. `git diff v0.8.0..dev -- src/keystone/core policies/schema.cedarschema` is empty. The decisions behind the load fixes are in ADR-0019.
