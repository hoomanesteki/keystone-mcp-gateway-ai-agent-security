# Phase 0 gate: Foundation

Decision: PASS
Date: 2026-10-21
Commit: 5c2ff16 on dev

## Tests

| Suite | Passed | Failed | Skipped (later phases) |
|---|---|---|---|
| Unit | 96 | 0 | 0 |
| Integration | 9 | 0 | 0 |
| E2E (compose) | 2 | 0 | 0 |
| Total | 107 | 0 | 0 |

`scripts/check_story_tests.py --phase 0`: 15 planned tests across 7 stories, 0 missing.

CI on the dev tip: 7 jobs green (`lint-type`, `unit`, `integration`, `security`, `docker`, `commits`, `docs`), about 90 s per run.

## Invariants

I1 to I8: not yet applicable (the pipeline arrives in Phase 1).

## Smoke and demo

```
$ make reset && make up && make gate PHASE=0
============================= 107 passed in 15.00s =============================
== smoke: phase 0
SERVICE      ENDPOINT                                             STATUS
postgres     pg_isready on :55432                                 healthy
redis        PING on :56379                                       healthy
keycloak     realm keystone on :8180                              healthy
jaeger       UI on :16686                                         healthy
prometheus   /-/healthy on :9090                                  healthy
grafana      /api/health on :3000                                 healthy
6 services checked, 0 failed

$ uv run python scripts/import_backlog.py --dry-run
79 stories, 10 phases, 301 points
```

## Numbers measured this phase

- `make up` from cold volumes: 27 to 31 s on a 10-core laptop (target 120 s).
- Full gate test run: 15 s.

## Findings

| Finding | Severity | Resolution |
|---|---|---|
| `protect_branches.sh` set `enforce_admins: true` with required pull requests, which would block the local merge flow once applied | Medium | Fixed in KS-091 |
| One KS-007 commit subject overstates its content; the next commit completes it | Low | Accepted. History on shared branches is never rewritten |
| On this machine a background process marks `.venv` hidden, and Python then skips its `.pth` file | Low | Documented in `docs/runbook.md` (set `UV_PROJECT_ENVIRONMENT` outside the repo). A fresh clone is unaffected |

## Deferred

These need a signed-in GitHub CLI. The scripts exist and their dry runs are tested. `make github-setup` runs them.

- Branch protection on `main` and `dev`.
- Milestones, labels and the 79 story issues.
- The GitHub release for this tag (`scripts/publish_releases.sh v0.0.1`).

## Contract changes

None. `src/keystone/core` does not exist yet.
