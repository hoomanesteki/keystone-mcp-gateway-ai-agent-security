# Progress

One table per phase. Status is one of todo, doing, review, done. The PR column stays empty
while work lands through merge commits on `dev`. Bugs found outside a story's scope go in
the "Found" list at the end.

## Phase 0: Foundation

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-001 | Repo scaffold and toolchain | 3 | done | | `chore/ks-001-scaffold`. No CI yet at merge time. |
| KS-002 | Compose base stack | 3 | done | | `chore/ks-002-compose`. No CI yet at merge time. |
| KS-003 | CI pipeline and branch protection | 3 | done | | `ci/ks-003-pipeline`. Deferred: needs gh auth (`scripts/protect_branches.sh` written, dry run only). Probe run 39713167881 on a throwaway branch failed `lint-type` on an unused import, as intended; the first green run was 39713012721. |
| KS-004 | Settings, logging and health endpoints | 2 | done | | `feat/ks-004-settings-health`. No CI yet at merge time. |
| KS-005 | Database layer and migrations | 3 | todo | | |
| KS-006 | Docs skeleton and contributor rules | 2 | todo | | |
| KS-007 | Backlog import and traceability scripts | 5 | todo | | |

## Found

Nothing yet.
