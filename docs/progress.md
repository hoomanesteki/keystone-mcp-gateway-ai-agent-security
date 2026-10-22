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
| KS-005 | Database layer and migrations | 3 | done | | `feat/ks-005-db`. CI runs `alembic upgrade head` before the integration tests. |
| KS-006 | Docs skeleton and contributor rules | 2 | done | | `docs/ks-006-docs-skeleton`. Also adds `scripts/lint_prose.py` (planned for KS-907) and turns on the commits and docs CI jobs. |
| KS-007 | Backlog import and traceability scripts | 5 | done | | `chore/ks-007-backlog-scripts`. Deferred: needs gh auth (the real import; only dry runs and a fake-gh test were run). |
| KS-091 | Let the admin merge without a pull request | 1 | done | | `fix/ks-091-protection-admin-bypass`. Found at gate 0: `enforce_admins: true` would block the local merge flow once protection is applied. |

## Phase 1: MCP proxy core

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-101 | Spike: MCP SDK proxy pattern | 2 | done | | `spike/ks-101-mcp-proxy`. The SDK is `mcp` 2.3.0, a new major version; findings in `docs/spikes/mcp-proxy.md`. ADR-0003, 0005 and 0007 written. |
| KS-102 | Core types, errors and naming | 3 | done | | `feat/ks-102-core-types`. `ToolResult` has no result-level meta field and the contract is unchanged, so `to_tool_result` puts `_meta` on the text content block. An upstream id may not end in `_`, or `mail_` + `__` + `x` would not split back. |
| KS-103 | Interceptor pipeline with stubs | 5 | done | | `feat/ks-103-pipeline`. A hook that raises anything but `Reject` fails closed (denied before dispatch, output blocked after) and the audit outcome is `error`. The audit write is shielded from cancellation. `jsonschema` is now a direct dependency. |
| KS-104 | Demo upstreams: mail, files, bank, echo | 5 | done | | `feat/ks-104-demo-upstreams`. Servers use `MCPServer` (FastMCP is gone in mcp 2.x). Every `/_state` also lists the tools called, which the Phase 2 routing test needs. Compose services are `mail-mcp`, `files-mcp`, `bank-mcp`, `echo-mcp`; the built image is tagged `keystone-upstreams:dev` because the pin test requires a tag on every service. |
| KS-105 | Upstream client and session pool | 5 | done | | `feat/ks-105-upstream-client`. Each client keeps its session in one background task, owned by the pool's task group. A call is resent only after `Session not found` (refused before it ran), never after a dropped connection. `health()` lists tools, because `ping` is gone in the newer protocol era. |
| KS-106 | Gateway MCP server | 5 | done | | `feat/ks-106-gateway-server`. Serves the handshake era only (ADR-0003). `ToolResult` has no result-level meta, so a rejection's `_meta` is on its text block (ADR-0007 notes it). Settings gain `upstreams`, `dev_principal` (refused in prod, where `/mcp` answers 401) and `allowed_hosts`. `Pipeline.reject` audits a call to an unknown tool. An `upstreams` entry may omit tenant and url at load time, so the Phase 0 settings test keeps its input; the registry refuses it at startup. |
| KS-107 | Scripted agent, equivalence and first invariants | 3 | done | | `feat/ks-107-scripted-agent`. Every result now carries `keystone/call_id` in its `_meta` so a transcript can quote it. The equivalence test normalizes nothing: no result holds a timestamp or a random id. |
| KS-108 | `make demo` for Phase 1 | 2 | done | | Same branch as KS-107. The demo prints an audit count, so `GET /_dev/audit` exposes the in-memory sink in dev and test (removed with the admin API in Phase 5). Compose gains the `keystone` service; `make up` now passes `--build`. |

## Phase 2: Registry, multi-upstream and pinning

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-191 | Pipeline refuses to dispatch without an allow decision | 1 | done | | `fix/ks-191-pipeline-hardening`. Dispatch only when `decision.effect` is `allow`, or `require_approval` with `approval_id` set; otherwise `KS_DENIED` with reason `no-decision`. The Phase 6 approval interceptor must set `approval_id` only after a successful `consume`. |
| KS-192 | Pool eviction waits for in-flight calls | 2 | done | | Same branch. `UpstreamPool.lease()` counts calls in flight; an evicted client leaves the pool at once and closes after its last call. |
| KS-193 | Rejection meta on the MCP result | 1 | done | | Same branch. `to_tool_result` returns `RejectionResult` (a `ToolResult` subclass, contract unchanged); only that type puts its `keystone/*` keys on the result-level `_meta`. The block copy stays. |
| KS-201 | Schema for upstreams, tools and sessions | 3 | done | | `feat/ks-201-registry-schema`. Migration 0002. `upstreams.id` is the primary key, so an upstream id is unique across tenants (with a unique `(tenant_id, id)` that the tools foreign key uses); KS-307 must pick a different slug for a second tenant's files server, or relax this. Adds `upstreams.source` (config or cli), `tools.last_seen_at`, and check constraints on every status. `cost_per_call_usd` is unconstrained NUMERIC so a float returns unchanged. `test_models_match_the_migrations` fails when a model changes without a migration. |
| KS-202 | Upstream config, admin CLI and SSRF guard | 5 | todo | | |
| KS-203 | Tool discovery and sync | 5 | todo | | |
| KS-204 | Aggregated listing and routing | 3 | todo | | |
| KS-205 | Pinning and quarantine | 5 | todo | | |
| KS-206 | Tool description screening | 3 | todo | | |
| KS-207 | Session store in Redis | 3 | todo | | |
| KS-208 | stdio upstreams | 3 | todo | | |
| KS-209 | Upstream health | 2 | todo | | |

## Phase 3: Identity and credentials

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-301 | Keycloak realm for local identity | 3 | todo | | |
| KS-302 | Fake IdP for tests | 2 | todo | | |
| KS-303 | JWT validation to principal | 5 | todo | | |
| KS-304 | MCP auth wiring and session binding | 5 | todo | | |
| KS-305 | Credential vault | 5 | todo | | |
| KS-306 | Credential injection and the canary invariant | 3 | todo | | |
| KS-307 | Tenant isolation | 3 | todo | | |
| KS-308 | Agent identity and trust | 2 | todo | | |

## Phase 4: Policy engine

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-401 | Spike: cedarpy capabilities | 2 | todo | | |
| KS-402 | Cedar schema and entity builder | 5 | todo | | |
| KS-403 | Policy store with validation and reload | 5 | todo | | |
| KS-404 | Two-pass policy engine | 5 | todo | | |
| KS-405 | Argument extractors | 3 | todo | | |
| KS-406 | Policy interceptor and filtered listing | 3 | todo | | |
| KS-407 | Default policy pack and policy docs | 3 | todo | | |
| KS-408 | Policy test runner | 5 | todo | | |

## Phase 5: Audit and observability

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-501 | Hash-chained audit writer | 5 | todo | | |
| KS-502 | Redaction and argument digests | 3 | todo | | |
| KS-503 | Audit verify and export | 3 | todo | | |
| KS-504 | OpenTelemetry tracing | 5 | todo | | |
| KS-505 | Prometheus metrics | 3 | todo | | |
| KS-506 | Grafana dashboard | 3 | todo | | |
| KS-507 | Admin API read endpoints | 5 | todo | | |

## Phase 6: Approvals and console

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-601 | Approval service | 5 | todo | | |
| KS-602 | Approval interceptor | 5 | todo | | |
| KS-603 | Virtual tools: await approval and whoami | 3 | todo | | |
| KS-604 | Approvals API and webhook notifier | 3 | todo | | |
| KS-605 | Console scaffold with sign-in | 5 | todo | | |
| KS-606 | Console: approvals queue | 5 | todo | | |
| KS-607 | Console: audit explorer | 3 | todo | | |
| KS-608 | Console: tool registry and change review | 3 | todo | | |
| KS-609 | Console end-to-end test | 3 | todo | | |

## Phase 7: Injection defense

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-701 | Scanner interface and rule engine | 5 | todo | | |
| KS-702 | Classifier adapter | 5 | todo | | |
| KS-703 | Combined scoring and output actions | 3 | todo | | |
| KS-704 | Output scanning, session taint and flags | 5 | todo | | |
| KS-705 | Rule of Two policies | 3 | todo | | |
| KS-706 | Full scanner on tool descriptions | 2 | todo | | |
| KS-707 | Detector evaluation harness | 5 | todo | | |
| KS-708 | Injection fixtures, web upstream and naive agent | 3 | todo | | |

## Phase 8: Sandbox, rate limits and budgets

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-801 | Hardened sandbox runner | 5 | todo | | |
| KS-802 | Built-in sandbox tools | 3 | todo | | |
| KS-803 | Containerized stdio upstreams | 3 | todo | | |
| KS-804 | Rate limiting | 3 | todo | | |
| KS-805 | Spend ledger and budgets | 5 | todo | | |
| KS-806 | LLM passthrough proxy with metering | 8 | todo | | |
| KS-807 | Console: budgets and sessions | 3 | todo | | |

## Phase 9: Proof and release

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-901 | Red-team scenario suite | 5 | todo | | |
| KS-902 | Red-team runner and report | 8 | todo | | |
| KS-903 | Performance harness | 5 | todo | | |
| KS-904 | AgentDojo adapter (Could) | 5 | todo | | |
| KS-905 | Terraform for AWS | 5 | todo | | |
| KS-906 | Hardening pass | 3 | todo | | |
| KS-907 | Docs, results and fresh-clone check | 3 | todo | | |
| KS-908 | Release v1.0.0 | 2 | todo | | |

## Deferred

Everything here needs a signed-in GitHub CLI, which this machine does not have. The scripts are
written and their dry runs pass.

| Item | Command | Status |
|---|---|---|
| Branch protection on `main` and `dev` | `make github-setup` | deferred: needs gh auth |
| Milestones, labels and one issue per story | `make github-setup` | deferred: needs gh auth (dry run lists 79 stories, 10 phases, 301 points) |
| GitHub release for `v0.0.1` | `scripts/publish_releases.sh v0.0.1` | deferred: needs gh auth |

## Found

On macOS, a background process can flag dot-directories such as `.venv` as hidden, and Python
skips hidden `.pth` files, so `import keystone` fails after `uv sync`. Setting
`UV_PROJECT_ENVIRONMENT` to a path outside the repo avoids it (see docs/runbook.md).
