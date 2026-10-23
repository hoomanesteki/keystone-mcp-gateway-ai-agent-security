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
| KS-202 | Upstream config, admin CLI and SSRF guard | 5 | done | | `feat/ks-202-upstream-config`. A config entry the registry cannot use (unknown tenant, URL refused by the guard) stops startup with every problem named and writes nothing. `keystone upstream remove` refuses a config upstream. Adds `keystone db upgrade` and `serve --migrate`, because the app now needs the registry tables at startup and compose never ran migrations. `upstream sync` arrives with KS-203. The guard checks at registration, so DNS rebinding is not covered (runbook says so). |
| KS-203 | Tool discovery and sync | 5 | done | | `feat/ks-203-tool-sync`. `registry/sync.py` is the file to read first: a failed list changes no tool, the upstream's or anyone else's, and `sync_upstream` never raises. A changed definition is only reported until KS-205. `RegistryService` replaces `StaticRegistry` in the app; `static.py` stays for its Phase 1 unit tests. The service caches per tenant for `registry.cache_ttl_s` (2 s) so a CLI sync reaches a running gateway. `registry sync` and `upstream sync` exit 1 if any upstream failed. A tool list cut off at the page limit is now an error. |
| KS-204 | Aggregated listing and routing | 3 | done | | `feat/ks-204-aggregate`. The list and the routing were already complete after KS-203, so this story is tests plus `notifications/tools/list_changed`. SDK 2.3 supports it in the handshake era; details in `docs/spikes/mcp-proxy.md` section 6. |
| KS-205 | Pinning and quarantine | 5 | done | | `feat/ks-205-pinning`. The pinning slot asks Postgres for the tool's status on every call, because the registry cache can be 2 s old and a CLI quarantine must stop the next call. A change taken back by the upstream releases the tool. `approve-change --expect FP` guards against a definition that changed after the review. Invariant I4 (`tests/invariants/test_i4_quarantine.py`) covers quarantine, a hand-disabled tool, a removed tool and a disabled upstream. The reasons are constants in `registry/pinning.py`. Found in review and fixed on `fix/ks-205-vanished-quarantine`: a tool held for review stays held when it vanishes from the upstream, and `tool disable` refuses a quarantined tool, so neither is a way around the review. |
| KS-206 | Tool description screening | 3 | done | | Same branch. Five rules in `defense/description_check.py`; the phrase rules run after hidden characters are stripped and the text is NFKC-normalized, so a zero-width space inside a word does not hide it. `tool show` prints the hits for the current and the pending description. Only new tools are screened at sync; a changed description is quarantined by KS-205 regardless. |
| KS-207 | Session store in Redis | 3 | done | | `feat/ks-207-session-store`. `GETEX` restarts the 24 h clock on read. The gateway saves the session after each call, which is what moves `last_seen_at` (at most once a minute). A Redis failure refuses the call through the pipeline (`KS_DENIED`, audited, so I2 holds); a Postgres failure only logs. An empty `KEYSTONE_REDIS_URL` selects the in-memory store. App tests now point at Redis database 15 and the `redis` fixture empties it. |
| KS-208 | stdio upstreams | 3 | done | | `feat/ks-208-stdio`. The SDK's stdio client always adds HOME, USER, SHELL and a few more variables, so a launcher (`python -I -S -c ...`) in front of the command keeps only PATH and the configured names and then execs the command; values never reach a command line. `env` is YAML-only because the `upstreams` table has no column for it. The HTTP and stdio clients share `_SessionClient`. The image now holds `examples/` and runs in `/app`. `scripts/smoke/phase_2.sh` and `tests/e2e/test_phase2.py` cover the checkpoint (15 tools, quarantine and approval, a down bank refused in about 20 ms). A stdio command is arbitrary code execution for whoever can write the table: the runbook says so. |
| KS-209 | Upstream health | 2 | done | | Same branch as KS-204. Probe interval, timeout and thresholds are settings (`health.*`, env `KEYSTONE_HEALTH__...`). A probe now connects if no session exists, with one attempt and no backoff, so a restarted upstream is noticed. A refused call sets `dispatched` to false. `/readyz` gained `upstreams`, so the Phase 0 readiness test compares the other keys. |

## Phase 3: Identity and credentials

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-301 | Keycloak realm for local identity | 3 | done | | `feat/ks-301-identity-fixtures`. Users have fixed ids, so a token's `sub` is the user name (`alice`). A `support` group exists although the story's group list omits it, because alice is "acme, support". Placeholders in the realm file are filled from Keycloak's environment; the dev values are in `.env.example` and repeated in compose, and `tests/unit/test_dev_secrets.py` fails if they differ. Verified by hand: an edited realm file is imported after `make reset && make up` but not after a plain `make up`. The runbook has the table of what to run. |
| KS-302 | Fake IdP for tests | 2 | done | | Same branch. Paths match Keycloak's (`/realms/keystone/...`). The first RSA and EC keys are made once per test process because RSA generation takes 0.1 s. `make_token` can also forge `alg=none` and the HS256 key-confusion token for KS-303. `token_for(user)` mirrors the realm's users, and `tests/unit/test_realm.py` checks that. |
| KS-303 | JWT validation to principal | 5 | done | | `feat/ks-303-jwt-principals`. `identity/jwt.py` reads the header first and refuses any `alg` outside RS256 and ES256 before a key is looked up, then checks that the key is RSA (2048 bits or more) for RS256 or EC P-256 for ES256, then gives the decoder that one algorithm. `exp`, `iat`, `iss`, `aud` and `sub` are required. Keys: 3 s timeout, and an unknown `kid` refreshes them once a minute (the first load does not count against that, so the first rotation is picked up at once). Keys that cannot be fetched give 503, not 401. Beyond the story, a header with `jku`, `jwk`, `x5u`, `crit` or `b64` is refused, and so are encryption keys and RSA keys under 2048 bits in the JWKS. I broke the validator twelve ways to check the tests notice (allow HS256, look up the key first, skip the audience check and so on). |
| KS-304 | MCP auth wiring and session binding | 5 | done | | `feat/ks-304-mcp-auth`. `identity/middleware.py` runs before the SDK: Host check (so 421 still beats 401), token to principal, session check. The binding is made from the `initialize` response, the first place the session id exists, and kept in the gateway process like the SDK's own sessions; a session id with no binding gets 404 and is never adopted by the first caller. Mismatch is 403 as the story says (the STRIDE table in the plan says 401). The handler also compares the stored state with the caller, so state changed behind its back is not trusted. `dev_principal` exists only with `auth.mode: none` (dev and test). Earlier tests changed through the fixtures: `mcp_client` signs in as alice, tests that call a high-risk tool or assert the old dev principal use `user="olivia"`. Two assertions changed because the story changes the behavior: the 401 challenge now carries `resource_metadata`, and a session is stored when it opens, so `test_a_list_before_any_call_stores_nothing` became `test_a_session_is_stored_when_it_opens_before_any_call`. Compose turns on `oidc`, and the smoke scripts sign in as olivia. |
| KS-305 | Credential vault | 5 | done | | `feat/ks-305-vault`. Fernet under `KEYSTONE_MASTER_KEYS` (first encrypts, all decrypt); `credentials` has a foreign key to the upstream and a unique constraint on (tenant, upstream, user) with NULLS NOT DISTINCT, so an upstream has one static row. `Vault` takes a store, so the unit tests use a dict. `cred set` has no option for the value: stdin, a hidden prompt or `--from-env`. Rotation skips rows already under the first key and replaces a row only if its ciphertext is still what was read, so it cannot undo a `cred set`. `KEYSTONE_ENV=prod` refuses the key published in `.env.example` (by its fingerprint). The log scrubber now holds a registry of secrets (KS-306 asks for it; the vault needs it now) and replaces them as substrings, not only whole values. `test_migrations_up_down` lists the new table. Settings errors can print the rejected value, so `master_keys` is validated when the vault is built, with a message that never quotes it. |
| KS-306 | Credential injection and the canary invariant | 3 | done | | `feat/ks-306-cred-injection`. `CredentialInterceptor` is the real credential slot (after policy and approval); the dispatcher also drops the headers when a call fails. Beyond the story, because the demo upstreams now demand their key: the registry sync and the health probes use the upstream's static credential (`Vault.service_headers`), and a new `credential_env` in the upstream config (header to environment variable) puts the keys into the vault at startup, through the vault, never from plaintext config. Demo servers report `api_key_received` (a boolean) in `/_state`. Tests get a second set of keyed demo servers (`keyed_upstreams`) whose echo key is the `canary_secret`, and `keystone_app_factory(keyed=True)`. I3 runs a session with a success, an upstream error, a timeout, a policy refusal, invalid arguments, an unknown tool and a dispatch that fails with the headers in its message, then searches the logs (structlog and stdlib), the audit records and every result; a second test shows the search finds the canary when the scrubber is off. The scrubber's registry is cleared after startup in I3, so decrypt-time registration is what is tested. Not covered, and listed in the runbook: an upstream that copies its key into a result. Spans are not searched until Phase 5 adds a tracer. A 401 from an upstream takes about 4 s to become `KS_UPSTREAM_ERROR`, because the client retries a failed connection three times. |
| KS-307 | Tenant isolation | 3 | done | | `feat/ks-307-tenants`. The registry lookups already took a tenant, so the story is mostly proof: `test_i5` has alice and bob each list and call every tool of the other tenant (15 tools, all `KS_TOOL_NOT_FOUND`, none dispatched, all audited), and a test swaps in a registry that ignores the tenant to show the gateway drops its answers anyway. A token for a tenant that is not in the config gets 403 `unknown_tenant` (an addition: it would otherwise open sessions and rows for a tenant nothing serves). The second tenant's upstream is `files_globex`, because upstream ids are unique across tenants (the note on KS-201); its server runs `files_server` on port 8112 with a seed of its own (`FILES_SEED`). Three session-binding tests moved to an app that serves globex, so that bob is a known principal there. `scripts/smoke/phase_3.sh` and `tests/e2e/test_phase3.py` follow the checkpoint. |
| KS-308 | Agent identity and trust | 2 | done | | Same branch. `agents` and `auth.allow_unknown_agents` in the settings; an unlisted agent is `Forbidden` (403) unless allowed, then trust `low`. `tests/integration/test_agents.py::test_unknown_agent_rejected` checks the rule on a real token from the fake IdP; the 403 over HTTP arrives with KS-304. |

## Phase 4: Policy engine

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-391 | Upstream authentication failures fail fast | 1 | done | | `fix/ks-391-upstream-auth-hardening`. Found at gate 3. The SDK turns every error status into one protocol error without the status, so a response hook on the HTTP client (`AuthWatch`) notes a 401 or 403, and a connection attempt that saw one raises `KS_UPSTREAM_ERROR` at once instead of walking through the backoff. A call took 41 ms in the test, against about 4.2 s before. A refusal on a session that is already open was never slow. |
| KS-392 | Scrub registered secrets from tool results | 2 | done | | Same branch. `gateway/scrub.py` replaces the injected credential values and every secret in the scrubber's registry with `[redacted]` in every string of the result (all block types, structured content, object keys), inside `UpstreamDispatcher.dispatch`, and logs `upstream_result_redacted`. A value Keystone sent is replaced whatever its length; the registry still skips values under 8 characters. The test-only upstream is `tests/fixtures/reflecting_upstream.py`; I3 now includes it and a second test shows the search finds the canary when the scrub is off. A value that comes back changed (reversed, encoded) is not caught. |
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
| First run of `.github/workflows/nightly.yml` | Run workflow in the Actions tab, or `gh workflow run nightly.yml` | deferred: needs gh auth. The same two commands (`make up`, `make test-e2e`) pass locally. |

## Found

On macOS, a background process can flag dot-directories such as `.venv` as hidden, and Python
skips hidden `.pth` files, so `import keystone` fails after `uv sync`. Setting
`UV_PROJECT_ENVIRONMENT` to a path outside the repo avoids it (see docs/runbook.md).
