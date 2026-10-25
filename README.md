# Keystone

[![CI](https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A self-hosted MCP gateway that decides every tool call an AI agent makes, holds the risky ones for a person, and records all of them.

Project page: <https://hoomanesteki.github.io/keystone-mcp-gateway-ai-agent-security/>

| If you want to | Go to |
|---|---|
| See it work | [Quick start](#quick-start) |
| Check a number | [Results](#results), then [docs/results.md](docs/results.md) |
| Know what it does not cover | [What it does not do](#what-it-does-not-do) |
| Understand the design | [How it works](#how-it-works), [docs/architecture.md](docs/architecture.md) |
| Run or change it | [Deploying](#deploying), [Development](#development), [docs/runbook.md](docs/runbook.md) |

## In one minute

An agent that reads email, web pages or files reads text a stranger wrote, and an agent that obeys that text can forward an invoice or move money. An MCP client that connects straight to each tool server has no single place to stop that call and no record of who allowed it.

Keystone is one MCP endpoint in front of all your tool servers. Each call passes identity, Cedar policy, approval and an injection scanner before it runs, and leaves one hash-chained audit row after.

I planted 48 attacks in mail, files, web pages and bank transactions, and ran a scripted agent that obeys every instruction it reads. It is a script, not a language model.

| Setup | Attacks that landed | Harmless tasks done |
|---|---|---|
| No defense (C0) | 48 of 48 | 12 of 12 |
| Access rules and approvals (C1) | 36 of 48 | 12 of 12 |
| Everything on (C2) | **0 of 48** (95% interval 0.0% to 7.4%) | 12 of 12 |

Source: [docs/results.md, Red team](docs/results.md#red-team), 2026-10-24, commit `050b15fd102a`. The approver in that run was an oracle: it approved what each task needed and rejected every other held call.

Two targets are missed, and the numbers are in [Results](#results). Detector recall is 0.71 against a target of 0.90. Under 200 concurrent sessions the gateway adds about 2 s at the median, because it is one process on one event loop.

```mermaid
flowchart LR
  A["Agents (any MCP client)"] -->|"MCP over HTTP, OIDC token"| K["Keystone /mcp"]
  K -->|"allowed calls, credential added"| T["Tool servers: mail, files, bank, web"]
  K -->|"held calls"| P["Approver in the console"]
  K -->|"one row per call"| L[("Audit log in Postgres")]
```

## How it stops the demo attack

1. The agent reads a poisoned email. The scanner scores it at 0.85 or more and taints the session, and the inbox tool adds the flag `reads_untrusted`.
2. The email tells the agent to forward an invoice to an outside address. That tool is tagged `external_effect`. Four Cedar rules match, among them `tainted-external-effect` and `untrusted-then-external-effect`, and each sends the call to a person.
3. The call waits in the console. The approver rejects it, the mail server never sees it, and the agent gets `KS_APPROVAL_REJECTED` as a tool result.

The mechanism is under [How it works](#how-it-works).

## Results

The targets are those of the plan ([docs/PLAN.md](docs/PLAN.md), section 1.7). Every value comes from a file in [eval/results/](eval/results/), rendered into [docs/results.md](docs/results.md) with its date and commit, and `tests/unit/test_results_doc.py` recomputes the key ones from the raw files. All runs: one Apple M4 laptop (10 CPUs), 2026-10-24 and 2026-10-25.

| ID | Target | Measured | Verdict | Source |
|---|---|---|---|---|
| M1 | Attack success, scripted agent, full Keystone: 0% | 0 of 48 (0.0%, 95% CI 0.0% to 7.4%) | met | [red team](docs/results.md#red-team) |
| M2 | Attack success, real model agent: at least 80% lower than no gateway | not run: needs an API key | not run | [the LLM agent](docs/results.md#the-llm-agent) |
| M3 | Harmless task drop: at most 10 points | 0.0 points (12 of 12 with and without Keystone) | met | [red team](docs/results.md#red-team) |
| M4 | Detector recall at a false positive rate of 5% or less: at least 0.90 | 0.71 (95% CI 0.67 to 0.74) | not met | [detector](docs/results.md#detector) |
| M5 | Added latency, scanner off: p50 at most 10 ms, p95 at most 25 ms | 200 sessions, 1 KB: p50 +1987.9 ms, p95 +2731.4 ms, 0 of 4,000 calls failed. One session, 1 KB: p50 +8.6 ms, p95 +11.7 ms. One session, 8 KB: p50 +11.0 ms, p95 +15.6 ms | not met at 200 sessions | [performance](docs/results.md#performance) |
| M6 | Added latency, classifier on, up to 2,000 tokens: p95 at most 150 ms | not measured: the model scored none of the scans in the run (see below). The rules alone, one session: p95 +47.8 ms at 1 KB, +115.8 ms at 8 KB | not measured | [performance](docs/results.md#performance) |
| M7 | Every tool call has a recorded decision | invariant test I1 passes at every gate | met | [phase 8 gate](docs/gates/phase-8.md) |
| M8 | One edited audit row is detected | `keystone audit verify` exits 2 and names the row | met | [phase 5 gate](docs/gates/phase-5.md) |
| M9 | Fresh clone to `make demo` in 10 minutes or less | measured at release | not run | [scripts/fresh_clone_test.sh](scripts/fresh_clone_test.sh) |

The full scorecard, with the files each value comes from, is in [docs/results.md](docs/results.md#scorecard).

What each layer stopped, for the scripted agent:

| Attack goal | C0 | C1 | C2 |
|---|---|---|---|
| Forward an invoice to an outside address | 12 of 12 | 0 of 12 | 0 of 12 |
| Transfer 450 dollars to the attacker's account | 12 of 12 | 12 of 12 | 0 of 12 |
| Write the attacker's endpoint into a config file | 12 of 12 | 12 of 12 | 0 of 12 |
| Send a colleague a phishing mail | 12 of 12 | 12 of 12 | 0 of 12 |

The cost of C2 is a person in the loop: 1.05 approval requests per run, and a person was asked during 3 of the 12 harmless tasks, against 1 of 12 in C1.

Why the misses:

- **M2.** The real-model run needs a model API key, and this project has none. The LLM agent loop, its metering and its budget stop are tested against a fake model API. That shows the wiring works and says nothing about how a model behaves, so it is not a row of the table. The command for the real run is in [docs/results.md](docs/results.md#the-llm-agent).
- **M4.** The classifier was trained on direct prompts and is weak on documents with an attack buried inside (0.28 alone on documents). The rules alone reach 0.59. I tuned thresholds on the dev split only, and every scoring of the test split is logged in [test-runs.jsonl](eval/results/test-runs.jsonl).
- **M5.** `keystone serve` is one uvicorn worker on one event loop. After the load fixes of [ADR-0019](docs/adr/0019-load-fixes.md) it serves 88 calls a second with the scanner off, against 1,072 for the echo server alone. At 200 sessions the added time is the wait for that loop, not the work of a call. With one session the gateway meets the target at 1 KB and misses the p50 by 1 ms at 8 KB.
- **M6.** In the performance run the container used about 3 of its 4 CPUs with the classifier on, and a scan of about 850 characters took 0.6 to 1.5 s against a wait of 300 ms. The model answered none of the scans, 98% to 99% found its one place taken, and the rules decided them. The 150 ms target needs a longer wait, a smaller model, the model outside the container or a GPU. That is a choice I have not made yet.
- **M9.** The first build took 20 minutes because the Keystone image holds torch and a 738 MB model. The timing script exists and has not been run, so I do not quote a number.

## Quick start

### Prerequisites

| Tool | Version I use | Needed for |
|---|---|---|
| Docker with Compose v2 | Docker Desktop with Docker 29, 8 GB of memory for its VM | the stack |
| GNU make, git, curl | any recent | the commands below |
| [uv](https://docs.astral.sh/uv/) | 0.12 | the demo scripts, the CLI and the tests |
| Python | 3.12 (`uv python install 3.12`) | installed and run by uv |
| `python3` on PATH | any 3.x | the shell scripts (`get_token.sh`, `demo_attack.sh`, the smokes) call it directly. On a Mac it comes with the Xcode command line tools |
| Node and pnpm | Node 26, pnpm 12 | the console and `make check` |

`make check` also builds two Docker images, so the Docker daemon must be running for it.

### Start the stack

1. Clone the repository and install the Python dependencies.

   ```bash
   git clone https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security.git
   cd keystone-mcp-gateway-ai-agent-security
   uv sync
   ```

2. Build and start everything.

   ```bash
   make up
   ```

   It prints a `Container keystone-<service>-1  Healthy` line per service and returns when all of them are healthy. The first build took 20 minutes on my laptop, because the Keystone image holds torch and a 738 MB classifier model. After that a rebuild took 54 seconds and a cold start takes about 30 seconds ([runbook](docs/runbook.md#local-stack)).

3. Check it.

   ```bash
   bash scripts/smoke/phase_0.sh
   curl -fsS http://localhost:8080/healthz
   ```

   The smoke script prints one row for each of the six infrastructure services (Postgres, Redis, Keycloak, Jaeger, Prometheus, Grafana). It does not check Keystone or the demo tool servers; the `curl` checks Keystone.

No `.env` is needed on a Mac: the defaults in [.env.example](.env.example) apply when it is absent. Copy it to `.env` only to move a port or change a password. On Linux, put `DOCKER_SOCKET_GID=$(stat -c %g /var/run/docker.sock)` in `.env` before `make up`, or the sandbox calls fail while the stack still reports healthy.

The address of every service is in the [runbook, Host ports](docs/runbook.md#host-ports), and the demo users and their passwords are in the [runbook, Getting started](docs/runbook.md#getting-started).

### See the attack demo

1. Run it. It runs `make up` first, so it also works from a stopped stack.

   ```bash
   make demo-attack
   ```

2. Read the `BEFORE` block. The agent is asked to summarize unread mail, and email `m13` tells it to forward the latest invoice to `attacker@evil.test`. Straight at the mail server it obeys, and the script prints `The mail server sent a mail to attacker@evil.test. The invoice is gone.`
3. Read the `AFTER` block. Through Keystone the scanner scores the email, the session is tainted and the forward is held. The approval card names four rules: `external-email-needs-approval`, `rule-of-two`, `tainted-external-effect` and `untrusted-then-external-effect`. The approver rejects it, and the script prints `The mail server sent nothing.`
4. Read the last block. A harmless summary through Keystone completes and nobody is asked anything.

The script exits 0 only when the first run was robbed and the second was not. `make demo` is the plain version: a scripted agent works as `olivia` through Keystone, and the script ends with `audit records added: 3, tool calls made: 3, steps ok: 4 of 4`.

Against one stack, the smoke scripts of phases 0 to 8 in a row took about 3 minutes, and 74 s on a second run ([docs/progress.md](docs/progress.md)). I have not timed these two demos on their own.

### Open the console

The console is a Vite dev server for approvers and admins. The steps, and how to make an approval card appear, are in the [runbook, Open the console](docs/runbook.md#open-the-console).

## How it works

### Where Keystone sits

```mermaid
flowchart LR
  agent["Agent or any MCP client"] -->|"Bearer JWT, MCP over HTTP"| ks["Keystone /mcp"]
  idp[("Keycloak or another OIDC provider")] -.->|"signing keys"| ks
  ks -->|"call plus injected credential"| up["Tool servers: mail, files, bank, web"]
  ks -->|"code"| sbx["Sandbox container, no network"]
  ks -->|"audit rows, approvals, ledger"| pg[("Postgres")]
  ks -->|"sessions, buckets, spend"| rd[("Redis")]
  ks -.->|"traces, metrics"| obs["Jaeger, Prometheus, Grafana"]
  console["Console"] -->|"admin API"| ks
```

[docs/architecture.md](docs/architecture.md) has the components, the data model, the Redis keys and the sequence of one call that needs an approval.

### The pipeline of one call

Every `tools/call` goes through nine slots in a fixed order ([src/keystone/gateway/wiring.py](src/keystone/gateway/wiring.py)). A slot before the dispatch can refuse the call, and then nothing after it runs except the audit row. The refusal reaches the agent as a tool result with a `KS_*` code, so the model can read why ([ADR-0007](docs/adr/0007-rejections-as-tool-results.md)).

```mermaid
flowchart TD
  IN["tools/call with a valid token"] -->|"call"| S1
  subgraph pre ["slots 1 to 6, before the dispatch"]
    S1["1 rate_limit"] --> S2["2 pinning"] --> S3["3 budget"] --> S4["4 policy"] --> S5["5 approval"] --> S6["6 credential"]
  end
  S6 -->|"call with the credential header"| D["dispatch to the tool server or the sandbox"]
  D -->|"tool result"| S7["7 output_scan"]
  S7 -->|"result, annotated, redacted or withheld"| S8["8 session_flags"]
  S8 --> S9["9 metering"]
  S9 -->|"result"| OUT["result to the agent"]
  pre -.->|"refusal from any of slots 1 to 6"| REF["refusal as a tool result"]
  OUT -->|"decision and reasons"| AUD["audit row, always written"]
  REF -->|"decision and reasons"| AUD
```

| Slot | What it does |
|---|---|
| 1 rate_limit | Token buckets per tenant, user, agent and tool. |
| 2 pinning | Refuses a tool that is quarantined (its description changed) or disabled. |
| 3 budget | Checks spend against the budgets before the call runs. |
| 4 policy | Cedar decides allow, deny or require approval; the policy ids are the reasons. |
| 5 approval | Holds the call until a person decides; it runs once, with the approved argument digest. |
| 6 credential | Decrypts the tool server's key and adds it as a header, after policy and approval. |
| 7 output_scan | Scores the output with seven rules and a classifier; annotates, redacts or withholds it, and taints the session at 0.85. |
| 8 session_flags | Adds the tool's tags (`reads_untrusted`, `reads_sensitive` and so on) to the session. |
| 9 metering | Books the cost of the call in the ledger. |

### The Rule of Two, and untrusted then external

Each tool carries tags in the config. A session keeps the tags of every tool it called, and an output that scores 0.85 or more taints it. Four default Cedar rules read that state ([policies/default/](policies/default/)):

| Session state | Tool being called | Result | Policy id |
|---|---|---|---|
| tainted | critical risk | deny | `deny-critical-when-tainted` |
| tainted | tagged `external_effect` | ask a person | `tainted-external-effect` |
| read untrusted and sensitive data | tagged `external_effect` | ask a person | `rule-of-two` |
| read untrusted data | tagged `external_effect` | ask a person | `untrusted-then-external-effect` |
| none of these | any | the access rules decide | |

More than one rule can match, and the approval card lists each that did.

I added the last rule after the red team. All 8 attacks that still landed read a web page and nothing sensitive, so the session had one of the two flags and `rule-of-two` never asked. I chose a rule over a lower taint threshold, because a threshold picked by looking at 8 attacks is tuned to those 8 ([ADR-0018](docs/adr/0018-untrusted-then-external.md)). With the rule, 0 of 48 landed. The cost: a session that reads a page or an inbox and then sends anything asks a person every time. A tenant can turn it off with `exclude_default_policies`.

```cedar
@id("untrusted-then-external-effect")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { resource.tags.contains("external_effect")
       && context.session_flags.contains("reads_untrusted") };
```

It is a `permit` because it lives in the approval set ([policies/default/approval/rule_of_two.cedar](policies/default/approval/rule_of_two.cedar)), where a match means "ask a person".

### Identity and credentials

Every request carries an OIDC access token (Keycloak locally), checked for `RS256` or `ES256`, issuer, audience and expiry, and its `tenant` claim limits the caller to that tenant's tools. The agent is the token's `azp` and must be listed in the config. Tool server keys are stored encrypted (Fernet) in Postgres and added to a call by the credential slot, so the agent never holds one ([runbook, Credentials](docs/runbook.md#credentials)).

### The audit chain

Every call, refused or not, writes exactly one row through a batched writer that stays off the call's path. Each row stores the sha256 of the previous row's hash plus its own canonical JSON, and `keystone audit verify` recomputes the chain and names the first row that does not match. Keystone's database role may only insert and read that table ([ADR-0009](docs/adr/0009-audit-chain.md)).

### What is enforced

Each invariant is a test in [tests/invariants/](tests/invariants/) that every phase gate runs.

| ID | Invariant |
|---|---|
| I1 | No call reaches a tool server without an `allow` decision recorded first |
| I2 | Every `tools/call`, refused or not, produces exactly one audit record |
| I3 | A canary secret never appears in logs, spans, audit rows, errors or tool results |
| I4 | A quarantined or disabled tool is never listed and never dispatched |
| I5 | A principal never lists or calls another tenant's tools |
| I6 | With no policies, every call is denied |
| I7 | A call that needs approval runs only with an approved, unexpired, unused approval for the same argument digest |
| I8 | A tainted session never dispatches a critical-risk tool |

## What it does not do

- **It does not stop every injection.** It limits what a session may do after it reads untrusted text. At a 5% false positive rate the detector finds 0.71 of injections offline and 0.66 with the gateway's 300 ms wait for the model ([detector](docs/results.md#detector)). It also wrongly flags every security article that quotes an attack (15 of 15) and a third of the instruction-like harmless texts (22 of 66).
- **It sees tool traffic only.** A model that leaks data in its reply to the user is out of reach.
- **Out of scope:** a signed-in user injecting their own agent, a compromised identity provider, side channels and timing attacks.
- **Untagged tools are invisible to the Rule of Two.** The v0.8.0 config left the files tools and `bank__list_transactions` untagged, and with it 29 of 48 attacks landed.
- **The approver in every measurement was an oracle.** A person who approves by habit gives the protection back. That is not measured.
- **Only the rules can taint a session**; the classifier can only flag. The model card says English only, and images are not scanned. The gateway waits 300 ms for the model and then scores by the rules alone, which happened to 12% of the scans of the test split.
- **Taint belongs to one MCP session.** A client that opens a new session starts clean.
- **The audit chain cannot see** the newest rows deleted, or a chain rewritten from the first row. Publishing the latest hash somewhere out of reach would close that, and it is not built.
- **Model requests through the LLM proxy** are budgeted and traced, but not rate limited, not checked by policy and not audited ([ADR-0016](docs/adr/0016-llm-proxy.md)).
- **The sandbox uses the Docker socket**, which gives Keystone root on the host. Local and single-host use only ([ADR-0012](docs/adr/0012-sandbox.md)).
- **Throughput is one process:** 88 calls a second with the scanner off at 200 sessions and 78 with one, and no high availability. MCP sessions live in the process, so a second worker is not a setting.
- **The classifier barely runs under load.** In the performance run the model scored none of the scans, and the rules decided them. The offline detector numbers above are for the model with all the time it needs.
- **A revoked credential can still be sent for up to 60 s** when it was changed through the CLI, because the gateway keeps an opened credential that long (`KEYSTONE_CREDENTIAL_CACHE_TTL_S=0` turns that off, [ADR-0019](docs/adr/0019-load-fixes.md)).
- **No real-model results yet.** M2 and the AgentDojo rows need an API key.

## Design decisions

Each decision that is costly to reverse has an ADR in [docs/adr/](docs/adr/) with the context and the trade-off.

| ADR | Decision |
|---|---|
| [0003](docs/adr/0003-python-and-the-low-level-server.md) | Python with the MCP low-level server. A Go gateway would likely add less overhead. I know Python better, and the policy, scanner and eval code is Python too. |
| [0006](docs/adr/0006-cedar.md) | Cedar in process through cedarpy: a typed schema rejects a misspelled attribute at load time, a decision is a function call, and an error denies. |
| [0007](docs/adr/0007-rejections-as-tool-results.md) | Refusals come back as tool results, because a JSON-RPC error often reaches the model as a failed turn with no reason. |
| [0009](docs/adr/0009-audit-chain.md) | A hash-chained audit log written in batches, so an edit shows and the writer stays off the call's path. |
| [0010](docs/adr/0010-approvals.md) | I bound an approval to the digest of the exact arguments, the tool, the session and the user, and it is used once. Otherwise an approval for one transfer could pay another that differs by a byte. |
| [0011](docs/adr/0011-scanner.md) | Rules first, a classifier behind them, and only the rules can taint a session. The classifier flags too many security articles to be trusted with that. |
| [0012](docs/adr/0012-sandbox.md) | One container per sandbox call, no network, read-only root, no capabilities. A test reads each flag back from a running container. |
| [0014](docs/adr/0014-redis-and-postgres.md) | Redis holds hot state and Postgres the record; budgets are rebuilt from the ledger, because a cap that a Redis restart clears is not a cap. |
| [0015](docs/adr/0015-session-merges.md) | A session changes only by merging, so a call held for approval cannot write back an older copy that drops a taint. |
| [0017](docs/adr/0017-redteam-baseline.md) | The red-team baseline is a profile of the same build, and the approver is an oracle. Whether an attack landed is read from the tool servers' state, not from what the agent says. |
| [0018](docs/adr/0018-untrusted-then-external.md) | A session that read untrusted text asks before any external effect. |
| [0019](docs/adr/0019-load-fixes.md) | What the performance run changed, and what it left alone. |

The other ADRs (tool naming, the console, the LLM proxy, dependency pins) are in [docs/adr/](docs/adr/).

## Repository layout

```
src/keystone/
  gateway/      MCP endpoint, the pipeline and its nine slots, dispatch
  registry/     tool sync, pinning, quarantine
  identity/     token checks, principals, credential vault
  policy/       Cedar adapter, loader, policy test runner
  approvals/    held calls, decisions, notifications
  defense/      rules, classifier, scanner, description check
  sandbox/      container runner
  metering/     rate limits, budgets, ledger, LLM proxy
  audit/        chain writer, verify, export
  admin/        admin API and the keystone CLI
  core/         contracts every slot builds against
policies/       Cedar schema, default rules, demo and per-tenant rules
console/        React console for approvers and admins (Vite, TypeScript)
deploy/         compose stack, Keycloak realm, Grafana, Prometheus, sandbox image, terraform/aws
examples/       demo tool servers, agents, injection fixtures, fake model API
eval/           red team, detector, performance, AgentDojo; results/ holds the raw files
scripts/        smoke scripts per phase, demo_attack.sh, get_token.sh, redteam.sh
tests/          unit, integration, invariants, e2e, policy_cases
docs/           runbook, policies, results, progress, ADRs, gate reports, the plan
site/           the project page
```

## Development

Setup, branch rules and how to add a tool server, a policy or an ADR are in [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
make setup            # uv sync and the pre-commit hook
make check            # starts Postgres and Redis, then lint, mypy, unit, integration, console checks
make gate PHASE=9     # everything the phase 9 gate runs, against the full stack
make help             # every target
```

The last full gate on `dev` ran 3,170 Python tests, 62 policy cases, 180 console unit tests and 2 browser tests in 27 minutes, with no failures ([docs/progress.md](docs/progress.md)). Each test carries a `phase(n)` marker, and I never skipped or loosened a test to get a build green.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs on every push:

| Job | What it runs |
|---|---|
| `lint-type` | ruff check, ruff format, mypy (strict on core, gateway, policy and audit) |
| `unit` | unit tests and invariants that need no services |
| `policy` | `keystone policy test --coverage`: every case, and every policy matched by one |
| `integration` | tests against Postgres, Redis and Docker, sandbox included |
| `console` | generated API types match the API, ESLint, Prettier, tsc, Vitest, build |
| `security` | gitleaks over the full history, pip-audit |
| `docker` | the image builds and starts |
| `commits` | commit subjects follow the convention |
| `terraform` | fmt, validate and tflint when `deploy/terraform` changes |
| `docs` | the prose rules (`scripts/lint_prose.py`) |

A nightly workflow starts the stack and runs the end-to-end tests, the console browser tests, a short performance run and a detector run.

How a change flows:

1. Branch from `dev` (`feat/ks-203-tool-sync`, `fix/...`, `docs/...`).
2. Push. CI must be green on the branch tip.
3. Merge into `dev` with `--no-ff`, push `dev`, delete the branch.
4. At the end of a phase, `make gate PHASE=N` passes, its report goes in [docs/gates/](docs/gates/), and `dev` is merged into `main` and tagged.

## Deploying

**One host, Docker Compose.** [deploy/docker-compose.yml](deploy/docker-compose.yml) is the stack `make up` starts. Its secrets are development values, and nothing in it should be reachable from beyond the machine. To run it against your own tools, put your own values in `.env`, list your tool servers in `deploy/keystone.compose.yaml`, and follow [docs/runbook.md](docs/runbook.md). The console has no production image yet and runs on Vite's dev server.

**AWS, Terraform.** [deploy/terraform/aws/](deploy/terraform/aws/) creates a VPC over 2 availability zones, an ALB, ECS Fargate, RDS Postgres 16, ElastiCache Redis 7, Secrets Manager secrets, CloudWatch logs and an optional Cognito pool. From list prices it costs about $4.30 a day, so run `terraform destroy` after a demo. The sandbox is off there (`KEYSTONE_SANDBOX_ENABLED=false`), because a Fargate task has no Docker socket. CI checks the module with fmt, validate and tflint. It has not been applied: I have no AWS credentials on this machine. `make tf-plan` plans it with the example variables.

Operating it: [docs/runbook.md](docs/runbook.md) (start, stop, every setting and port, credentials, policies, approvals, audit, troubleshooting) and [docs/policies.md](docs/policies.md) (writing and testing policies).

## Status and roadmap

I built Keystone one phase at a time. Each phase ended with a gate report and a tag on `main`.

| Phase | Tag | Gate |
|---|---|---|
| 0 Foundation: repository, CI, local stack | v0.0.1 | [phase-0](docs/gates/phase-0.md) |
| 1 MCP proxy core and the fixed pipeline | v0.1.0 | [phase-1](docs/gates/phase-1.md) |
| 2 Registry, several tool servers, pinning | v0.2.0 | [phase-2](docs/gates/phase-2.md) |
| 3 Identity, tenants, credential vault | v0.3.0 | [phase-3](docs/gates/phase-3.md) |
| 4 Cedar policy engine | v0.4.0 | [phase-4](docs/gates/phase-4.md) |
| 5 Audit chain, traces, metrics | v0.5.0 | [phase-5](docs/gates/phase-5.md) |
| 6 Approvals and the console | v0.6.0 | [phase-6](docs/gates/phase-6.md) |
| 7 Injection defense and the Rule of Two | v0.7.0 | [phase-7](docs/gates/phase-7.md) |
| 8 Sandbox, rate limits, budgets, LLM proxy | v0.8.0 | [phase-8](docs/gates/phase-8.md) |
| 9 Proof and release | v1.0.0, not released | |

Phase 9 so far: the red team, the detector join, the performance harness and the load fixes, the AgentDojo adapter, the untrusted-then-external rule and the Terraform module are done. Still open: a hardening pass with fuzz tests (KS-906), the fresh-clone check (KS-907) and the release (KS-908). The changes by release are in [CHANGELOG.md](CHANGELOG.md), and status per story in [docs/progress.md](docs/progress.md).

After v1:

- A2A proxying, with policy on `message/send`
- OpenAPI to MCP conversion for internal REST APIs
- Data loss checks on arguments, with custom classifiers
- Policy simulation: replay 7 days of audit rows against a proposed policy
- An egress allowlist for sandbox containers
- A Helm chart

## License and author

MIT, see [LICENSE](LICENSE). Written by Hooman Esteki.
