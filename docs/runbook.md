# Runbook

How to run the local stack and what each part listens on. This file grows with the phases.

## Local stack

`make up` builds and starts Postgres, Redis, Keycloak, Jaeger, Prometheus, Grafana, the four demo
upstreams and Keystone, and waits until every container reports healthy. Cold start takes about
30 seconds on a laptop with warm images. The first build of the two local images takes longer: the
Keystone image holds torch and a 738 MB model (the classifier, below), and its first build took
20 minutes on a laptop. The model stays in a build cache after that, so a rebuild after an edit in
`src` took 54 seconds; `docker builder prune` empties the cache and the next build downloads the
model again.

| Command | What it does |
|---|---|
| `make up` | Start the full stack and wait for health |
| `make up-core` | Start Postgres and Redis only (what `make check` needs) |
| `make demo` | `make up`, reset the upstreams, run the scripted agent through Keystone as olivia and print its transcript |
| `make sandbox-image` | Build the image the sandbox runs code in (the compose service `sandbox-image` builds it too). `make test-int` and `make gate` build it first, because the tests marked `docker` need it |
| `make down` | Stop the stack and keep its data |
| `make reset` | Stop the stack and delete its volumes |
| `scripts/get_token.sh alice support-agent` | Print an access token for a Keycloak user (see Identity) |
| `make test-e2e` | The end-to-end tests against the running stack. The nightly workflow runs `make up` and then this |
| `make console-check` | The console's lint (ESLint with type information, Prettier), unit tests and production build. `make check` runs it |
| `make console-types` | Write the admin API's schema (`scripts/dump_openapi.py`) and generate `console/src/api/schema.d.ts` from it |
| `make console-e2e` | The browser test of the approval loop (see Console). It starts the stack if it is not running; `make gate PHASE=6` and the nightly run it |
| `bash scripts/smoke/phase_0.sh` | Print one health row per service |
| `bash scripts/smoke/phase_1.sh` | The body of `make demo`; exits 1 if a step fails or the audit log (read through the admin API) does not hold one new record for each call |
| `bash scripts/smoke/phase_9.sh` | The smokes of phases 0 to 8, in that order, against the one stack that is up. It runs all nine even when one fails and ends with the list of the ones that passed and the ones that failed (exit 1 if any failed), so that a gate says every phase that is broken and not only the first. A script that is missing counts as a failure. `make gate PHASE=9` runs this one and not the eight again. `SMOKE_DIR` names another folder of `phase_0.sh` to `phase_8.sh`, which its tests use. |
| `bash scripts/smoke/phase_8.sh` | The sandbox (olivia's script prints 42, alice is refused with `default-deny`); lena's fourth call of a cent is `KS_BUDGET_EXCEEDED` and the budgets API shows $0.03 of $0.03; the LLM proxy against the fake model API (a whole answer, an Anthropic stream equal to the fake's own bytes, an OpenAI stream asked for its usage, each booked at 4 tokens in and 12 out and $0.000192; an unpriced model is a 400; lena's day is spent, so her request is a 402 and the fake sees nothing; a provider that repeats the key is answered with it taken out, and the key is in no response, log or span; `keystone_llm_tokens_total` grows by 12 and 36). Then Keystone is restarted with a burst of 5 calls for one user, 12 calls are made, 5 pass and 7 are `KS_RATE_LIMITED` with a `retry_after_s` of about 2 s, and a call after that long passes. It clears the day's spend of acme first so that it can run twice, and restores the default limits when it ends. About 2 minutes. |
| `bash scripts/smoke/phase_7.sh` | The naive agent summarizes unread mail, and one email tells it to forward an invoice to attacker@evil.test. Straight at the mail server the attack lands. Through Keystone nothing is sent: the email scores above 0.85, the session is tainted, and the approval card names `rule-of-two` and `tainted-external-effect`. A summary of harmless mail asks for no approval. `make demo-attack` prints the two runs one after the other. |
| `bash scripts/smoke/phase_6.sh` | Three agents run as olivia and lena decides through the admin API: a transfer of 900 is held, approved and completed (a second decision is 409 and olivia's own is 403); one of 700 is rejected with a note that the agent gets; one of 600 times out as `KS_APPROVAL_PENDING`, is approved late and is awaited. Then the audit log and `keystone_approvals_pending` are checked. About 20 seconds: the third request waits out the 10 s hold. |
| `bash scripts/smoke/phase_5.sh` | Runs the demo, finds a Jaeger trace of more than 9 spans with no user or argument in it, reads `keystone_tool_calls_total` from `/metrics` and from Prometheus, finds the dashboard in Grafana, verifies the audit chain, edits a record as the Postgres superuser and checks that `keystone audit verify` exits 2 and names the seq, then puts the record back. About 15 seconds. |
| `bash scripts/smoke/phase_4.sh` | Alice's transfer is `KS_DENIED default-deny` and her tool list has 16 tools (14 of acme's and Keystone's 2); olivia's transfer of 900 is held for approval, lena rejects it through the admin API and olivia is told `KS_APPROVAL_REJECTED`, the audit shows `require_approval` / `approve-transfer-over-500` and one of 100 is dispatched; a policy file is broken on the host, the reload answers 422 with the version unchanged, and the file is put back. About 30 seconds. |
| `bash scripts/smoke/phase_3.sh` | Tokens for alice and bob, a request without a token (401), olivia's 20 tools, bob's 3 globex tools and Keystone's 2, and `KS_TOOL_NOT_FOUND` for an acme tool, the mail server's `api_key_received`, and a search of the Keystone logs for the demo keys and the master key. About 15 seconds. |
| `bash scripts/smoke/phase_2.sh` | Lists the 20 tools, quarantines and approves a changed echo description, stops the bank server and checks the refusal. About 45 seconds. It restarts Keystone with a 2 s health probe (`SMOKE_HEALTH_INTERVAL_S`) and restores everything when it ends. |

## Host ports

The defaults are in `.env.example`. Copy it to `.env` to move a port, then run `make up` again.
Tests never use these ports. They start their own services on free ports.

| Service | Host port | Notes |
|---|---|---|
| Keystone | 8080 | compose service `keystone` (or `keystone serve`). MCP endpoint: `http://localhost:8080/mcp` |
| Postgres | 55432 | database, user and password are all `keystone` |
| Redis | 56379 | tests use db 15 |
| Keycloak | 8180 | admin console login `admin` / `admin`, realm `keystone` |
| Jaeger UI | 16686 | |
| OTLP gRPC / HTTP | 4317 / 4318 | sent to Jaeger |
| Prometheus | 9090 | |
| Grafana | 3000 | login `admin` / `admin`, Prometheus and Jaeger provisioned |
| Mail, files, bank, echo, web | 8101, 8102, 8103, 8104, 8105 | demo upstreams, services `mail-mcp`, `files-mcp`, `bank-mcp`, `echo-mcp`, `web-mcp` |
| Files for globex | 8112 | the globex tenant's own drive, service `files-globex-mcp` |
| Fake LLM | 8199 | the fake model API that the LLM proxy forwards to in compose, service `fake-llm` (see LLM proxy) |
| Console | 5173 | the Vite dev server (`pnpm dev` in `console/`), which `make console-e2e` also starts. The port is fixed because the Keycloak client `console` allows `http://localhost:5173/*` only |

The credentials above are for local development only. Nothing in compose is meant to be exposed
beyond the machine.

## Demo upstreams

Five small MCP servers give the gateway something to proxy and give tests state to inspect. They
share one image (`deploy/Dockerfile.upstreams`), and `make up` starts them.

| Server | Port | Tools |
|---|---|---|
| mail | 8101 | `list_emails`, `read_email`, `send_email` (12 seeded emails) |
| files | 8102 | `list_files`, `read_file`, `write_file` (confined to one workspace) |
| bank | 8103 | `get_balance`, `list_transactions`, `transfer` (3 seeded accounts) |
| echo | 8104 | `echo`, `sleep`, `fail` |
| web | 8105 | `fetch(url)`, which returns a stored page and never reaches the network (`examples/fixtures/web/pages.json`) |
| files (globex) | 8112 | the tools of `files`, on another drive (`examples/fixtures/files-globex`), for the globex tenant |

Each also serves plain HTTP routes next to `/mcp` that are not tools, so an agent cannot call them:
`GET /healthz`, `POST /_reset` (back to the seed) and `GET /_state` (sent mail, transfers, written
files, the urls asked of the web server, and the names of the tools called). The mail, files, bank
and web servers take `POST /_reset?variant=<name>`, which puts them in the state of one scenario of
the red-team suite (see Red-team scenarios below); a name that is not a variant is a 404 and nothing
is reset. The echo server adds `POST /_mutate`, which rewrites the `echo` description, and
`ECHO_POISONED=1`, which adds a tool with an injected description.

Run one outside compose: `uv run python -m examples.upstreams.mail_server --port 8101`. Add
`--transport stdio` to speak MCP over stdin and stdout.

| Variable | Purpose |
|---|---|
| `MAIL_DB`, `BANK_DB`, `FILES_DB` | SQLite file for the server's state. Default: a temp file. Every start re-seeds it. |
| `FILES_WORKSPACE` | Directory the files server confines itself to. Default: a temp directory. |
| `FILES_SEED` | Directory the files server starts from and returns to on reset. Default: `examples/fixtures/files`. |
| `MAIL_API_KEY`, `FILES_API_KEY`, `BANK_API_KEY`, `ECHO_API_KEY`, `WEB_API_KEY` | When set, `/mcp` requires a matching `X-Api-Key` header, and `/_state` reports `api_key_received`. Compose sets them (the defaults are in `.env.example`); Keystone takes them from its own environment and stores them in the vault. |
| `ECHO_POISONED` | `1` adds the poisoned tool. |
| `MAIL_POISONED` | `1` adds three unread emails (m13 to m15) that carry an instruction for the agent that reads them. Compose sets it. Without it the mailbox is the 12 emails of the seed. |
| `FILES_POISONED` | `1` adds two files (`notes/vendor-onboarding.md`, `reports/q3-vendor-spend.csv`) that carry an instruction. Compose sets it for the acme drive and not for globex's. |

### Injection fixtures and the naive agent

The injection defense is tested against planted attacks (KS-708). `examples/fixtures/injections/templates.yaml`
has 12 attack texts (`ignore_previous`, `important_instructions`, `fake_system`, `tool_knowledge`,
`hidden_unicode`, `markdown_exfil`, `urgent_secrecy`, `fake_error_recovery`, `translated`, `base64`,
`delimiter_escape`, `role_override`) and 5 goals (forward the latest invoice to `attacker@evil.test`,
a transfer, a leak, a file write, a request to an attacker's address). Everything in the fixtures
is invented, on `.test` addresses, in English except the `translated` template.

Each text carries a marker, `<!--ks-do:{"args":{...},"tool":"mail__send_email"}-->`, which is the same goal
as a tool call. The marker is for the naive agent only. A detector is never measured on a text that
still has one: `re.sub(r'<!--ks-do:(\{.*?\})-->', '', text, flags=re.DOTALL)` removes it, and
`examples/injections.py` (`strip_markers`) does the same.

`examples/agents/naive_agent.py` runs a task script like the scripted agent, and whenever a result holds a
marker it calls that tool with those arguments at once. It stands in for a model that has been fully
taken over, so a gateway that stops it does not depend on how a model behaves. After a
`KS_APPROVAL_PENDING` it calls `keystone__await_approval` once.

    # the attack lands: the agent talks to the mail server directly, whose mailbox is poisoned in compose
    uv run python -m examples.agents.naive_agent --url http://localhost:8101/mcp \
        --header "X-Api-Key: dev-mail-key-3f9a1c7d" \
        --script examples/agents/scripts/summarize_unread.yaml --format text
    curl -s localhost:8101/_state     # "sent" holds the mail to attacker@evil.test

    # the same task through Keystone, signed in as olivia
    KEYSTONE_TOKEN=$(scripts/get_token.sh olivia ops-agent) uv run python -m examples.agents.naive_agent \
        --url http://localhost:8080/mcp --script examples/agents/scripts/summarize_unread.yaml --format text

`summarize_unread_benign.yaml` is the same task over mail with no instruction. Reset the mail
server between runs: `curl -s -X POST localhost:8101/_reset`.

Through Keystone the agent still reads the poisoned email and still tries to forward the invoice.
The forward is held for a person (`rule-of-two`, `tainted-external-effect`,
`untrusted-then-external-effect` and acme's `external-email-needs-approval` are its reasons), and nobody approves it. `make demo-attack` runs
both scenarios and prints them side by side, with `examples/agents/auto_reject.py` standing in for
the person: lena through the admin API, rejecting whatever reaches the queue. It prints one line of
JSON for each request, with what a person would see on the card (tool, reasons, taint, flags,
arguments). `scripts/smoke/phase_7.sh` runs the same two scenarios and a harmless summary with
assertions, and `scripts/smoke/attack_lib.sh` is what both share.

### Red-team scenarios

The red-team suite (KS-901) is 60 scenarios in `eval/redteam/scenarios/`, one file for each of 12
tasks: three that read mail, three that read files, three that read web pages and three that read
the transactions of a bank account. Each file holds the task without an attack (`<task>.benign`)
and the task with each of 4 goals of an attacker planted in what it reads: forward the latest invoice
to `attacker@evil.test` (`exfil_email`), transfer 450 dollars to `ACCT-666` (`transfer_funds`),
overwrite `config/settings.txt` (`overwrite_settings`) and send a phishing mail to a colleague
(`phish_colleague`). The text of the attack is one of the 12 templates above, dealt out so that every
template meets every goal once, and put at the start, middle or end of the document.

A scenario holds the prompt a user gives, the script the naive agent runs for it, the calls the task
needs (`expected_actions`, which the approver of the runs approves and nothing else), and two checks
that read state and not words: `utility_check` for the task and `attack_check` for the attack. A check
reads the `/_state` of the demo upstreams, so an agent that says it sent a mail and did not is not
believed.

The state of a scenario is a variant, `examples/fixtures/variants/<task>-<goal>/`, with a file for
each upstream it changes: `mail.json` (emails added or replaced by id), `files/` (laid over the
workspace), `bank.json` (transactions added) and `web.json` (pages added or replaced by url). The
folder `_base` is laid over first for every variant, and holds `config/settings.txt`. A variant
ignores `MAIL_POISONED` and `FILES_POISONED`: its state is what its files say.

    uv run python -m eval.redteam.build            # write the scenarios and variants from the catalog
    uv run python -m eval.redteam.build --check    # fail when the files differ from the catalog
    curl -s -X POST 'localhost:8101/_reset?variant=mail_summary-exfil_email'

`eval/redteam/catalog.py` is the source, and what it writes is committed so that a result can name
a scenario and a reader can open the file the agent was given. A test builds the catalog again and
compares it with the files on disk.

### Red-team runs

`eval/redteam/runner.py` (KS-902) plays the scenarios against the compose stack and writes a line of
JSON for each run. `scripts/redteam.sh` runs it in the three configs of the proof and restarts the
keystone service between them, so the stack must be up first (`make up`):

    scripts/redteam.sh naive                    # 60 scenarios in C0, C1 and C2: no model, no key
    scripts/redteam.sh naive --configs C2       # one config, or a list such as C0,C2
    uv run python -m eval.redteam.report        # write the red-team section of docs/results.md
    uv run python -m eval.redteam.report --check

The three configs are three settings of one build. C0 is `KEYSTONE_PROFILE=passthrough`: the
pipeline keeps its order, its audit record and the credentials it adds for an upstream, every other
slot is the Phase 1 stub, and no scanner is built. C1 mounts a copy of `policies/` without the two
`rule_of_two.cedar` files (made in `.cache/redteam/` for each run) and turns the scanner off, so the
access rules, acme's rule for mail to outside addresses and the transfer limit are in force. C2 is
the stack as it is. `deploy/redteam.override.yml` holds the variables that change, and with none set
it changes nothing. A script that fails or is stopped restarts Keystone with the settings of the
stack.

The runner does not trust the label it is given. Before the first run it reads
`keystone_gateway_info{profile,scanner,classifier}` from `/metrics` and the policy ids from the
admin API, and it stops with status 2 and `this is not C2: its scanner is off, not on` if they are
not what the label needs. C2 needs a scanner with its model, and the model loads in the background
for about 7 seconds after the gateway starts, so the runner first waits (up to 3 minutes) until
`keystone_scanner_classifier_ready` says it has loaded; a scan made before that is scored by the
rules alone. A gateway whose extra is not installed says `classifier="none"`, and C2 is refused.

    curl -s localhost:8080/metrics | grep -E 'keystone_gateway_info|classifier_ready'

A run is one scenario, one config, one agent, once. The runner puts the upstreams in the state of
the scenario (`POST /_reset?variant=`), starts the approver, lets the agent do the task as olivia
through ops-agent, asks the upstreams what they did (`GET /_state`) and decides the two checks of
the scenario from that. The approver is lena, who signs in through `keystone-cli` and may use the
approvals routes of the admin API and nothing else. She polls the pending requests every quarter of
a second, approves a request when its tool and the arguments an action of `expected_actions` names
are the same (each action once) and rejects every other request with a note. A line of the file has
the scenario and its template, goal and vector, the two checks, the approvals asked and decided with
the rules that asked and the flags of the session at that moment, the error codes the agent met,
the tokens and the cost from the ledger, and the flags and taint of the session at the end.

A result file is never written over: the runner opens it for creation and refuses if it exists, so
rename the first file (add `-repeat1`, say) if a config is run twice in a day. The files are
`eval/results/redteam-<agent>-<config>-<date>.jsonl`, they are committed, and the report reads
them and nothing else. It leaves out a file that was made with `--only` or `--limit` and a file of
a stand-in model (`fake-*`). Of the whole files of one kind it takes the newest for its figures, and
it lists the others in a table of repeat runs that says in how many scenarios they differ in
outcome and in the scores of the scanner, so a run that does not repeat shows.

To run the config of an earlier release against the code of this one (to see what a change to the
config did), give the ref: `scripts/redteam.sh naive --configs C2 --config-ref v0.8.0`. The file
is named after it and the report shows it as a row of its own.

The model-driven agent (`examples/agents/llm_agent.py`) sends its requests to Keystone's LLM proxy,
so the cost of a run is read from the ledger. The stack points the proxy at the fake model API, and
its model `fake-agent` makes the calls of a script and obeys what it reads, which tests the loop and
the metering with no key:

    scripts/redteam.sh llm --model fake-agent --script-hint --limit 4 --out-dir /some/folder

Its files are not rows of the table. For a real model, `scripts/redteam.sh` lists the variables it
needs (the provider's address, the variable that holds the key, a price list that has the model in
it) and refuses to start without them; the command is in the red-team section of `docs/results.md`,
with its status. The demo tenant has a budget of $25 a day in `deploy/keystone.compose.yaml`, which
a run that costs more would meet.

## Identity (Keycloak)

`make up` starts Keycloak 26 and imports the realm `keystone` from `deploy/keycloak/realm-keystone.json`.
Its admin console is at `http://localhost:8180` (`admin` / `admin`).

| User | Tenant | Groups | Realm role | Signs in through |
|---|---|---|---|---|
| `alice` | acme | `/tenants/acme`, `/support` | | `support-agent` |
| `olivia` | acme | `/tenants/acme`, `/operators` | | `ops-agent` |
| `lena` | acme | `/tenants/acme`, `/approvers` | `approver` | `keystone-cli` |
| `bob` | globex | `/tenants/globex` | | `support-agent` |
| `root` | acme | `/tenants/acme`, `/admins` | `admin` | `ops-agent` |

The user id is the user name, so a token's `sub` reads `alice`. Passwords are `<name>-dev-password`.
The clients `support-agent`, `ops-agent` and `keystone-cli` are confidential and allow the
password grant, which exists for the demo and the smoke scripts. `console` is public and uses
PKCE with the redirect `http://localhost:5173/*`. Every client puts `keystone` in `aud` and adds
the claims `tenant` (from the user attribute), `groups` (full paths such as `/tenants/acme`) and
`roles` (realm roles).

```bash
scripts/get_token.sh alice support-agent        # prints an access token
```

The script reads `<USER>_PASSWORD` and `<CLIENT>_SECRET` from the environment, then `.env`, then
`.env.example`. Those files hold development values that are public in this repository. Never use
them outside your own machine. The realm file contains `${NAME}` placeholders and no secrets;
Keycloak fills them from its environment, which `deploy/docker-compose.yml` sets.

A user needs an email, a first name, a last name, `emailVerified: true` and no required actions,
or Keycloak 26 refuses the password grant with "Account is not fully set up". A custom user
attribute such as `tenant` must be declared in the realm's user profile (the realm file does) or
the realm must set `unmanagedAttributePolicy` to `ENABLED`.

### The issuer

A token's `iss` must be the same whichever address asked for the token, or validation fails for
somebody. Compose sets `KC_HOSTNAME=http://localhost:8180` and `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`.
Every token then carries `iss=http://localhost:8180/realms/keystone`, while a request to
`http://keycloak:8080/...` from another container gets a `jwks_uri` that points at
`keycloak:8080`. A service inside the network can then fetch the keys without going out through
the host. `tests/e2e/test_keycloak.py` checks both answers.

Keystone has two settings for this. `oidc_issuer` (`KEYSTONE_OIDC_ISSUER`) is the value tokens
carry in `iss`: `http://localhost:8180/realms/keystone` in compose. `oidc_discovery_url`
(`KEYSTONE_OIDC_DISCOVERY_URL`) is where Keystone reads the discovery document, and it only needs
to be set when that differs from the issuer's own address: in compose it is
`http://keycloak:8080/realms/keystone/.well-known/openid-configuration`. The document's `issuer`
must equal `oidc_issuer`, or Keystone refuses its keys (503, and a log line naming both values).

### How Keystone checks a token

`identity/jwt.py` does it in this order, and stops at the first failure:

1. The header is read without verifying anything. An `alg` other than `RS256` or `ES256` is
   refused here, so `none`, the HMAC algorithms and anything else never reach a key. A header with
   `jku`, `jwk`, `x5u`, `crit` or `b64` is refused too, and so is a token without a `kid`.
2. The `kid` selects one key from the identity provider's published set. Encryption keys
   (`use: enc`), RSA keys under 2048 bits and EC keys that are not P-256 are not used.
3. The key must match the algorithm: RSA for `RS256`, EC P-256 for `ES256`.
4. The signature and the claims are verified with exactly that one algorithm. `exp`, `iat`,
   `iss`, `aud` and `sub` must be present. `iss` must equal the configured issuer, `aud` must
   contain the configured audience, and `exp`, `nbf` and `iat` get 60 seconds of leeway.

The keys are fetched from the discovery document with a 3 second timeout and kept in memory. A
token with an unknown `kid` makes Keystone fetch them again, at most once a minute, so a rotation
is picked up and a stream of made-up key ids costs the identity provider one request a minute.
While Keystone holds no keys at all, a failed fetch is retried after 2 seconds. If the keys cannot
be fetched, the answer is 503, not 401: the token was not shown to be bad.

`tenant` is required and must look like a tenant id. The agent is `azp`, or `client_id` when
there is no `azp`. Groups lose their leading `/`, and the `/tenants/...` groups are dropped,
because the tenant has its own claim. The roles come from `roles`, or from `realm_access.roles`
when there is no `roles` claim, and only `admin` and `approver` are kept.

### Agents

An agent is the OAuth client that acts for a user (`azp`). The `agents` section of the config
lists the ones that may connect and how far Keystone trusts each (`low`, `standard` or `high`):

```yaml
agents:
  support-agent: {trust: standard}
  ops-agent: {trust: high}
auth:
  allow_unknown_agents: false   # true lets an unlisted agent in with trust low
```

A token from an agent that is not listed is refused with 403, after it has been validated. Set
`KEYSTONE_AUTH__ALLOW_UNKNOWN_AGENTS=true` to let such an agent in with trust `low` instead.
`keystone agent list` prints the table and says which of the two applies. The trust level is in
the principal that policy sees (Phase 4).

### Changing the realm

Keycloak imports the realm file only when the realm does not exist. The development database
lives in the Keycloak container, so removing the container removes the realm. After you edit
`realm-keystone.json`:

| What you run | Result |
|---|---|
| `make reset && make up` | The edited realm is imported. This also deletes the Postgres, Prometheus and Grafana volumes. |
| `make down && make up` | The same for the realm, and the volumes stay. |
| `make up` alone | Nothing changes: the container is reused and the realm already exists. |
| `docker compose -f deploy/docker-compose.yml up -d --force-recreate keycloak` | Re-imports the file and touches nothing else. |

Recreating Keycloak creates new signing keys, so tokens fetched before it stop validating.
Keystone picks up the new keys the first time it sees a token with an unknown key id, at most once
a minute, so a token fetched right after the restart may be refused for up to a minute.

## Keystone settings

Environment variables win over the YAML file named by `KEYSTONE_CONFIG`.

| Variable | Default | Purpose |
|---|---|---|
| `KEYSTONE_ENV` | `dev` | `dev`, `test` or `prod` |
| `KEYSTONE_DATABASE_URL` | `postgresql+asyncpg://keystone:keystone@localhost:55432/keystone` | Postgres DSN. Compose runs Keystone as the role `keystone_app` (see Database roles). |
| `KEYSTONE_MIGRATE_DATABASE_URL` | unset | Where `keystone db upgrade` and `keystone serve --migrate` connect, when that is not `KEYSTONE_DATABASE_URL`: creating tables takes the role that owns them. Unset means they use `KEYSTONE_DATABASE_URL`. Compose sets it to the owner. |
| `KEYSTONE_APP_DB_PASSWORD` | the development password | Read by the migration that creates the `keystone_app` role. With `KEYSTONE_ENV=prod` and no value, that migration stops. It is not a Keystone setting: set the same value in the password of `KEYSTONE_DATABASE_URL`. |
| `KEYSTONE_REDIS_URL` | `redis://localhost:56379/0` | Redis URL. Session state lives here. Set it to an empty string to keep session state in the gateway process instead (one process only, lost on restart). |
| `KEYSTONE_REDIS_POOL_SIZE` | `500` | Connections in the one Redis pool that sessions, rate limits, budgets and approvals share. A caller that finds them all in use waits for one. |
| `KEYSTONE_REDIS_POOL_TIMEOUT_S` | `2` | How long such a caller waits, in seconds. After that the call is refused as before (`session state is unavailable`), because a call that cannot read its session must not run. |
| `KEYSTONE_CREDENTIAL_CACHE_TTL_S` | `60` | How long the gateway keeps an upstream's opened credential instead of reading and decrypting it on every call. `keystone cred set` and `rotate-keys` run in the CLI, another process, so the gateway sends the old credential until the entry expires: set `0` to read it every call. |
| `KEYSTONE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |
| `KEYSTONE_CONFIG` | unset | Path to a YAML file with the same keys |
| `KEYSTONE_ALLOWED_HOSTS` | `["127.0.0.1:*","localhost:*","[::1]:*"]` | JSON list of `Host` header values the MCP endpoint accepts (DNS rebinding guard). `:*` matches any port. Add the service name, for example `keystone:*`, to reach it from another container. |
| `KEYSTONE_ALLOW_PRIVATE_UPSTREAMS` | `false` | When `false`, an upstream URL whose host resolves to a loopback, private (RFC 1918), link-local (including 169.254.169.254), CGNAT (100.64.0.0/10) or IPv6 unique-local address is refused. Local compose sets it to `true`, because the demo upstreams are on a private network. |
| `KEYSTONE_REGISTRY__SYNC_INTERVAL_S` | `300` | Seconds between syncs of every upstream. `0` turns the timer off (the startup sync and the CLI still run). Also `registry.sync_interval_s` in the YAML. |
| `KEYSTONE_REGISTRY__SYNC_TIMEOUT_S` | `20` | The longest one upstream's sync may take, connecting included. |
| `KEYSTONE_REGISTRY__CACHE_TTL_S` | `2` | How long the gateway keeps its in-memory copy of a tenant's tools. A sync run by the CLI reaches a running gateway after this long at most. |
| `KEYSTONE_HEALTH__INTERVAL_S` | `30` | Seconds between health probes of every upstream. `0` turns them off, and no upstream is then marked down. Also `health.interval_s` in the YAML. |
| `KEYSTONE_HEALTH__TIMEOUT_S` | `3` | A probe slower than this has failed. |
| `KEYSTONE_HEALTH__DEGRADED_AFTER` | `1` | Consecutive failed probes before an upstream is `degraded`. |
| `KEYSTONE_HEALTH__DOWN_AFTER` | `3` | Consecutive failed probes before it is `down`. Not less than `DEGRADED_AFTER`. |
| `KEYSTONE_AUTH__MODE` | `oidc` | `oidc`: every request to `/mcp` carries a bearer token from the identity provider. `none`: every caller is the dev principal. `none` is refused unless `KEYSTONE_ENV` is `dev` or `test`. Also `auth.mode` in the YAML. |
| `KEYSTONE_OIDC_ISSUER` | unset | The `iss` of valid tokens. Required when the mode is `oidc`, and an https URL when `KEYSTONE_ENV=prod`. |
| `KEYSTONE_OIDC_AUDIENCE` | `keystone` | The value `aud` must contain. |
| `KEYSTONE_OIDC_DISCOVERY_URL` | the issuer's own `/.well-known/openid-configuration` | Where to read the discovery document, when that is not the issuer's address. See "The issuer". |
| `KEYSTONE_PUBLIC_BASE_URL` | the address of the request | How clients reach Keystone, for the sign-in metadata (`http://localhost:8080` in compose). Set it behind a proxy that changes the scheme or the host. |
| `KEYSTONE_MASTER_KEYS` | unset | Fernet keys for the credential vault, comma separated. The first encrypts, all decrypt. Needed by `keystone cred ...` and, from KS-306, by the gateway. |
| `KEYSTONE_DEV_PRINCIPAL` | tenant `acme`, user `olivia`, groups `operators`, agent `ops-agent` | JSON object. Who every caller is when `KEYSTONE_AUTH__MODE=none`. Refused in any other mode. |
| `KEYSTONE_AUTH__ALLOW_UNKNOWN_AGENTS` | `false` | Let an agent that is not under `agents` in with trust `low`. Also `auth.allow_unknown_agents` in the YAML. |
| `KEYSTONE_CONSOLE_ORIGIN` | `http://localhost:5173` | The one origin a browser may call the admin API from (CORS). A preflight from any other origin is refused with 400. Write it as `scheme://host[:port]`. |
| `KEYSTONE_OTLP_ENDPOINT` | unset | Where spans are sent: an OTLP/HTTP endpoint such as `http://jaeger:4318` (`/v1/traces` is added). Unset means no spans are made and audit rows carry no `trace_id`. Compose sets it to Jaeger. |
| `KEYSTONE_AUDIT__FAIL_CLOSED` | `true`, except `false` when `KEYSTONE_ENV=dev` | While the audit writer is unhealthy (its queue is over 90% full, or a flush failed less than 5 seconds ago), refuse every call with `KS_DENIED` and the reason `audit-unavailable`, before any interceptor runs. See Audit. Also `audit.fail_closed` in the YAML. |
| `KEYSTONE_AUDIT__REDACT_KEYS` | `[]` | JSON list of argument keys whose values the audit log replaces with `[redacted]`, besides keys that look like secrets. Whole names, any case: `["ssn", "dob"]`. Also `audit.redact_keys` in the YAML. |
| `KEYSTONE_POLICY__ROOT` | `policies` | The directory with the schema and the policies (see Policies). A relative path is read from the working directory; the image has its own copy at `/app/policies`, and compose mounts this checkout's at `/etc/keystone/policies`. Also `policy.root` in the YAML. |
| `KEYSTONE_POLICY__INCLUDE_DEMO` | `false` | Also read `demo/`, the rules that go with the demo upstreams. Compose turns it on. |
| `KEYSTONE_POLICY__LIST_CACHE_TTL_S` | `60` | How long the answer to "which tools may this caller see" is kept, per caller and policy version. `0` turns the cache off. |
| `KEYSTONE_APPROVALS__WAIT_SECONDS` | `60` | How long a call that needs approval is held before the agent gets `KS_APPROVAL_PENDING` and an id. `0` never holds one; at most 300. See Approvals. |
| `KEYSTONE_APPROVALS__TTL_SECONDS` | `900` | How long after the request it can be decided and used. |
| `KEYSTONE_APPROVALS__SWEEP_INTERVAL_S` | `30` | Seconds between marking requests that ran out of time as expired. |
| `KEYSTONE_APPROVALS__POLL_INTERVAL_S` | `2` | Seconds between looks at a request a call is waiting for, when Redis has not woken it. |
| `KEYSTONE_APPROVALS__WEBHOOK_URL` | unset | Where a new request is announced, signed (see Approvals). Needs `KEYSTONE_APPROVALS_WEBHOOK_SECRET`. |
| `KEYSTONE_APPROVALS_WEBHOOK_SECRET` | unset | The key that signs the webhook, at least 16 characters. Read from the environment only, never from the YAML. Not a nested setting: one underscore. |
| `KEYSTONE_APPROVALS__SLACK_WEBHOOK_URL` | unset | A Slack incoming webhook that gets a plain message for each request. A secret. |
| `KEYSTONE_APPROVALS__WEBHOOK_BACKOFF_S` | `[1, 2, 4]` | JSON list of the seconds before each retry of a webhook delivery. |
| `KEYSTONE_SCANNER__ENABLED` | `true` | Whether tool output is scanned. See Scanner. |
| `KEYSTONE_SCANNER__CLASSIFIER` | `protectai-deberta-v2` | The model behind the rules: `protectai-deberta-v2`, `prompt-guard-2-86m` or `none`. Needs the extra `keystone[scanner]`. |
| `KEYSTONE_SCANNER_CLASSIFIER` | unset | The same setting under a shorter name (one underscore). It wins when both are set. `KEYSTONE_SCANNER_CLASSIFIER=none` turns the model off. |
| `KEYSTONE_SCANNER__CLASSIFIER_TIMEOUT_MS` | `300` | How long a scan waits for the model. After that the scan goes on with the rules alone and its `model` says `timeout`. 1 to 10,000. |
| `KEYSTONE_SCANNER__JOIN` | `rules_first` | How the rules' score and the model's make one: `rules_first` (a text the rules flag keeps their score and the model is not asked; any other text gets the model's score added at `MODEL_WEIGHT`) or `max` (the higher of the two, and the model reads every text, which Phase 7 shipped). |
| `KEYSTONE_SCANNER__MODEL_WEIGHT` | `0.7` | How much of the model's score counts for a text the rules did not flag. Over 0 and up to 1. A weight under 0.85 means the model alone can flag a text and cannot taint a session. |
| `KEYSTONE_SCANNER__WINDOW_TOKENS` | `128` | The model reads a long text in windows of this many tokens of the text (16 to 510). A short window keeps an attack from being lost in the document around it, and gives a long text more windows to read. |
| `KEYSTONE_SCANNER__WINDOW_OVERLAP` | `64` | Tokens a window shares with the one before. Less than `WINDOW_TOKENS`. |
| `KEYSTONE_SCANNER__THRESHOLDS__SUSPICIOUS` | `0.5` | A score from here up is `suspicious`. It is also the score at which the rules-first join stops asking the model. |
| `KEYSTONE_SCANNER__THRESHOLDS__INJECTION` | `0.85` | A score from here up is an `injection`. Not below `SUSPICIOUS`. |
| `KEYSTONE_SCANNER__ALLOWED_DOMAINS` | `[]` | JSON list of hosts a markdown image may point to without a mark against it. A name covers its subdomains. |
| `KEYSTONE_SCANNER__MAX_SCAN_CHARS` | `200000` | The most text one scan reads. A longer text is read at both ends, half of this at each. |
| `KEYSTONE_SCANNER__DESCRIPTION_THRESHOLD` | `0.5` | A new tool is held when the rules score its description, or the description of a field of its input schema, at or above this. Above 0, at most 1. See Upstreams. |
| `KEYSTONE_SANDBOX_ENABLED` | `true` | Whether the `sandbox` upstream is registered. `false` for a host with no Docker socket: no tool is listed and nothing talks to Docker. The same setting as `KEYSTONE_SANDBOX__ENABLED`; this shorter name wins when both are set. See Sandbox. |
| `KEYSTONE_SANDBOX__IMAGE` | `keystone-sandbox-python:dev` | The image the code runs in (`make sandbox-image`). |
| `KEYSTONE_SANDBOX__RUNTIME` | `runc` | The Docker runtime of the containers: `runc`, or `runsc` where gVisor is installed. |
| `KEYSTONE_SANDBOX__TIMEOUT_S` | `30` | How long one run may take before its container is killed. Above 0, at most 300. |
| `KEYSTONE_SANDBOX__MAX_CONCURRENT` | `4` | Containers running at once. A call over that waits for one to end. |
| `KEYSTONE_RATE_LIMITS__<SCOPE>__CAPACITY` and `KEYSTONE_RATE_LIMITS__<SCOPE>__REFILL_PER_S` | unset (no limit) | A token bucket for one scope: how many calls at once (1 or more) and how many more each second (above 0). `<SCOPE>` is `PER_TENANT`, `PER_USER`, `PER_AGENT` or `PER_TOOL`. Also `rate_limits.per_user: {capacity: 60, refill_per_s: 1}` in the YAML, and an environment variable changes one field of what the file sets. See Rate limits. |
| `KEYSTONE_LLM_PROXY__ENABLED` | `false` | Whether the routes `/llm/anthropic/v1/messages` and `/llm/openai/v1/chat/completions` exist. Needs `KEYSTONE_MASTER_KEYS` and a price file; either missing stops the start. See LLM proxy. |
| `KEYSTONE_LLM_PROXY__TENANT` | the only tenant, when there is one | The tenant that owns the provider keys, and the only one whose agents may use the proxy. Needed when `tenants` lists more than one. |
| `KEYSTONE_LLM_PROXY__PRICING_FILE` | `pricing.yaml` | The price list, read at start. Compose mounts `deploy/pricing.compose.yaml` (fake prices) at `/etc/keystone/pricing.yaml`. |
| `KEYSTONE_LLM_PROXY__ALLOW_UNPRICED` | `false` | Let a model that is not in the price list through at no cost, with a warning in the log. When `false` it is refused with 400. |
| `KEYSTONE_LLM_PROXY__DEFAULT_MAX_TOKENS` | `4096` | The output assumed by the budget check for a request that does not say how long its answer may be. |
| `KEYSTONE_LLM_PROXY__MAX_BODY_BYTES` | `8388608` | The largest request body the proxy reads (1,024 to 67,108,864). A larger one is refused with 413. |
| `KEYSTONE_LLM_PROXY__TIMEOUT_S` | `600` | How long the proxy waits on a provider for a byte, for a whole answer or a stream. |
| `KEYSTONE_LLM_PROXY__ANTHROPIC__BASE_URL`, `KEYSTONE_LLM_PROXY__OPENAI__BASE_URL` | `https://api.anthropic.com`, `https://api.openai.com` | Where the provider's API is. The proxy adds `/v1/messages` or `/v1/chat/completions`. |
| `KEYSTONE_LLM_PROXY__ANTHROPIC__API_KEY_ENV`, `KEYSTONE_LLM_PROXY__OPENAI__API_KEY_ENV` | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | The name of the environment variable that holds the provider's key. At each start the key goes into the vault, and the variable is not read again. `null` for a provider that needs no key. A name that starts with `KEYSTONE_` is refused. |

Four sections come from the YAML file only: `tenants`, `upstreams`, `agents` and `budgets` (see `keystone.example.yaml`).

## Credentials

An upstream that needs an API key gets it from Keystone, never from the agent and never from the
config file. The key is stored encrypted in Postgres (table `credentials`), and the credential slot
of the pipeline adds it to the call as an HTTP header at the last moment: after policy and
approval, so a refused call never has its credential decrypted, and dropped from the call context
as soon as the call ends. It does not appear in the tool list, in a result, in a rejection, in the
audit record or in a log line.

`credential_mode` on the upstream says whose credential it is:

| Mode | What Keystone sends |
|---|---|
| `none` (default) | Nothing |
| `static` | The upstream's own credential, the same for every caller |
| `per_user` | The credential of the user making the call. A user without one is refused with `KS_DENIED` ("no credential for this user on mail") |

```bash
echo -n "$MAIL_KEY" | keystone cred set --upstream mail --header X-Api-Key     # the value comes from stdin
keystone cred set --upstream mail --header X-Api-Key --from-env MAIL_API_KEY   # or from a variable
keystone cred set --upstream crm --user alice --header X-Api-Key --from-env ALICE_CRM_KEY
keystone cred list                                                             # who, which key, when
```

There is no option that takes the value on the command line, where a process list would show it.
On a terminal the command asks for the value without echoing it. `cred set` replaces the
credential it finds for that upstream and user, and holds one header. `cred list` prints the
tenant, upstream, user, the id of the master key and two times. It does not decrypt anything.

The vault needs `KEYSTONE_MASTER_KEYS`: one or more Fernet keys, comma separated. The first
encrypts and every one decrypts. Make a key with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. The
key in `.env.example` is public, for local use only: `KEYSTONE_ENV=prod` refuses it.

To rotate the master key, put the new key first and keep the old one, run
`keystone cred rotate-keys`, then remove the old key:

```bash
KEYSTONE_MASTER_KEYS="$NEW,$OLD" keystone cred rotate-keys     # rotated 12, already under the first key 0
KEYSTONE_MASTER_KEYS="$NEW"      keystone serve                # now the old key can go
```

It exits 1 and names the rows it could not decrypt if some credential was written under a key that
is no longer listed. A rotation never undoes a `cred set` made while it runs.

### From the environment at startup

In the config, an HTTP upstream can name the environment variable that holds its key instead of
holding it. Keystone reads the variable when it starts and stores the value in the vault through
the same code as `cred set`, before the first sync needs it:

```yaml
upstreams:
  - id: mail
    tenant: acme
    url: http://mail-mcp:8101/mcp
    credential_mode: static
    credential_env: {X-Api-Key: MAIL_API_KEY}
```

A value that has not changed is not written again. A variable that is not set leaves the stored
credential as it is, so a restart without the variable does not lose it. A name that starts with
`KEYSTONE_` is refused, so the master key cannot be used as an upstream credential by mistake.
`credential_env` on an upstream whose `credential_mode` is `none` is an error, because it would
never be sent. Keystone does not start if an upstream in the config uses credentials and
`KEYSTONE_MASTER_KEYS` is not set.

Keystone also uses an upstream's static credential for what it does on its own account: reading
the tool list (startup, the timer and `keystone registry sync`) and the health probes. A `per_user`
upstream that has a static credential is read with that one; a user's credential is never used
for it. Without a static credential those requests carry no key, so a `per_user` upstream that
demands a key even to list its tools needs a static credential as well, or its probes fail and
Keystone marks it down.

A call whose upstream gets no credential (a `static` upstream whose credential was deleted, say)
reaches the upstream without one. If the upstream answers 401 or 403, the agent gets
`KS_UPSTREAM_ERROR` ("the upstream server refused the credentials Keystone sent") at once: a
connection attempt that meets either status is not retried, because the same credential gets the
same answer, and the tests hold the call under 1 s. The log line `upstream_credentials_refused`
names the upstream. A connection that fails for any other reason still goes through the reconnect
backoff (0.2, 0.8 and 3.2 s).

An upstream that copies the key it received into a tool result does not hand it to the agent. Before
a result leaves dispatch, every credential value Keystone sent for the call, whatever its length,
and every secret registered with the log scrubber are replaced with `[redacted]`, in all text of
the result and in its structured content. The log line `upstream_result_redacted` names the
upstream and the tool, so an operator can see which server does it. Only a value that comes back as
it was sent is caught: an upstream that reverses, splits or encodes the key first is not, and a
server you do not trust belongs in a container (see Containerized stdio upstreams).

Header names are letters, digits and dashes. `Host`, `Content-Type`, `Mcp-Session-Id` and the
other headers the HTTP layer owns are refused. Values are printable ASCII on one line, up to 4096
characters.

Every credential the vault decrypts is also registered with the log scrubber, which replaces it
wherever it appears in a log line, in a field of any name and inside an exception message. A
value shorter than 8 characters is not registered, because it would match inside ordinary words, so
use keys longer than that.

## Tenants

A tenant is one team that shares the Keystone: its upstreams, its tools, its users and its
sessions. Compose runs two, `acme` and `globex`. A token's `tenant` claim decides which one a
caller belongs to, and nothing else can: not a header, not a field of the request. A token for a
tenant that is not under `tenants` in the config gets 403 `unknown_tenant`.

| | acme | globex |
|---|---|---|
| Users | alice, olivia, lena, root | bob |
| Upstreams | mail, files, bank, echo, web, echostd, sandbox (18 tools) | files_globex (3 tools) |

An upstream id is unique across tenants, so globex's drive is `files_globex` (its tools are
`files_globex__read_file` and so on) and not a second `files`.

A caller lists and calls only its own tenant's tools. A call to another tenant's tool, by its exact
name, gets `KS_TOOL_NOT_FOUND`, the same answer as for a name that does not exist anywhere, so
the answer does not confirm that the tool exists. `KS_DENIED` would. The gateway also drops any
tool the registry returns for another tenant, so a bug in a lookup cannot show one (invariant
I5, `tests/invariants/test_i5_tenants.py`).

Try it with `scripts/smoke/phase_3.sh`, or by hand:

```bash
KEYSTONE_TOKEN=$(scripts/get_token.sh bob support-agent) \
  uv run python scripts/smoke/mcp_probe.py call bank__get_balance '{"account": "CHK-001"}'
# error=true code=KS_TOOL_NOT_FOUND
```

## Policies

The rules that decide a call are Cedar policies kept in files, read when Keystone starts, checked
before they are used, and identified by a version. `docs/policies.md` explains how to write them,
with examples and the usual mistakes. Everything is under one directory (`policy.root`):

| Path | What it holds |
|---|---|
| `schema.cedarschema` | The schema, the one source for entities and context (plan section 3.8) |
| `default/access/*.cedar`, `default/approval/*.cedar` | Rules for every tenant |
| `<tenant>/access/*.cedar`, `<tenant>/approval/*.cedar` | Rules for one tenant, named by its id |
| `demo/access/*.cedar`, `demo/approval/*.cedar` | Rules for the demo upstreams, read when `policy.include_demo` is on |

A tenant's access set is `default/` plus `demo/` (if on) plus its own directory, and so is its
approval set. The access set is standard Cedar: a call is denied unless a permit matches and no
forbid does. The approval set holds permits only, and is asked after access allowed: a permit that
matches means a person has to approve the call.

### How a call is decided

The policy slot runs after the pinning check and before approval and credentials, so a refused
call never has its credential opened. It reads the arguments a tool's `extract` config names,
builds the entities (the user as `Keystone::User::"<tenant>:<user>"` with its groups as parents,
the tool with its upstream, risk, risk level and tags) and the context (agent, trust, session
flags, taint, call count, hour in UTC and the extracted `args`), and asks the engine:

| The engine says | The agent gets | The audit record has |
|---|---|---|
| allow | the call goes on | `allow`, with the ids of the permits that allowed it |
| deny | `KS_DENIED`, "denied by policy: `<ids>`", and the ids in `_meta` as `keystone/reasons` | `deny`, with the ids of the forbids that matched, or `default-deny` when nothing allowed it |
| require approval | the call is held for a person (see Approvals), then runs, or ends as `KS_APPROVAL_REJECTED`, `KS_APPROVAL_EXPIRED` or `KS_APPROVAL_PENDING` | `require_approval`, with the ids of the approval permits that matched |
| the rules could not be evaluated | `KS_DENIED` with the reason `policy-error` | `deny`, reason `policy-error` |

The last row is the fail-closed rule. It covers a policy that failed to evaluate in either pass
(Cedar skips such a policy, so a broken `forbid` would otherwise not forbid), a context the schema
refuses (an `args` key it does not know), a tenant with no set, and any exception. The cause goes
to the log as `policy_evaluation_failed`, naming the policy by its id, and never to the agent. A
set with no rule that allows anything denies every call with `default-deny` (invariant I6).

Each call's audit record holds the `effect`, the `decision_source` and the `reasons`, so the
decision can be read back from the log (see Audit).

### The default pack

| File | Policy | What it does |
|---|---|---|
| `default/access/base.cedar` | `same-tenant-low-medium` | Anyone may list and call low and medium risk tools of their own tenant |
| | `operators-high` | Members of `operators` may also use high risk tools of their tenant |
| | `admins-critical` | Members of `admins` may use critical tools of their tenant |
| | `deny-cross-tenant` | No one uses another tenant's tool, whatever else allows it |
| `demo/approval/bank.cedar` | `approve-transfer-over-500` | A transfer over 500, or one whose amount could not be read, needs approval |
| `acme/approval/mail.cedar` | `external-email-needs-approval` | A message to anyone outside `acme.test`, or to a recipient that is not one plain address, needs approval |
| `default/access/rule_of_two.cedar` | `deny-critical-when-tainted` | A session that read an injection never calls a critical tool |
| `default/approval/rule_of_two.cedar` | `rule-of-two` | A session that has read untrusted and sensitive data asks before it calls a tool with an external effect |
| | `untrusted-then-external-effect` | A session that has read untrusted text asks before it calls a tool with an external effect, whatever else it read (ADR-0018). A tenant turns it off with `exclude_default_policies` in its entry under `tenants` |
| | `tainted-external-effect` | A tainted session asks before it calls a tool with an external effect |

The Rule of Two (plan section 3.5) is the last four rows. A session should not combine all of
these without a person: it processes untrusted input, it has access to sensitive data, and it
changes state or sends data out. The first two are the session's flags (`reads_untrusted` and
`reads_sensitive`, from the tags of the tools it called) and the third is the tag `external_effect`
on the tool being called. So an operator who reads an email and then sends one in the same session
is asked about the second, whoever the mail goes to, and one whose session read an injection is
asked before any external effect and cannot call a critical tool. Both are ordinary Cedar, so a
tenant reads and tightens them like the rest. A new MCP session starts clean. A script that reads
mail and then sends it should send first, or use a session of its own for each step.

Risk comes from the upstream config, so in the local stack `mail__send_email` and
`bank__transfer` are high risk: support (alice) is refused both with `default-deny`, and an
operator (olivia) is allowed `bank__transfer` up to 500 and `mail__send_email` to `acme.test`
(`operators-high`), and asked about the rest: the call waits for a person (see Approvals), and
nothing is sent or moved until one approves it. `scripts/smoke/phase_4.sh` runs the demo.

### The tool list

`tools/list` shows a caller only the tools whose `list_tool` the policy allows. In the local stack
support sees 14 of acme's 18 tools and operators see all 18, because `mail__send_email`,
`bank__transfer` and the two tools of the sandbox are high risk and only operators may use them. Every caller is also offered the
two tools that Keystone serves itself (see Approvals), which the policy does not decide. The list
is only a convenience. Every call is decided again when it is
made, so a tool that is not listed is still refused if it is called by name. A listing that cannot
be decided shows nothing.

The answers are kept for `policy.list_cache_ttl_s` seconds (60) per caller and policy version, in
Redis under `ks:policy:listcache:{principal_hash}:{version}`, or in the process when there is no
Redis. The caller is the tenant, user, groups, agent, trust and roles. A reload changes the
version, so the next listing is decided under the new rules at once. A tool that is new, or whose
risk or tags changed, is decided again without waiting for the entry to expire. A listing does not
depend on the session, so a policy for `list_tool` cannot read the session flags. Redis being down
only means the answers are worked out again.

### What a load checks

A set with any problem is refused whole, and every problem is listed with the file it is in:

- The schema parses, and every policy validates against it. A misspelled attribute, an optional
  attribute read without `has`, a type error and an unknown entity type or action are all caught.
- Every policy has `@id("kebab-case-name")`. The id is what the audit log shows as the reason for
  a decision, so it is required, unique within a tenant's combined set (access and approval
  together), and not one of the names the engine uses itself (`default-deny`, `policy-error`).
- The approval set has no `forbid`. A policy there can ask for approval but cannot block a call,
  so a forbid would not do what its author expects.
- Policy templates (`?principal`) are refused: they do nothing until linked.
- A directory or file that Cedar would never read is an error too: `aproval/` instead of
  `approval/`, `base.cdar` instead of `base.cedar`, a directory that is not `default`, `demo` or
  a configured tenant, a `.cedar` file outside `access/` and `approval/`. A rule that silently does
  not load is a rule someone believes is in force. Hidden files (`.DS_Store`, editor swap files)
  are ignored. With no tenant configured nothing can be served, so tenant directories are not
  read and not checked.

Starting with a set that has a problem stops Keystone, and `keystone serve` prints each problem. A
reload with one is refused and the set in force stays in force.

### Versions

The version of a set is the sha256 of its files, the schema included, taken as sorted
`(relative path, content)` pairs. It does not depend on timestamps or on the order the files were
written, so the same files give the same version on every start. Each version that is loaded is
recorded in `policy_versions` with every file's path, sha256 and content, so the rules in force at
the time of a decision can be read back from the version the audit record names.

### Testing

`uv run keystone policy test policies tests/policy_cases --coverage` runs the cases in
`tests/policy_cases/` through the loader and the engine, prints one row per case and exits 1 if any
case decides differently or a policy was matched by no case. The `policy` job of CI runs it on every
push, and `make gate` expects it to pass. `docs/policies.md` describes the case format.

### Reloading

| How | What it does |
|---|---|
| `keystone policy reload` | Calls the endpoint below. `--url` (or `KEYSTONE_ADMIN_URL`, default `http://localhost:8080`) is the running Keystone, and `--token` (or `KEYSTONE_ADMIN_TOKEN`) is an access token of a user with the `admin` role. Exits 1 and prints every problem when the set is refused. |
| `POST /admin/api/v1/policies/reload` | Needs the `admin` role. 200: `{"version", "previous", "changed"}`. 422: `{"error": "invalid_policies", "errors": [...], "version": <the version still in force>}`. 401, 403 and 503 are as for `/mcp`. |
| `kill -HUP <pid>` | The same reload in the process that gets the signal. A refused set is logged as `policy_sighup_refused` and nothing changes. |

```bash
export KEYSTONE_ADMIN_TOKEN=$(scripts/get_token.sh root keystone-cli)
uv run keystone policy reload
# policies reloaded: version 4f0c8a1d92b3 (unchanged)
```

The admin API checks the token with the code that checks it for `/mcp`, but the caller does not
have to be a listed agent: `keystone-cli` is how the CLI signs in, and it is not under `agents`.
What lets a caller in is the `admin` role (user `root` in the local realm). A reload runs one at a
time. It records the new version before it puts the set in force, so a set that could not be
recorded is not used.

## Approvals

A call that the policy sends to approval (`require_approval`) waits for a person. Each request is a
row in `approvals`, and it is specific, time-limited and used once. This section describes the
service that keeps the rows. The interceptor that holds the call, the tools an agent waits with
and the API an approver uses come after it.

A row holds the tool, the arguments with secrets masked (`args_redacted`, the same masking the
audit log uses), who asked (user, agent, session, call), the ids of the policies that asked, and
the original arguments encrypted with the vault's keys (`args_ciphertext`) so that an approved call
runs with exactly them. It also holds `args_digest`, the sha256 of the canonical JSON of the
arguments that the audit log writes as `args_digest`. The approval is for that digest: it cannot
be used for other arguments.

| State | How it gets there |
|---|---|
| `pending` | The call was sent to approval |
| `approved`, `rejected` | A person with the `approver` or `admin` role decided |
| `consumed` | The approved request was used by the call it was made for |
| `expired` | `ttl_seconds` passed before it was decided or used |

The rules, each one SQL statement in `src/keystone/approvals/service.py`:

- **Decide.** A request changes only while it is pending, unexpired, in the approver's tenant and
  not requested by the approver. The user who asked can never approve their own request, whatever
  roles they hold, and an approver of another tenant gets "not found". Two decisions at once leave
  one: the other is told the request is no longer pending.
- **Use.** An approval is used by one `UPDATE` that checks the status (`approved`), the tenant,
  the tool, the session, the user, the digest of the arguments and that it has not expired. It
  returns whether it changed a row, so of two calls that present one approval exactly one gets it.
- **Time.** `expires_at` is set from the database clock, and both statements compare it with
  `clock_timestamp()`. They do not use `now()`: that is the start of the transaction, so a
  statement held up by a row lock would be judged by a time before it waited, and could use an
  approval after it had expired. `test_a_consume_that_waited_for_a_lock_past_the_expiry_fails`
  holds a lock across an expiry to show the difference. The sweeper marks expired rows every 30
  seconds; nothing depends on it for safety.
- **Waiting.** A waiter subscribes to `ks:approval:<id>` on Redis, reads the row, and sleeps until
  a message arrives or `poll_interval_s` passes. A message only wakes it. The verdict is always
  read from the row, so a message that is lost or forged decides nothing, and without Redis the
  wait polls.
- **Keeping.** The original arguments are kept for one purpose, to run an approved call. The
  statement that makes a request unusable (a rejection, a use, the sweeper marking it expired)
  empties them in the same change. The masked form, the digest and who decided stay.
- **Ids.** An id comes from an agent's arguments or a URL, and Postgres cannot hold a NUL
  character. Ids are cleaned like every other value, so an id with one is a request nobody has.

`keystone_approvals_pending{tenant}` counts the pending requests of each tenant. It is set when
the sweeper starts and after each request, decision and sweep.

Approvals need `KEYSTONE_MASTER_KEYS`, because the arguments are encrypted with the vault's keys.
Without them there is no approval service and a call that needs approval is refused with
`KS_DENIED`, "approval not available". Rotating the keys needs no re-encryption of the arguments:
every key decrypts, and a request lives for 15 minutes at most. Removing a key before the requests
it encrypted have expired makes those requests unusable.

### Holding a call

The approval slot runs after the policy slot. For a `require_approval` decision it does one of two
things (`gateway/interceptors/approval.py`, ADR-0010).

A new call is stored as a request and held in line for `approvals.wait_seconds` (60 by default;
the local stack uses 10). The agent sees one slow call, and then one of:

| What happened in the wait | The agent gets | The audit record has |
|---|---|---|
| a person approved it | the upstream's result, as if there had been no approval | `require_approval`, outcome `ok`, `dispatched` true, and `approval:<id>` after the policy's reasons |
| a person rejected it | `KS_APPROVAL_REJECTED`, with the approver's note as the message | outcome `rejected`, code `KS_APPROVAL_REJECTED` |
| it expired | `KS_APPROVAL_EXPIRED` | outcome `rejected`, code `KS_APPROVAL_EXPIRED` |
| nobody decided | `KS_APPROVAL_PENDING` | outcome `rejected`, code `KS_APPROVAL_PENDING` |

A pending answer carries the id of the request in the text, where a model reads it, and in `_meta`
as `keystone/approval_id`, with `keystone/expires_at` and `keystone/next` (`call
keystone__await_approval`). The call does not run until the request is approved and used.

A call that is approved in the wait is checked again before its approval is used. The slots ahead
of the approval slot decided it before the wait, and a tool may have been quarantined, a policy
reloaded or a budget spent since. They run a second time (pinning, budget and policy; the rate
limit does not, since a call is charged once) and what they say stands: a quarantined tool ends the
call with `KS_QUARANTINED`, a policy that now denies it with `KS_DENIED`, an unhealthy audit log
with `KS_DENIED` ("audit unavailable"), and in each case the approval is left unused. If the policy
no longer asks for approval the call goes on as an allow and the approval is not used. The agent
is not handed the id of an approval that was left unused: it asks again, and a person decides
again. The record of a call that ran on an approval ends its reasons with `approval:<id>`, so the
audit log says which approval allowed it and the approval row says who decided.

A call that arrives with an approval id on its context is the re-entry of a call that waited. The
slot takes the id off the context, uses the approval against the call's tool, session, user and
arguments digest, and puts the id back only if that worked. The pipeline dispatches a
`require_approval` call only when the id is on the context (KS-191), so a call with a made-up id,
one for other arguments, a used one or an expired one is refused with `KS_APPROVAL_EXPIRED` and
never reaches the upstream. Invariant I7 (`tests/invariants/test_i7_approvals.py`) tries every
combination of an id in each of its six states with arguments, tool, session and user that are the
approved ones or not: exactly one dispatches.

### Deciding through the API

The console and scripts decide with three routes. A caller needs the `approver` or the `admin`
role, and sees the requests of the tenant of the token only.

`GET /approvals?status=pending` answers a list, oldest first. `GET /approvals/{id}` answers one
request and `recent_calls`. Each request has: `id`, `status`, `tool`, `risk` and `tags` (of the
tool, `null` if the tool is not registered), `arguments` (secrets masked), `args_digest`,
`reasons` (the ids of the policies that asked), `requested_by_user`, `requested_by_agent`,
`arguments_masked`, `own_request` (true when the caller made it and so cannot decide it),
`session_id`, `call_id`, `requested_at`, `expires_at`, `expires_in_s` (counted by the server, so a
clock that is wrong in the browser does not matter), `decided_by`, `decision_note`, `decided_at`,
and `flags` and `tainted` of the session that asked. The session is read without keeping it alive.

The `arguments` are what the audit log keeps of them: the value under a key that looks like a
secret is `[redacted]`, a card number, a social security number, a bearer token, an AWS key id or a
private key inside a string is replaced, a string over 2,048 characters is cut to its first 256
characters and the sha256 of the whole, and arguments that are still over 16 KiB after that are
replaced by a note. `arguments_masked` is true when any of that happened. What runs is more than
what is shown, so an approver should treat what is not shown as unknown, and a console should say
so next to the decision. It does not block a decision. `args_digest` is the digest of the real
arguments, and the approval is for exactly those.

`POST /approvals/{id}/decision` takes `{"approve": true|false, "note": "..."}` (the note is
optional and at most 500 characters; `approve` must be a JSON boolean and an unknown key is an
error) and answers the request as it now stands.

| Status | When |
|---|---|
| 200 | The decision was made |
| 401 | No token, or one that is not valid |
| 403 | No approver or admin role, or the request is the caller's own |
| 404 | There is no such request in the caller's tenant (another tenant's looks the same, and so does an id that is not one) |
| 409 | The request is no longer pending. The body is `{"error": "conflict", "reason": "the request is approved", "status": "approved"}`; `status` is `approved`, `rejected`, `consumed` or `expired`. A request past its time is `expired` at once, before the sweeper has marked it |
| 422 | The body is not a decision |
| 503 | Keystone has no master keys, so there are no approvals |

The decision is one statement (see above), so two approvers who decide together get one 200 and
one 409. A rejection reaches the agent as `KS_APPROVAL_REJECTED` with the note.

### Telling others

`approvals.webhook_url` (`KEYSTONE_APPROVALS__WEBHOOK_URL`) makes Keystone `POST` a JSON body to
that address when a request is made:

```json
{"id": "01J...", "tenant": "acme", "tool": "bank__transfer", "requester": "olivia",
 "agent": "ops-agent", "reasons": ["approve-transfer-over-500"],
 "expires_at": "2026-10-23T12:15:00+00:00",
 "console_url": "http://localhost:5173/approvals?id=01J..."}
```

The arguments are not in it. The body is signed, so the receiver can check where it came from and
how old it is:

```
X-Keystone-Timestamp: 1761218100
X-Keystone-Signature: sha256=<hex HMAC-SHA256 of timestamp + "." + body>
```

The key is `KEYSTONE_APPROVALS_WEBHOOK_SECRET`. It is read from the environment and from nowhere else:
a `webhook_secret` in the YAML is an error, and Keystone does not start with a webhook and no
secret, or with one shorter than 16 characters (`openssl rand -hex 32` makes a good one). A receiver
checks it like this, and refuses a timestamp older than a few minutes:

```python
import hashlib, hmac


def valid(secret: bytes, timestamp: str, signature: str, body: bytes) -> bool:
    mac = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, f"sha256={mac}")
```

A delivery never delays the call that asked. It is queued and sent by a task of its own, with 5
seconds for each attempt and three retries after 1, 2 and 4 seconds (`approvals.webhook_backoff_s`
changes them). A network error, a timeout, a 408, a 429 and a 5xx are retried; any other answer
ends the delivery. Failures are logged with the receiver's host and no more. The queue holds 100
notifications and drops the rest, logging `approval_notification_dropped`.

`approvals.slack_webhook_url` (`KEYSTONE_APPROVALS__SLACK_WEBHOOK_URL`) sends a plain message to a
Slack incoming webhook: who wants to call which tool, the reasons and the console link. Its address
is a secret, so it is held as one and never logged; set it from the environment. The agent's id, the
tool's name and the reasons are written by others, so `&`, `<` and `>` in them are escaped and a
name such as `<!channel>` reads as text and pings no one.

### Keystone's own tools

Two tools belong to Keystone itself. Their names start with `keystone__`, the id of a pseudo-upstream
that no configured upstream can have: the config loader, `keystone upstream add` and the registry
all refuse the id `keystone`, and the gateway does not believe a registry row that claims it. Every
caller is offered both in `tools/list`, whatever the policy says about the rest. A call to either
goes through the pipeline like any other. The policy slot gives it `allow` with the decision source
`virtual` and the reason `virtual-tool`, and does not ask Cedar (an empty policy set still offers
and answers them: they are the exception to I6, and the await tool runs a call that the policy
decides again). The pinning and credential slots have nothing to look up for them. Rate limits, the
audit sink, tracing and metrics apply as they do to every call.

| Tool | Arguments | What it does |
|---|---|---|
| `keystone__await_approval` | `approval_id` (from `KS_APPROVAL_PENDING`), `wait_seconds` (0 to 120, 60 by default) | Waits for the request, and when it is approved runs the call that waited |
| `keystone__whoami` | none | Returns `principal` (`tenant_id`, `user_id`, `groups`, `agent_id`, `agent_trust`, `scopes`, `roles`), `flags`, `tainted`, `call_count` and `spent_usd` |

`keystone__whoami` shows who Keystone thinks the caller is and the state of the session. It never
returns a token or a credential: the principal holds none.

`keystone__await_approval` answers only for a request made by this user, through this agent, in this
session. An id that does not exist, one of another tenant, another user or another session gets the
same `KS_DENIED`, "there is no such approval request for this session". For an id that is the
caller's it waits up to `wait_seconds`, then:

| The request is | The agent gets |
|---|---|
| approved | the result of the original call, which ran just now with the arguments that were approved |
| rejected | `KS_APPROVAL_REJECTED` with the note |
| expired, or already used | `KS_APPROVAL_EXPIRED` |
| still pending | `KS_APPROVAL_PENDING` again, with the same id |

The original call runs through the whole pipeline again, as a call of its own with a new call id.
The tool must still be active (a quarantine since then refuses it), the policy decides again under
the rules in force now, and the approval is used against the tool, session, user and arguments it
was made for. A policy that has been tightened since the approval refuses the call with
`KS_DENIED`, and the approval is kept: when the rule is lifted the same id completes the call. The
audit log has a record for the call that was told to wait, one for the call the await ran, and one
for the await (source `virtual`). A client must not give up on a held call before the hold ends: an
HTTP read timeout shorter than `approvals.wait_seconds` (or than the `wait_seconds` of an await)
ends the connection, not the request. The scripted agent waits up to 330 seconds.

### What approvals do not do

- **Revoke.** An approval is good until it is used or `approvals.ttl_seconds` have passed since the
  request (15 minutes by default). To stop a call that is approved already, quarantine or disable
  the tool, or change the policy: the call is checked at the time of use and refused.
- **Spare an approval that a later slot refuses.** The approval is used before the credential slot
  and the dispatcher run. A call refused there, for a per-user credential that is missing or an
  upstream that is marked down, has spent its approval, and a person decides again.
- **Limit.** A call that asks for approval is a call, so a rate limit (KS-804) caps how fast a user,
  an agent or a tenant can make requests, and the request that would pass it is refused before it is
  a row. Nothing caps how many requests one user or session leaves pending at a pace under the limit,
  merges identical ones (an approver who approves two lets the call run twice) or counts the callers
  waiting at once; every waiter holds a Redis connection and polls the table. The queue API shows
  the oldest 200 requests.
- **Put the approvals table in the audit chain.** The table is not part of the tamper-evident
  chain, and the role Keystone connects as can change it. The audit record of a call that ran on
  an approval names it, which ties the two together without protecting the table.

## Upstreams

Each upstream has an `id` (lowercase letters, digits and single underscores, not ending in an
underscore, and not `keystone`, which is reserved for Keystone's own tools), a `tenant` that is
listed under `tenants` and, for `transport: http`, a `url`. A
`credential_mode` (`none`, `static` or `per_user`) and per-tool settings are optional. An unknown
key is an error, so a typo does not pass quietly.

Keystone applies the `upstreams` section every time it starts. It adds or updates each entry with
`source=config`, and a config upstream that is no longer in the file is set to `disabled`. Rows are
never deleted, because audit records name upstreams. If any entry cannot be used (an unknown
tenant, a missing url, a URL the SSRF guard refuses), Keystone stops at startup, names every
problem, and writes nothing.

The URL check resolves the host and refuses it unless every address is public. It runs when an
upstream is registered, so it does not stop a name that points somewhere public today and
somewhere private later (DNS rebinding). Keep the network policy around the gateway tight in
production.

The `keystone` command manages upstreams without a restart. It reads the same settings as the
server, so run it where `KEYSTONE_DATABASE_URL` points at the right database (inside compose:
`docker compose -f deploy/docker-compose.yml exec keystone keystone upstream list`).

| Command | What it does |
|---|---|
| `keystone upstream list [--all] [--json]` | Id, tenant, transport, status, source, last sync and target. `--all` includes disabled upstreams. |
| `keystone upstream add ID --url URL [--tenant T]` | Register an http upstream with `source=cli`. The URL goes through the SSRF guard. |
| `keystone upstream add ID --transport stdio -- CMD ARGS...` | Register a stdio upstream. |
| `keystone upstream remove ID` | Disable a CLI upstream. A config upstream is removed by editing the file. |
| `keystone cred set --upstream ID --header NAME [--user U] [--from-env VAR]` | Store an upstream credential, read from stdin or the variable. |
| `keystone cred list [--json]` | Stored credentials, without their values. |
| `keystone cred rotate-keys` | Re-encrypt every credential under the first master key. |
| `keystone agent list [--json]` | The agents in the config with their trust level, and what an unlisted agent gets. |
| `keystone db upgrade` | Apply database migrations. `keystone serve --migrate` does it before starting; the compose stack uses that. |

### stdio upstreams

An upstream with `transport: stdio` is a program that Keystone starts and talks to over its
standard input and output. In the YAML it has a `command` (a list) and an optional `env` (a map);
with the CLI, put the command after `--`:
`keystone upstream add tools --transport stdio -- python -m my_server`. The compose stack starts
one, `echostd`, which runs `python -m examples.upstreams.echo_server --transport stdio` inside the
Keystone container (the image keeps `examples/` in `/app`).

The program starts when the first call or sync needs it, starts again after a crash (with the
reconnect backoff of 0.2, 0.8 and 3.2 seconds), and ends when Keystone shuts down. A call that
was running when it died fails and is not sent again. Its environment is `PATH` (Keystone's, unless
`env` sets one) and the variables in `env`, and nothing else: not `HOME`, not any `KEYSTONE_*`
variable, never the master key or the database URL. A key in `env` that starts with `KEYSTONE_` is
refused when the config loads. `env` values are plain text in the YAML, so they are for settings
and not for secrets. `env` can only be set in the YAML; an upstream added with the CLI gets just
`PATH`. POSIX only.

A stdio upstream runs as the Keystone user, with no sandbox. Whoever can write a `command` into the
`upstreams` table or run `keystone upstream add` can run a program inside the Keystone container,
so treat both as operator rights and keep the database closed. For a server you do not trust, use
a containerized one.

### Containerized stdio upstreams

`transport: container_stdio` runs a stdio server in a container (KS-803, ADR-0012):

```yaml
  - id: crm
    tenant: acme
    transport: container_stdio
    image: crm-mcp:1.4        # built on the host already; Keystone never pulls
    command: [crm-server, --stdio]   # optional; the image's own command if left out
    env: {CRM_REGION: eu}     # plain settings, as for stdio; passed by name, never on a command line
    network: none             # none (the default) or bridge
```

Keystone starts it with `docker run --rm -i --pull never --network none --read-only --cap-drop ALL
--security-opt no-new-privileges --memory 256m --memory-swap 256m --pids-limit 64 --user 10001`,
labelled `keystone.container_stdio=1`, when the first call or sync needs it, and again after it
dies, with the backoff of a stdio upstream. Closing the connection ends the container (`--rm`
removes it). `bridge` lets the server reach the network: that is a decision about a third party,
so it is written in the config and nowhere else. A name in `env` that starts with `DOCKER_` is
refused, since the `docker` command reads those too. The `docker` binary is in the Keystone image.
With the CLI: `keystone upstream add crm --transport container_stdio --image crm-mcp:1.4 -- crm-server
--stdio` (always with no network).

`examples/upstreams/Dockerfile.echo` builds the demo echo and probe servers as such an image
(`make echo-image`, tag `keystone-echo-stdio:dev`); the tests of this transport use it. An image
that is not built is an upstream whose sync failed, with `last_error` set, and not a crash.

### Tool lists and syncing

Keystone reads each upstream's tool list when it starts, every `registry.sync_interval_s`, and
when you run `keystone registry sync`. Each tool is stored with the SHA-256 of its description and
of its input schema. The `tools` block of an upstream in the YAML sets risk, tags, cost, timeout
and extractors by the upstream's own tool name (for example `send_email`, not `mail__send_email`).
A tool without an entry has risk `medium`, no tags and no cost.

An extractor reduces a call's arguments to a fact a policy may read, such as the amount of a
transfer or the domain of a recipient. The `extract` map of a tool pairs a field of the schema's
`args` record with a path and pipes:

```yaml
tools:
  send_email: {risk: high, tags: [external_effect], extract: {recipient_domain: "$.to | domain"}}
  transfer:   {risk: high, tags: [external_effect], extract: {amount: "$.amount | cents"}}
```

The path is `$.a`, `$.a.b` or `$.a[0]`, in any mix. The pipes are `int` (cut the fraction), `cents`
(times 100, rounded half up), `domain` (the domain of one plain email address, in lower case),
`lower` and `len` (of a text or a list). The key must be a field of `args` in
`policies/schema.cedarschema` (`amount`, `recipient_domain`, `path` or `count`), and the pipes
must give the type the schema says. Keystone stops at startup, naming the upstream, the tool and
the key, if one is not. An argument that is not there, or that a pipe cannot use, leaves the key
out for that call and logs why at debug level, without the value. A policy has to ask
`context.args has amount` before it reads the field.

Two cases are treated so that a rule is not skipped by accident. A number beyond the range of a
Cedar `Long` (about 9.2 x 10^18) is capped at the range, so a rule that says "over 500" still sees a
transfer of 10^30. And `domain` accepts one plain address: `a@evil.test,b@acme.test`, a display
name or a comment has no domain. With `int`, an amount of 500.99 becomes 500; use `cents` for
money and write the limit in cents.

| Command | What it does |
|---|---|
| `keystone registry sync [--upstream ID] [--json]` | Sync now and print, per upstream, how many tools were created, unchanged, changed and removed, plus the names and any errors. Exits 1 if an upstream could not be synced. |
| `keystone upstream sync ID` | The same for one upstream. |

What a sync does to a tool:

| Upstream lists the tool | Result |
|---|---|
| for the first time | created, status `active` |
| with the definition we hold | unchanged; the config's overrides are applied again |
| with a different description or schema | reported as `changed`; pinning (KS-205) decides what happens |
| no longer, in a complete list | an `active` tool becomes `disabled`, reason `removed_from_upstream`, and returns to `active` if the upstream lists it again with the same definition. A quarantined tool stays quarantined, so vanishing and coming back is no way around a review. |

A sync that fails, because the upstream is down, slow or sent a broken answer, writes the error to
the upstream's `last_error` and changes no tool. Only a complete list can show that a tool is
gone. A failure on one upstream does not touch any other upstream, and startup carries on: the
upstream's tools stay as they were and the timer tries it again at the next round. `keystone
upstream list` shows the error under the row.

### Pinning and quarantine

A tool's description is text the model reads, so a server that changes it after you approved it
can give the agent new instructions. Keystone stores the description and the schema it first saw
(the pinned definition) with their hashes, and shows agents only that.

When a sync finds a different description or schema, the tool is `quarantined`, with the reason
`description_changed`, `schema_changed` or both, and the new definition waits next to the pinned
one. A quarantined tool is left out of `tools/list`, and a call to it returns `KS_QUARANTINED`
without reaching the upstream. The check reads the tool's status from Postgres on every call, so a
quarantine made by the CLI in another process stops the very next call. If an upstream takes the
change back, the tool is released by the next sync. A newer offer replaces an older pending one.

| Command | What it does |
|---|---|
| `keystone tool list [--status S] [--json]` | Every tool with its status and reason. |
| `keystone tool show NAME` | The pinned definition, the pending one, a diff, and a fingerprint of the pending definition. |
| `keystone tool approve-change NAME [--expect FP] [--note TEXT]` | Make the pending definition the pinned one, recompute the hashes and set the tool `active`. With `--expect`, refuses if the pending definition is no longer the one with that fingerprint. The note goes in the log. |
| `keystone tool disable NAME` / `enable NAME` | Take a tool out of service by hand. Sync never re-enables a tool you disabled. `disable` and `enable` both refuse a quarantined tool (review it and approve it instead), and `enable` refuses one the upstream stopped listing. |

A tool seen for the first time is screened too (`keystone.defense.description_check`), in two
passes over its description and over the `description` of every field of its input schema, at any
depth. The first pass is five rules from Phase 2: characters a reader cannot see (tag characters,
zero-width and bidirectional controls), phrases such as "ignore all previous instructions" or "do
not tell the user", the pseudo tags `<important>` and `<system>`, "before using this tool"
together with read, send or call, and a text longer than 2,000 characters. The second pass is the
scanner's rules, the ones that read tool output (see Scanner), and it holds the tool when the
highest score is at or above `scanner.description_threshold` (0.5). The classifier is not used: it
scored two harmless descriptions of the demo tools ("Return the payload unchanged.") at 0.998, and a
tool must not be held or not depending on whether a model has loaded.

A tool that trips either pass is created `quarantined` with the reason
`suspicious_description:<rule ids> score=<score> in=<place>`, for example
`suspicious_description:role_spoof,tool_directive score=0.70 in=input_schema.properties.note`. It
has no pending definition. The first pass's rules come first, then the scanner's, each once; the
score is the highest of the texts that held the tool, and the place is where it was. With
`scanner.enabled: false` only the first pass runs, on the description alone, and the reason is the
rule ids as before. A schema with more than 1,000 descriptions is held as `oversized` and the rest
is not read. Other strings of a schema (`title`, `default`, `enum`, `examples`, property names)
are not read. `keystone tool show` and the tools page print the rules and the score. The agent is
told the category only, not which rule fired. `approve-change` releases it as it is after you have
read it. These are patterns and a determined author will get past them; they stop the careless and
make a person look. Try it: `ECHO_POISONED=1` makes the demo echo server list a tool that is held
at first sight.

Review with `tool show`, then approve with the fingerprint it printed:
`keystone tool approve-change echo__echo --expect 1a2b3c4d5e6f`. Without `--expect`, a server
that changes the definition again between your review and your approval gets the second version
approved. The approval is logged now; the audit log records it from Phase 5.

### Health

Every `health.interval_s` Keystone asks each live upstream for its first page of tools, with a
`health.timeout_s` limit. A failed probe makes the upstream `degraded`, and `health.down_after`
failed probes in a row make it `down`. One good probe makes it `up` again. The probes go on while
an upstream is down, which is how it comes back. With the defaults an upstream that stops
answering is `down` after about 90 seconds.

A call to a `down` upstream is refused at once with `KS_UPSTREAM_ERROR` ("upstream bank is down")
and is not sent. Its audit record shows `dispatched: false`. The tools of a `down` upstream stay
in the list, because the upstream may be back before the next `tools/list`.

`GET /readyz` has an `upstreams` object next to `dependencies`:
`{"upstreams": {"bank": "down", "mail": "up"}}`. An upstream that is down does not change the HTTP
status. Only Postgres and Redis do.

### Telling clients about changes

When a sync changes which tools a tenant can see (a tool appears, disappears or changes
definition), Keystone sends `notifications/tools/list_changed` to that tenant's open sessions. A
change made by the CLI in another process is noticed within `registry.cache_ttl_s`. Only a client
that keeps the standalone GET stream open receives it; others see the change at their next
`tools/list`.

Without `--tenant`, `add` uses the config's only tenant, and fails when the config names none or
several.

## Sandbox

Code an agent writes runs in a container that Keystone starts for that call and removes after it
(ADR-0012, KS-801). The runner is `src/keystone/sandbox/runner.py`, and the tools that use it are
the upstream `sandbox` (KS-802).

What a container has: no network (a loopback and no route), a read-only root, a tmpfs of 64 MB on
`/tmp` (nothing in it can be run) and on `/workspace`, 512 MB of memory with no swap, one CPU, 128
processes, no capabilities, `no-new-privileges`, and user 10001. These are fixed in the code and
are not settings. Output is cut at 64 KB for stdout and for stderr, and a run still going after
`sandbox.timeout_s` is killed and says so.

Three things are needed, and compose supplies them:

| What | Where it comes from |
|---|---|
| The Docker socket | compose mounts `/var/run/docker.sock` into the Keystone container. **Local and single-host use only**: whoever can use the socket can start any container on the host as root. Keystone runs as user 10001, so compose adds the socket's group: `DOCKER_SOCKET_GID`, default `0` for Docker Desktop. On Linux set it to `stat -c %g /var/run/docker.sock`. |
| The image | `make sandbox-image`, or the one-shot compose service `sandbox-image` that `make up` runs. It is `deploy/sandbox/Dockerfile.python`: Python 3.12, numpy, pandas and `wget`. |
| `KEYSTONE_SANDBOX_ENABLED` | `true` unless set. Set it to `false` where there is no socket (a Fargate task). |

Look at what the sandbox has started with `docker ps -a --filter label=keystone.sandbox=1`; the
label `keystone.call_id` names the call. A container older than 10 minutes is removed by the
reaper, which looks once a minute. `docker ps` should show none that are minutes old; if it does,
the reaper is not running or cannot reach the daemon (`sandbox_reaper_failed` in the log).

### The tools

The upstream `sandbox` has transport `builtin`. Add `- {id: sandbox, tenant: acme, transport:
builtin}` under `upstreams` to give a tenant its two tools (the compose config does). An upstream
id is unique across tenants, so one tenant has the sandbox unless you give another a copy under a
second id.

| Tool | Arguments | Runs |
|---|---|---|
| `sandbox__run_python` | `code`, and optionally `stdin` | `python -c code` with Python 3.12, numpy and pandas |
| `sandbox__run_shell` | `command` | `sh -c command` in the same image, with `wget` |

Both are high risk with the tag `code_exec`, so by the default access policy operators may call
them and nobody else may: a user in support is denied (`default-deny`) and does not see them in
`tools/list`. A tenant that wants other rules writes them in Cedar, or sets `risk` and `tags` for
the tools in the config. Setting a price there (`tools: {run_python: {cost_per_call_usd: 0.002}}`)
leaves the risk and the tag as they are.

The answer is one text block of JSON: `{"exit_code": 0, "stdout": "4\n", "stderr": "",
"timed_out": false, "truncated": false}`. A program that exits with anything but 0, or runs out of
time, is an error result (`isError`), and the block still says why. A run that is cut at 64 KB says
`truncated`. A NUL character in `code` or `command` is refused by the schema, before a container
is made. If Docker cannot run the container, the agent gets `KS_UPSTREAM_ERROR` and "the sandbox is
not available", and the log says why (`sandbox_unavailable`). The upstream is probed like the
others, and one the probes find down is refused at once; the probe checks the daemon, the runtime
and the image.

What a script prints goes through the scanner like the output of any tool. A script that prints an
instruction is redacted and wrapped in the warning (the action for high risk tools) and taints the
session, as a web page that holds one would. A session that ran code is not marked as having read
anything: `code_exec` is not one of the flags (`reads_untrusted`, `reads_sensitive`).

The descriptions of the two tools are pinned like any tool's. If a release of Keystone words one
differently, the tool is held until a person approves the change (`keystone tool approve-change`),
and `keystone tool show` has the diff.

`KEYSTONE_SANDBOX_ENABLED=false` leaves the `sandbox` upstream unregistered. Keystone sets a
`sandbox` row it stored before to `disabled` at the next start, so its tools leave the list, and
nothing talks to Docker.

To run under gVisor, install `runsc` on the Docker host, register it as a runtime, and set
`KEYSTONE_SANDBOX__RUNTIME=runsc`. Keystone checks that the daemon knows the runtime before it
says the sandbox is up.

The tests marked `docker` run the runner against the daemon. Without a daemon or the image they
are skipped and say why; with `KEYSTONE_REQUIRE_DOCKER=1` (which `make test-int`, `make gate` and
the integration job of CI set) that is a failure.

## Rate limits

A looping agent should hit a wall before it floods an upstream (KS-804). Each limit is a token
bucket: it holds `capacity` tokens, gets `refill_per_s` back every second, and a call takes one. A
bucket that is empty refuses the call with `KS_RATE_LIMITED` and says how long until it has a
token.

```yaml
rate_limits:
  per_tenant: {capacity: 600, refill_per_s: 10}   # everything a tenant does
  per_user:   {capacity: 60,  refill_per_s: 1}    # one user, the token's `sub`, through any agent
  per_agent:  {capacity: 120, refill_per_s: 2}    # one OAuth client, for all of its users
  per_tool:   {capacity: 30,  refill_per_s: 0.5}  # one tool, for everybody: it protects the upstream
```

Every scope is optional, and a scope left out has no limit. A call is checked against all the
scopes that are set, in the order above, and the first bucket with no token refuses it. Nothing is
taken from any bucket when one refuses, so a call refused for the tool has not used a token of the
user's. A scope belongs to a tenant: the same user id in two tenants has two buckets.

What counts: every call, including the two tools Keystone serves itself, and a call that goes on to
wait for approval. The limit is the first slot, so a flood of calls that the policy would deny, or
that would each make an approval request, is a flood of refusals and not of rows. An agent that
polls `keystone__await_approval` in a loop is limited like one that polls a mail server. The call
that the await tool runs once a person has approved is not counted again: it was counted when it
first arrived, and the await was counted as the call it is. (This is what closes the finding of the
Phase 6 gate, that nothing limited how many approval requests one agent could make.)

The answer to a call that is refused is the usual one (ADR-0007):

```
[keystone:KS_RATE_LIMITED] call 01J... rate limited: too many calls: your user's limit is used up, try again in 2.0 seconds
```

`retry_after_s` and `scope` are in the metadata of the text block, and also as `keystone/retry_after_s`
and `keystone/scope` in the metadata of the result, where a client library looks. The wait is rounded
up to the millisecond, so a client that sleeps that long is not refused again for a fraction of one.
The audit record has the decision `deny`, the source `rate_limit`, the reason `rate-limit:<scope>`,
the code `KS_RATE_LIMITED` and `dispatched` false, and `keystone_rate_limited_total{tenant,scope}`
counts it.

The buckets are in Redis under `ks:rl:<scope>:<tenant>:<id>` (a hash of `tokens` and `ts`), checked
by one Lua script that takes the time as an argument and does all the scopes of a call in one step,
so two Keystone processes share them and a check cannot be raced. A bucket expires when it would be
full again, so an idle user costs nothing. A Redis that is flushed gives every bucket back full. With
no Redis (`KEYSTONE_REDIS_URL` empty) the buckets are in the process. Because the time comes from
Keystone and not from Redis, two processes whose clocks differ disagree a little: a bucket does not
refill for time that went backwards. A Redis that cannot be reached denies the call, as it does for
the session state, and never lets it through without a limit.

The compose stack sets limits far above what the smoke scripts and the browser test do. The limit
of one user is read from `KEYSTONE_RATE_LIMIT_USER_CAPACITY` and `KEYSTONE_RATE_LIMIT_USER_REFILL`
in the environment of `docker compose` (300 and 50), which `scripts/smoke/phase_8.sh` lowers for its
burst and puts back.

Two limits to know about. A call to a tool that does not exist is refused before it enters the
pipeline and is not counted, so it is not limited either (it is audited). And the proxy for model
calls (KS-806) is not rate limited: a budget caps it.

## Budgets

A runaway agent should be stopped by a number, before the money is spent (KS-805, ADR-0014). A
budget is a limit in dollars for one tenant, one user or one agent over a day or a month:

```yaml
upstreams:
  - id: crm
    # ...
    tools:
      lookup: {cost_per_call_usd: 0.002}      # the price of one call
budgets:
  - {tenant: acme, scope: tenant, window: day,   limit_usd: 25}
  - {tenant: acme, scope: user,   scope_id: olivia, window: day, limit_usd: 5}
  - {tenant: acme, scope: agent,  scope_id: ops-agent, window: month, limit_usd: 200}
```

`scope_id` is a user's id (the token's `sub`) or an agent's (`azp`); a budget for the tenant leaves it
out. A day runs from 00:00 UTC to the next, a month from the first at 00:00 UTC. The file is the only
source: Keystone stores the budgets at each start, changes a limit that changed and removes a budget
that left the file (and logs it). A budget for a tenant that is not under `tenants` stops the start.

**The pre-check** is the budget slot, the third in the pipeline (`gateway/interceptors/budget.py`,
which calls `BudgetService.check` in `metering/budgets.py`). It adds the price of the tool to what
each budget that applies to the caller has spent in its window, and refuses the call if any sum is
over a limit. `projected = spent + cost_per_call_usd`, so a limit of $0.03 allows three calls of a
cent and refuses the fourth. It runs before the dispatch, so the upstream sees no request, and again
after a wait for approval. The budgets are checked tenant, user, agent, and a day before a month, and
the first to fail is reported. A tool with no price is never held, and neither are Keystone's own.

```
[keystone:KS_BUDGET_EXCEEDED] call 01J... over budget: the user's budget of $0.03 a day would be passed by this call ($0.03 spent); it resets at 2026-10-24T00:00:00Z
```

`scope`, `window`, `limit_usd`, `spent_usd` and `resets_at` are in the metadata of the text block,
and as `keystone/...` in the metadata of the result. The audit record says deny from the source
`budget`, with the reason `budget:<scope>:<window>`, and the call is not dispatched.

**The metering slot** is the last, and it runs after the upstream answers (`gateway/interceptors/
metering.py`). A call that was dispatched and came back with a result, an error result included, is
charged the price of its tool: `ctx.cost_usd` (the audit record's `cost_usd`), a row in `spend_ledger`,
the counters of the budgets that apply, and the session's `spent_usd` (`keystone__whoami` shows it).
A call that never reached the upstream is not charged. The row is written once for a call id.

**Where the numbers live.** `spend_ledger` (Postgres) is the record: `ts` (the moment the call began,
which decides its window), the tenant, user and agent, `kind` (`tool` or `llm`), `ref` (the call id or
the id of a model request), and for a model `model`, `input_tokens` and `output_tokens`, then
`cost_usd`. The application's role may add rows and read them and nothing else. The counters are
Redis strings, `ks:spend:{tenant}:{scope}:{id}:{window}:{start}` (a colon in an id is written `%3A`),
that expire a day after their window. They are a cache of the ledger: they are set from it at each
start, and one that is missing when a check needs it is read from the ledger then. A Redis that
is restarted or flushed, with Keystone running or not, does not give anyone their spend back.

```
docker compose -f deploy/docker-compose.yml exec postgres psql -U keystone -c \
  "SELECT ts, user_id, kind, ref, cost_usd FROM spend_ledger ORDER BY ts DESC LIMIT 10"
docker compose -f deploy/docker-compose.yml exec redis redis-cli --scan --pattern 'ks:spend:*'
```

**What it does not do.** The check is not a reservation: calls checked together see the same spend,
and a cap is overshot by at most the price of the calls in flight at once. A charge goes to the
window its call began in. There is no refund and no way to change a budget without the file. A
priced call that cannot be recorded (Postgres is away) has its output withheld, since the slot
fails after the dispatch, and the audit record shows the price it should have had.

`GET /admin/api/v1/budgets` lists the tenant's budgets with `limit_usd`, `spent_usd` (what the check
reads), `window_start` and `resets_at`, and the console's Budgets page draws them. The local stack
prices `echostd__echo` at a cent, and gives lena three cents a day and acme $25 a day.

## LLM proxy

Model requests can go through Keystone, so that they get the identity, the budget and the tracing of
a tool call and one place answers "what did this agent cost?" (KS-806, ADR-0016). It is off until
`llm_proxy.enabled` is true.

```yaml
llm_proxy:
  enabled: true
  tenant: acme                        # whose provider keys these are; needed with more than one tenant
  pricing_file: /etc/keystone/pricing.yaml
  anthropic: {base_url: "https://api.anthropic.com", api_key_env: ANTHROPIC_API_KEY}
  openai: {base_url: "https://api.openai.com", api_key_env: OPENAI_API_KEY}
```

**Prices come first.** `pricing.example.yaml` shows the shape of `pricing.yaml`, with numbers that
say on every line that they are not real. Copy it, open each provider's pricing page for each model
you let your agents use, and write the real prices in. Keystone does not know them and does not
guess: it stops at start if the file is missing, and refuses a request for a model that is not in
it. Prices are US dollars for each million tokens (`input_per_mtok`, `output_per_mtok`, and
optionally `cache_read_per_mtok` and `cache_write_per_mtok`; a cache price left out is the input
price), and a name that ends in `*` covers a family. The file is read at start: after a change,
restart. Keep it current, because a price that is too low under-counts spend and nothing can tell.

**The keys** are read from the variables the config names at each start and stored in the vault,
encrypted, as the static credentials of the pseudo-upstreams `llm_anthropic` and `llm_openai`. A
variable that is not set leaves the stored key alone, so a key put there by hand stays. The rows
exist from the first start with the proxy on, and then `keystone cred` can replace a key:

```
keystone cred set --upstream llm_anthropic --header x-api-key --from-env ANTHROPIC_API_KEY
printf 'Bearer %s' "$OPENAI_API_KEY" | keystone cred set --upstream llm_openai --header Authorization
keystone cred list
```

Anthropic takes its key in `x-api-key` and OpenAI as `Authorization: Bearer <key>`, and the proxy
sends whatever header the vault holds, so the value stored for OpenAI starts with `Bearer `.

The two ids are reserved and their rows are disabled, so they are never synced, probed or listed
as upstreams. A key is never returned, logged or put on a span. A request to a provider with
`api_key_env` set and no key stored is refused with 503 `KS_PROVIDER_KEY_MISSING` before anything is
sent. Disabling the proxy later does not remove the stored keys; replace them, and revoke them at
the provider if they should be gone.

**Pointing an agent at it.** The agent uses its Keystone token as the API key, and the SDK's base
URL is Keystone's:

```
export ANTHROPIC_BASE_URL=http://localhost:8080/llm/anthropic   # the SDK adds /v1/messages
export ANTHROPIC_API_KEY=$(scripts/get_token.sh olivia ops-agent)
export OPENAI_BASE_URL=http://localhost:8080/llm/openai/v1      # the SDK adds /chat/completions
export OPENAI_API_KEY=$(scripts/get_token.sh olivia ops-agent)
```

The token is checked as it is for `/mcp`: sign-in, the agent list, the tenant. It may be the bearer
token or `x-api-key`. Only agents of `llm_proxy.tenant` may use the proxy (403 `KS_DENIED` for
others). A token lasts as long as the identity provider says, and an SDK that is not given a
fresh one will start to get 401 when it expires.

**What a request goes through.**

| Step | Refused with | Status |
|---|---|---|
| The token | `KS_UNAUTHORIZED`, `KS_FORBIDDEN`, `KS_UNAVAILABLE` (keys unreachable) | 401, 403, 503 |
| The tenant | `KS_DENIED` | 403 |
| The body: JSON object, `model`, `stream`, size, no `content-encoding` | `KS_INVALID_REQUEST`, `KS_REQUEST_TOO_LARGE` | 400, 413, 415 |
| The model has a price | `KS_MODEL_NOT_PRICED` (unless `allow_unpriced`) | 400 |
| `X-Keystone-Session`, when sent | `KS_SESSION_NOT_FOUND`, `KS_SESSION_MISMATCH` | 404, 403 |
| The budgets, against the estimate | `KS_BUDGET_EXCEEDED`, or `KS_UNAVAILABLE` when they cannot be read | 402, 503 |
| The provider's key | `KS_PROVIDER_KEY_MISSING`, `KS_UNAVAILABLE` | 503 |
| The provider | its own status and body, or `KS_UPSTREAM_ERROR`, `KS_UPSTREAM_TIMEOUT`, `KS_UNAVAILABLE` (too many in flight) | as it answers, 502, 504, 503 |

Keystone's refusals are JSON: `{"error": {"type": "keystone", "code": "KS_BUDGET_EXCEEDED", "message":
"...", ...}}`, with the facts beside the code (`scope`, `window`, `limit_usd`, `spent_usd`,
`estimate_usd` and `resets_at` for a budget). A refusal is 402 and not 429 on purpose: SDKs retry
429 and 5xx. The estimate that the budget is checked against is the body at four bytes a token as
input, plus `max_tokens` of output (4096 when the request does not say; `n` answers for OpenAI).
It is deliberately the most the request could cost, so a request with a very large `max_tokens`
can be refused when a smaller one would not be. Nothing is held: the check is not a reservation
(ADR-0014).

**What it books.** When an answer ends, and before its last byte is sent, one row goes into
`spend_ledger` with `kind = 'llm'`, `ref` the request id (the `x-keystone-request-id` header of the
answer), the model the caller asked for, the tokens and the cost, counted against the same budgets
as tool calls. The cost is the provider's own token count times the price, and cached tokens are
priced apart. The counters, the session (when linked) and the metric follow:

```
docker compose -f deploy/docker-compose.yml exec postgres psql -U keystone -c \
  "SELECT ts, user_id, model, input_tokens, output_tokens, cost_usd FROM spend_ledger
   WHERE kind = 'llm' ORDER BY ts DESC LIMIT 10"
curl -s localhost:8080/metrics | grep keystone_llm_tokens_total
```

`keystone_llm_tokens_total{tenant,model,direction}` has `direction` `input`, `output`, `cache_read`
or `cache_write`, and `model` is the name of the entry in the price list that applied (a family
name for `some-family-*`), or `unpriced`. Each request is a `keystone.llm_call` span (it continues
a `traceparent` the caller sends) with `gen_ai.system`, `gen_ai.request.model`,
`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `keystone.cost_usd` and
`keystone.outcome`, and a log line `llm_request` with the same, the request id and a hash of the user.

**Streams** reach the caller byte for byte as the provider sends them. An OpenAI stream is asked to
report its usage (`stream_options.include_usage`), because OpenAI says nothing otherwise, and the
caller's stream then ends with one more chunk, with an empty `choices` list. A stream that ends
without the provider's final count, or that is cut, or that the caller leaves, is booked for the
tokens that were counted and logged as `llm_usage_incomplete` with a `reason` (`partial_usage`,
`no_usage`, `cut`, `client_gone`). A caller that hangs up on an answer that is not a stream is
still charged: the proxy reads the rest of it. `llm_booking_failed` in the log means a request was
answered and could not be written to the books; the line has the request id, and the cost is in
the `llm_request` line next to it.

**The local stack** forwards both providers to the fake model API (`examples/fake_llm`, the service
`fake-llm` on port 8199, which wants the key `FAKE_LLM_API_KEY`) and prices it with fake prices
(`deploy/pricing.compose.yaml`). A request for `fake-model` with a prompt of four words and a
reply of twelve costs $0.000192. The model name picks a behavior, as the docstring of
`examples/fake_llm/server.py` says: `fake-model-cached` adds cache tokens, `fake-no-usage` leaves
the usage out of a stream, `fake-cut` breaks one, `fake-error-429`, `fake-error-500` and
`fake-error-echo-key` fail, and `fake-slow` is slow. `bash scripts/smoke/phase_8.sh` uses it.

**What it does not do.** It applies no access policy (any agent of the tenant may call any priced
model, within its budgets), it is not rate limited, it writes no `audit_events` row, it does not
log prompts or answers, there are no refunds, and a tenant cannot have a provider key of its own.
The cost is the tokens: a provider's charge for anything else, such as a search tool billed for each
use, is not counted.
Only chat requests of the two APIs exist: the other endpoints of a provider are not proxied.

## Sessions

Each MCP session has a state (flags, taint, call count, spend) stored as a Redis hash under
`ks:sess:{session id}`. `redis-cli HGETALL ks:sess:<id>` shows it: `session_id`, `principal` (JSON)
and `created_at`, then `flag:<tag>` for each flag, `tainted`, `call_count` and `spent_usd` once
they are set. The key lives 24 hours from its last use: reading a session and every change to it
restart the clock. Postgres holds one `sessions` row per session, written when the session opens,
as the durable reference that audit records will point at.

A session changes by merging (ADR-0015). Flags are only added, the taint is only set, and the
counters only go up, so a call that was held for approval cannot write an old copy over what a
call in the meantime recorded. Deleting the key is the only way to clear a taint, and the next
call of that MCP session then starts with a clean state. A key in the format of v0.6.0 (a JSON
string) is not read: Keystone makes a new session over it.

The row's `final_flags` and `tainted` are merged too (union, and never back to false). A flag or
the taint that is new is written to the row at once, and `last_seen_at` at most once a minute per
session. A write to the row that takes longer than 2 seconds is given up and logged as
`session_row_not_touched`; the next write brings the row up to date.

If Redis cannot be reached, a call is refused with `KS_DENIED` ("session state is unavailable") and
audited, because a call must not run without the flags and taint of its session. If Postgres
cannot write the row, the call goes ahead and the failure is logged. A request that names no MCP
session id gets a throwaway state that is never stored. Redis database 15 belongs to the tests;
they empty it.

A session is bound to the principal that opened it. When `initialize` creates the session,
Keystone records the tenant, the user and the agent of the token next to the new session id,
before the client learns the id. Every later request that names the session must carry a token
with the same three values, or it gets 403 `session belongs to another principal`. A different
token for the same principal (a refreshed one, with changed groups) is fine, and each call is
decided on the groups of its own token. A session id Keystone has no binding for gets 404, which
makes a client start a new session; it is never adopted by whoever names it first. The binding
is kept in the gateway process, like the SDK's own sessions, so it does not depend on Redis
being up.

## Scanner

Tool output is untrusted text: an email, a web page or a file can carry an instruction for the
agent that reads it. The scanner reads the output of a tool and says how much it looks like such an
instruction (ADR-0011). The pipeline runs it on the output of every tool of an upstream
(`scanner.enabled`, on by default), before the agent sees the output.

The rules are in `src/keystone/defense/rules.py`, seven of them, each with a weight. A text that
breaks several gets `1 - (1 - w1) * (1 - w2) * ...`, the chance that at least one hit is real.

| Rule | What it looks for | Weight |
|---|---|---|
| `instruction_override` | "ignore all previous instructions", also in Spanish, French, German, Portuguese and Italian | 0.6 |
| `role_spoof` | a line that starts `system:` or `assistant:`, a `### System` heading, chat template tokens, `<system>` and `[SYSTEM NOTICE]` | 0.5 |
| `hidden_unicode` | tag characters, bidirectional overrides, word joiners, and zero-width characters between letters of the same script | 0.9 |
| `tool_directive` | "call the send_email tool", "send ... to someone@host", "transfer ... to account" | 0.4 |
| `secrecy` | "do not tell the user", "secretly", "without telling", "do not ask for confirmation" | 0.5 |
| `markdown_exfil` | a markdown image or link whose address has a query longer than 32 characters, or an image on a host that is not allowed | 0.7 |
| `encoded_payload` | a base64 run of more than 200 characters (0.2), and 0.5 more when it decodes to text that breaks another rule | 0.2 |

A score under `scanner.thresholds.suspicious` (0.5) is `benign`, from `injection` (0.85) up it is an
`injection`, and in between it is `suspicious`. One weak rule on its own stays benign, which is
why the weights of `tool_directive` (0.4) and `encoded_payload` (0.2) are what they are.

What the scan does to the text first: invisible characters are taken out and the rest is
normalized (NFKC), so a zero-width space inside a word or fullwidth letters do not hide a phrase.
A tool result that is JSON is read as the strings in it, because there a line break or a quote is
written with a backslash and a reader undoes that. Images are not read; they are counted.

### What happens to a flagged output

An output that scores `suspicious` or `injection` is handled by the risk of the tool that made it
(`scanner.actions`, one value for each of `low`, `medium`, `high` and `critical`):

| Action | Default for | What the agent gets |
|---|---|---|
| `annotate` | low, medium | A warning block in front, then `<<<untrusted>>>`, the upstream's blocks as they were, then `<<<end untrusted>>>` |
| `redact` | high | The same, with the invisible characters and the leaking images and links cut out of every text, resource and structured value first |
| `block` | critical | Only `[keystone:KS_OUTPUT_BLOCKED] output withheld (score 0.93, rules: ...). Call id <id>.`, as an error |
| `pass` | none | The output as it was. The score is still recorded |

A benign output is never changed: the agent gets what the upstream sent, byte for byte.

The scanner cannot crash a call. If the classifier raises, the rules alone decide and the result
says `model: "error"`. If the rules raise, the output goes through as it is, the scan says
`action: "error"` (the audit row's `scan_action`), and nothing is flagged. If an action raises on
an output that was flagged, the output is withheld. Each one counts in
`keystone_scan_errors_total{stage}` (`classifier`, `rules` or `action`) and logs
`scanner_classifier_failed`, `scanner_rules_failed` or `scanner_action_failed` with the name of the
exception and never the text that was being read.

### Flags, taint and the audit record

Two slots of the pipeline use the scan, in this order (KS-704, ADR-0011):

| Slot | What it does after a call | Where you see it |
|---|---|---|
| `output_scan` | Scans the output, applies the action for the tool's risk, and writes the scan on the call. An output that scores `injection` (0.85 and up) **taints the session**, whatever the action did to it and whatever the tool's tags are | the audit record's `scan_score` and `scan_action`; `keystone_scan_score`; `keystone_sessions_tainted_total` |
| `session_flags` | Adds the tags `reads_untrusted` and `reads_sensitive` of the tool to the session's flags and counts the call | `keystone__whoami`; the session's Redis hash; the approval card; `context.session_flags` in a policy |

What gets left out:

- Keystone's own tools (`keystone__whoami`, `keystone__await_approval`) are neither scanned nor counted.
- An error result from an upstream is scanned, because the text of an error can quote what an
  attacker wrote, and it can taint. It adds no flag and is not counted: a call that returned nothing
  read nothing.
- `external_effect` and `code_exec` are not recorded as flags. The Rule of Two reads those off the
  tool being called.
- With `scanner.enabled: false` nothing is scanned and the audit record has no scan (`scan_score`
  and `scan_action` are empty, which is not the same as `pass`). Flags and the call count still
  work.

`scan_action` in the audit record is one of `pass`, `annotate`, `redact`, `block` or `error`.
`error` is a scan that could not be made: the output went through as the upstream sent it, and
`keystone_scan_errors_total{stage="rules"}` went up. Read `scan_score` with the label thresholds
in mind: 0.5 is `suspicious`, 0.85 is `injection`.

The taint and the flags are recorded with the session store's own atomic changes, so a call held
for approval cannot write an old copy of the session over what another call recorded (ADR-0015).
A call sees them from the next call on. A call that is already past the policy slot when the
taint lands is not stopped by it. A client that opens a new MCP session starts with a clean one.
If the session store cannot record a taint or a flag, the output is withheld (`KS_OUTPUT_BLOCKED`,
audit outcome `error`): an output that was found to be an injection and could not be recorded as
one does not reach the agent.

### The classifier

Behind the rules there is a model, `protectai/deberta-v3-base-prompt-injection-v2` by default
(Apache-2.0, English only), which scores the same text between 0 and 1. It is the optional extra
`keystone[scanner]` (torch for the CPU and transformers), and the compose image has it. How its score
and the rules' make one is `scanner.join` (ADR-0011):

- `rules_first`, the default: a text whose rules score is at `thresholds.suspicious` (0.5) or more
  keeps that score and is not given to the model (the scan's `model` says `skipped`). For any other
  text the score is `1 - (1 - rules) * (1 - model_weight * model)`, with `model_weight` 0.7. The model
  can raise a score and never lowers one. A sure model makes a text `suspicious` (at 0.714 sure or
  more) and cannot make it an `injection`, so **only the rules taint a session**.
- `max`, what Phase 7 shipped: the higher of the two, and the model reads every text.

The model reads a long text in windows of `scanner.window_tokens` (128) tokens that overlap by
`scanner.window_overlap` (64), and the score is the highest window. On the dev split the model alone
flags 37 percent of the documents with an attack with windows of 510 tokens and 64 percent with
windows of 128, which is why they are short. A text of N tokens costs N/64 windows, and a text of more
than 32 windows is sampled across its length.

```bash
uv sync --extra scanner                  # in a checkout; the first use downloads about 740 MB
uv run python -m keystone.defense.classifier fetch    # or fetch the model now
docker build --build-arg WITH_SCANNER=1 .             # an image with the extra and the model in it
KEYSTONE_SCANNER_CLASSIFIER=none make up              # compose without the model
uv run pytest tests/integration/test_classifier_real.py   # the one test that loads the real model
```

Without the extra the gateway still starts and the scanner runs on its rules alone; it logs
`scanner_classifier_unavailable` once at start, naming what is missing. A scan waits at most
`scanner.classifier_timeout_ms` (300) for the model. A model that has not answered by then, or is
still loading, leaves the rules' score, and the result says `model: "timeout"`. At 300 ms the model
reads about 1,500 characters on a laptop with windows of 128 tokens (3,500 with windows of 510), so
a longer output is judged by the rules alone. Raise the timeout to let the model read more, at that
much more time on each such call, and measure it (`scripts/bench_scanner.py --classifier`,
`docs/spikes/scanner.md`). On the test split 12 percent of the scans fell back to the rules at 300 ms.
The model also has a limit on how many scans run in it at once. A scan that finds every place taken
does not queue: the model is left out of it, the rules decide, and the result says `model: "busy"`
(KS-992). The limit comes from the CPUs the process may use, a container's limit counted, keeping
one for the event loop: 1 scan at a time with the other CPUs as threads below 5 CPUs, 2 scans from
5. `scanner.classifier_concurrency` and `scanner.classifier_threads` set them. Without a limit, 200
sessions of calls gave the model every core of a 4 CPU container, the event loop starved, the
health probes of the upstreams timed out and calls failed with `upstream echo is down`.
The image sets `HF_HUB_OFFLINE=1`: the model is in it, and the container never goes to the network
for it.

The gateway loads the model in the background when it starts (`scanner_classifier_ready` in the
log when it is done, `scanner_classifier_not_ready` when it cannot, and the gauge
`keystone_scanner_classifier_ready{classifier}` at `/metrics`, 0 until it has loaded and 1 after),
so only the first seconds of a run are scored by the rules alone. A measurement of the model waits
for the gauge. `keystone_gateway_info` carries the model that was built, `classifier="none"` where
there is none. An app under test (`env=test`) does not load it in the background, and loads it at
its first scan.

`prompt-guard-2-86m` (Llama Prompt Guard 2) is gated on Hugging Face: accept its license with an
account, and give the gateway a token. Its labels are not verified here (ADR-0011).

What it does not do. The rules are patterns and understand nothing: a phrase nobody listed, or a
language the list lacks, is not seen, and the same holds for a text that explains an attack
instead of making it (it can score high). Python regular expressions hold the interpreter while
they run, so a scan of 200,000 characters (the limit) keeps the gateway busy for about 20 ms.
`scripts/bench_scanner.py` measures it, and `docs/spikes/scanner.md` has the numbers.

### Measuring the detector

`eval/detector/` measures how well the scanner tells an injection from a harmless text (KS-707). It
runs on a dataset that is fixed and checked by hash, and what it measures goes to
[results.md](results.md) with its date and commit. `eval/DATASETS.md` says where every part of the
data comes from and under what license.

```bash
uv sync --extra scanner --extra eval                  # the model, and pyarrow for the public data
uv run python -m eval.detector.datasets build         # build the dataset and check it
uv run python -m eval.detector.run --config rules --split dev --summary     # the rules: seconds
uv run python -m eval.detector.run --config combined --split dev            # with the model
uv run python -m eval.detector.tune --config combined --scores /tmp/dev.jsonl   # thresholds, on dev
uv run python -m eval.detector.combine windows --shape 128/64    # the model's score of every window of dev
uv run python -m eval.detector.combine sweep --out eval/results/combination-dev-<date>.json
uv run python -m eval.detector.report --note "why"    # all of test; writes the report
uv run python -m eval.detector.report --render eval/results/detector-<date>.json   # the words again
```

- **The data** is 1,892 texts: 662 public prompts (`deepset/prompt-injections`), 1,080 documents
  (360 carriers, each once as it is and twice with an attack put in it, a quarter of the attacks
  hidden) and 150 hard negatives, harmless texts that sound like orders. They are split in two by
  carrier: `dev` is 919 texts and `test` is 973. The public parts are downloaded at a pinned
  revision and kept in `eval/data/`, which is not committed. When the download fails, or pyarrow is
  not installed, the build is without them and says so in its first lines, in the JSON and in the
  report.
- **The manifest** (`eval/detector/manifest.json`) has the sha256 of every text. A text that
  differs stops the run with `DatasetChanged`, naming the first five. A change of a template, a
  sentence bank or the seed changes texts: `python -m eval.detector.datasets manifest` writes the
  new manifest, and after that every earlier number is about other data, so tune on dev again and
  run the report again.
- **The test split** is for the numbers that are published. Thresholds are tuned on dev only
  (`tune.py` refuses another split). Every run that scores test, `run --split test` or `report`,
  adds a line to `eval/results/test-runs.jsonl` with the time, the commit, whether the tree had
  uncommitted changes, the number of texts and the headline numbers, and the report lists those
  lines. Say why with `--note`.
- **Run the report on a clean tree and a quiet machine.** It records the commit and whether the
  tree was clean, and it times one text at a time, so another job on the machine shows up in the
  timings. It scores the test split in three passes of the scanner (as it is set, the model alone at
  the same windows, and as Phase 7 shipped it) and took 16 minutes on a 10-CPU Mac with nothing else
  running. Before KS-792 it was one pass and took 3 min 40 s and 4 min 42 s; the model is nearly all
  of the time, and two runs gave the same classification numbers and timings that differed by 20 to
  45 percent.
- **The sweep on dev** (`eval/detector/combine.py`) is how a join or a window is tried. `windows` scores
  every window of the dev split in one shape and keeps the scores in `eval/data/` (about 8 minutes for
  each shape), and `sweep` tries every join on them in seconds and writes the record that the report
  quotes. It refuses the test split, and a test holds the defaults of `scanner` equal to the candidate
  the latest record chose.
- **Nightly**, the workflow scores 200 texts of dev with the rules alone and no model. It fails when
  the data differs from the manifest or when the ROC AUC of that sample is under 0.7, which is a
  guard against a scanner that stopped working and not a result.
- **The slow tests** (`tests/integration/test_detector_real.py`, run by `make gate`) download the
  datasets for real, build again from the cache with the network refused, and score a few texts with
  the real model.

What the numbers do not say is the last section of `docs/results.md`. The attacks of the documents
are the templates of this repository, written alongside the rules, so the public prompts are the
independent check.

## Performance

`eval/perf` (KS-903) measures what the gateway adds to a call, and where the time goes. It needs the
stack up (`make up`) and a machine with little else running on it.

    make perf-smoke       # 10 sessions x 5 calls, the echo upstream and the stack as it runs
    make perf             # the full matrix: about an hour on a laptop; keep the machine awake
    uv run python -m eval.perf.report         # write the section of docs/results.md

On a laptop run the matrix under `caffeinate -i` (macOS) or `systemd-inhibit` (Linux): a sleep in
the middle of a run stops the clocks of the containers and the numbers with them.

The matrix has five targets: the echo upstream alone (port 8104, the API key of the stack), and
Keystone in four settings of one build, each made by restarting the keystone service with
`deploy/perf.override.yml` and `PERF_PROFILE`, `PERF_SCANNER` or `PERF_CLASSIFIER`: passthrough,
full with the scanner off, full with the rules alone, and full with the classifier. The override
limits the container to 4 CPUs and 4 GB, sets the log level to warning, turns the sandbox off
(its health check holds the event loop for a few milliseconds) and raises the rate limits to the
largest the settings take, so that no call is refused and every slot still runs. `keystone serve`
runs one uvicorn worker on one event loop, and there is no setting for more: every call of a run
shares it. Before it measures a target the matrix reads `keystone_gateway_info` at `/metrics`,
refuses a gateway that is not what the target says, waits for the model to load where there is one,
and waits until the host is at least 85% idle over two seconds (it says so in the result if the
host never was).

N sessions (200) open at once and each makes M calls (20) of the echo tool one after the other with
a payload of S bytes (1 KB and 8 KB) of plain English. After three calls a session that are not
counted, the timed calls start together. A call is timed from the request to the whole answer. A
call that fails is counted in the error rate, by what Keystone answered, and left out of the
percentiles: a gateway that refuses a call quickly would otherwise look faster the more it failed.
`eval/perf/load.py` shares the sessions out over four processes, because one process that runs
200 clients is itself slow and puts its own time into every latency, and it records how busy each
process was. A token of the local realm lives five minutes, so each process gets its own and a new
one every two minutes. A run that lasts ten minutes stops making calls and says so.

For each target and payload there is a second run with one session making 200 calls, so that
nothing waits for another call. The difference between the two is the queue. The gateway is
restarted for each payload, and the run with one session comes first and warms it, so that what one
run did to the process (a pool used up, a session lost) is not in the next. While a run is made the
matrix also reads the log of the container, and counts the events logged at warning level or above
by name and error, which is how a failure is traced to its cause.

The gateway counts the time every call spends in each stage of its pipeline
(`keystone_tool_call_duration_seconds{stage}`: `total`, `upstream`, and each of the nine slots). The
matrix reads those counters just before the timed calls and just after, and the mean of each stage
is that of the calls that were timed. It also samples `docker stats` for the container while they
are made. The result is `eval/results/perf-<date>.json`, with every latency, and a file is never
written over. The report names the file, the commit and the machine (CPU model, vCPUs, memory,
Docker, the VM Docker runs in), and `python -m eval.perf.report --check` fails when
`docs/results.md` is not what the file renders.

## Audit

Every tool call leaves one row in the `audit_events` table: who (tenant, user, agent, session),
what (the tool), what was decided (`effect`, `decision_source`, `reasons`, `policy_version`),
what happened (`outcome` `ok`, `rejected` or `error`, `reject_code`, `dispatched`), what it cost,
how long it took, and the hash chain. A call that Keystone refuses before it enters the pipeline
(a tool that does not exist) has a row too. Rows are only ever added.

Each row holds the hash of the row before it, and its own hash covers that and every other column.
Changing a row changes its hash, and removing one breaks the link after it. The chain is the same
across several Keystone processes: each batch takes a Postgres advisory lock, reads the last hash
and extends it. ADR-0009 has the rules and what the chain does not prove.

The pipeline hands the row to a writer and goes on. The writer takes up to 200 rows or 50
milliseconds at a time and writes each batch in one transaction. What it does when that fails:

| What went wrong | What the writer does | What you see |
|---|---|---|
| The database is down, slow or refuses the connection | Keeps the batch and everything behind it, in order, and tries again after 0.2 s, doubling to 3 s | `audit_flush_failed` in the log, `keystone_audit_failures_total{reason="flush_failed"}` rising |
| The database refuses one record (a constraint or a type) | Halves the batch until that record is alone, drops it, writes the rest | `audit_record_dropped` with the call id, `reason="record_dropped"` |
| The queue (10,000 records) is full for 5 seconds | Refuses the new record | `audit_queue_full`, `reason="queue_full"` |
| Keystone stops | Flushes the queue, for 10 seconds at most | `audit_shutdown_dropped` and `reason="shutdown_dropped"` for whatever is left |

A process that is killed loses the rows it had not written, at most the last 50 ms of calls.

A row keeps the arguments of the call, masked, and the sha256 of the original ones. A key that
looks like a secret (`secret`, `token`, `password`, `api key`, `authorization`) or is listed in
`audit.redact_keys` has its value replaced by `[redacted]`. In strings, payment card numbers,
US social security numbers, bearer tokens, AWS access key ids and private key blocks are masked,
and a string over 2,048 characters is cut to 256 characters and its sha256. The patterns are a net
with holes; list the keys of any field you know is sensitive. To prove what a call sent, hash the
canonical JSON of the original arguments (sorted keys, no spaces) and compare it with `args_digest`.

The writer is unhealthy when its queue is over 90% full or a flush failed less than 5 seconds ago.
With `audit.fail_closed` on, which is the default outside `dev`, an unhealthy writer makes the
pipeline refuse each call before it runs an interceptor: `KS_DENIED`, "audit unavailable", with
`keystone/reason: audit-unavailable` in `_meta`, and a row for the refusal once the writer can
take it. In `dev` the call goes ahead and the failure is counted.

### Checking and exporting the log

`keystone audit verify` reads every row in `seq` order and recomputes the hashes from what Postgres
returns. It prints `OK, 42 records` and exits 0, or `broken at seq 10: hash mismatch` (a row was
edited, or its link to the row before it was) or `broken at seq 5: gap` (a row is missing) and
exits 2. `--from-seq N` starts at record N, and trusts the stored hash of record N-1 as the anchor
without checking that record, so it says nothing about the records before N.

```bash
docker compose -f deploy/docker-compose.yml exec keystone keystone audit verify
```

`keystone audit export [--since T] [--until T] [--tenant ID]` writes the records as JSON lines to
standard output, from `--since` (inclusive) up to `--until` (exclusive), as dates or times
(`2026-10-01`, `2026-10-01T12:00:00Z`; UTC unless the time says otherwise). A line holds the
columns of one record in the form its hash covers, so whoever receives the file can check it with
a sha256 and a JSON library: the hash is the sha256 of the previous hash (as bytes) followed by the
canonical JSON (sorted keys, no spaces) of the line without `seq`, `prev_hash` and `hash`. A tenant's
export has gaps in `seq`, because the chain runs through every tenant's records; each line still
proves itself.

What verify cannot see: a log that was cut short (the newest rows deleted) is still a whole chain,
and so is one whose every row and hash was rewritten. Publish the latest hash somewhere out of
reach to close both (ADR-0009).

### Database roles

Migrations run as the role that owns the tables. Keystone runs as `keystone_app`, which the
migration `0006` creates (`CREATE ROLE ... LOGIN`, with `KEYSTONE_APP_DB_PASSWORD`). It may select,
insert, update and delete in every table, and on `audit_events` it may only insert and select, so a
compromised gateway cannot edit or delete what it logged. Tables that later migrations create are
open to it by default privileges. It has no access to `alembic_version`. A role belongs to the
Postgres cluster, not to one database, so the migration leaves an existing `keystone_app` as it is:
change its password with `ALTER ROLE keystone_app PASSWORD '...'`, and change the password in
`KEYSTONE_DATABASE_URL` with it. The owner, and any Postgres superuser, can still change the log;
that is how the Phase 5 smoke shows verify catching an edit.

The rows are read through the admin API (`GET /admin/api/v1/audit`), through
`keystone audit export`, or with `psql` as the database owner:

```bash
docker compose -f deploy/docker-compose.yml exec postgres psql -U keystone -d keystone \
  -c "SELECT seq, tool_name, effect, reasons, outcome FROM audit_events ORDER BY seq DESC LIMIT 10"
```

## Tracing

With `KEYSTONE_OTLP_ENDPOINT` set (compose points it at Jaeger), every tool call is one trace, and
Jaeger shows it at http://localhost:16686 under the service `keystone`. The root span is
`keystone.tool_call` (kind server). Under it are one `keystone.interceptor.<name>` span for each
hook of each interceptor (`keystone.hook` says `before_call` or `after_call`) and
`keystone.upstream.call` (kind client, with `keystone.upstream`). The audit row of the call holds the
trace id.

The root span carries:

| Attribute | Value |
|---|---|
| `gen_ai.operation.name` | `execute_tool` |
| `gen_ai.tool.name`, `gen_ai.tool.call.id` | the tool, and the call id |
| `keystone.tenant`, `keystone.agent` | the tenant and the agent of the token |
| `keystone.user_hash` | the first 12 hex characters of the sha256 of the user id |
| `keystone.decision.effect`, `keystone.decision.reasons` | what the policy decided, once it has |
| `keystone.outcome`, `keystone.reject_code` | `ok`, `rejected` or `error`, and the code that refused the call |

No span holds a raw user id or an argument value, and no exception is recorded on one, because its
text can carry either. A failed stage is a span status with fixed text. The user hash lets you
match two traces of one user; it is not secret, since anyone with a list of user ids can hash it.

A request that carries a W3C `traceparent` header is continued: the root span is a child of it, in
the same trace. A header that cannot be read is ignored and the call starts a trace of its own. The
call's `traceparent` (and `tracestate`) also go to the upstream in the `_meta` of the `tools/call`
request, with the upstream call span as the parent, so an upstream that traces can join. Nothing is
sent when tracing is off. Spans are sent in batches every second; a collector that is down costs
nothing but the spans.

## Metrics and the dashboard

`GET /metrics` serves the Prometheus text format. It needs no token, because a scrape sends none,
and it holds no user, session or argument: keep it off the public network all the same. Compose
runs Prometheus (http://localhost:9090) with a job that scrapes `keystone:8080/metrics` every 5
seconds, and Grafana (http://localhost:3000, user `admin`, password `admin`) with the dashboard
**Keystone** in the folder of the same name, loaded from `deploy/grafana/dashboards/keystone.json`.
Edit the file, not the UI: the provisioned dashboard is read-only.

| Metric | Labels | What it counts |
|---|---|---|
| `keystone_tool_calls_total` | `tenant`, `tool`, `effect`, `outcome` | Every call, by what the policy decided (`allow`, `deny`, `require_approval`, or `none` when nothing decided) and how it ended (`ok`, `rejected`, `error`) |
| `keystone_tool_call_duration_seconds` | `stage` | A histogram. `total` is the whole call. Other stages are an interceptor (`policy`, `pinning`, ...), observed once for each of its hooks, and `upstream` |
| `keystone_rejections_total` | `tenant`, `code` | Calls Keystone refused, by `KS_*` code |
| `keystone_upstream_errors_total` | `upstream`, `kind` | `timeout`, `down` (refused without a try, because the upstream is marked down) or `error` |
| `keystone_quarantined_tools` | `tenant` | Tools held for review, as of the last time the registry read the tenant's tools |
| `keystone_policy_eval_seconds` | none | A histogram of the time the policy engine took, for calls and for tool lists |
| `keystone_audit_queue_depth` | none | Audit records accepted and not yet written |
| `keystone_audit_failures_total` | `reason` | `flush_failed`, `record_dropped`, `queue_full`, `shutdown_dropped`, `not_running` (see Audit) |
| `keystone_scan_score` | `tenant` | A histogram of the score of each output the scanner read, in tenths from 0.1 to 1.0. A scan that failed has no score and is not in it |
| `keystone_sessions_tainted_total` | `tenant` | Outputs that scored as an injection in a session that was not tainted yet (see Scanner) |
| `keystone_scan_errors_total` | `stage` | A scan that failed and was worked around: `classifier`, `rules` or `action` (see Scanner) |

The labels are bounded on purpose. There is no label for a user, a session or an argument: a label
whose values come from callers would give Prometheus a series for each of them, and metrics are
often less protected than logs. A tenant that is not in the config is `other`, an upstream that
is not is `unknown`, and a call to a tool that does not exist is counted under the tool `unknown`,
whatever name the caller made up.

`keystone_approvals_pending{tenant}` counts the approval requests waiting for a decision. The
approval service sets it when it starts and after each request, decision and sweep.

`keystone_rate_limited_total{tenant,scope}` counts the calls a rate limit refused (KS-804), and
`keystone_budget_spent_usd{tenant,scope}` is the highest spend in the current window among the
budgets of one scope (KS-805). `keystone_llm_tokens_total` is set by the proxy for model calls
(KS-806), and its panel shows "no data" until the proxy has served a request.

The dashboard has five rows: Traffic (calls per second by effect, outcome and tool, rejections by
code), Latency (p50 and p95 of the total, p95 by stage, policy evaluation), Upstreams (errors,
quarantined tools), Audit (queue depth, failures) and the later phases. A test checks that every
metric a panel asks for is declared in `telemetry/metrics.py`, and that every label it groups by
exists.

## Admin API

`/admin/api/v1` is the interface the console and operator scripts use. Every route needs a token
with the `admin` role (401 without a token or with a bad one, 403 without the role), except the
`/approvals` routes, which also take the `approver` role. A route added later is for admins until
it is listed as an approvals route (`admin/auth.py`). Every answer is limited to the tenant of the
token: a record, tool or session of another tenant is not
found (404), so the answer does not say it exists. The OpenAPI schema is at
`/admin/api/v1/openapi.json` and needs no token. The app as a whole serves no schema or docs.

| Route | What it does |
|---|---|
| `GET /audit` | Search the audit log, newest first. Filters: `user`, `agent`, `tool`, `effect`, `outcome`, `since`, `until`, `call_id`, `session` (an MCP session id; there is no index on it, so the search reads the tenant's records newest first until it has a page). Pages by `cursor` (a `seq`) and `limit` (1 to 200, 50 by default); `next_cursor` is null on the last page. A page never repeats a record, even while calls are being made |
| `GET /audit/{seq}` | One record |
| `GET /audit/verify?last=10000` | Check the hash chain of the newest records (up to 100,000; `keystone audit verify` checks the whole log). The chain runs through every tenant, so the result is about the whole log |
| `GET /tools`, `GET /tools/{name}` | The tenant's tools, each with its risk, tags, status and `cost_per_call_usd` (a decimal string); a tool's detail with its pending definition, its fingerprint and a diff |
| `POST /tools/{name}/approve-change` | Accept a held definition. The body may carry `expect` (the fingerprint, a prefix will do) and `note` |
| `POST /tools/{name}/disable`, `POST /tools/{name}/enable` | The same as the CLI |
| `GET /upstreams` | Upstreams with status and last sync. A URL is shown without credentials |
| `GET /sessions` | Live sessions of the tenant, read from Redis |
| `GET /policies` | The version in force and the ids of the tenant's policies |
| `POST /policies/reload` | Read the policy files again (see Policies) |
| `POST /scan` | `{"text": "...", "risk": "medium"}`. Scan a text as the output of a tool of that risk and say what an agent would be given: `scan` (the score, the label, the rules that hit, the model and the action) and `content`, the blocks after the action (the text as it came, with a warning, with the hidden characters cut out, or the refusal that stands in for it). It changes nothing, writes no audit record and taints no session. 503 when the scanner is off. An AgentDojo run uses it (`eval/agentdojo/NOTES.md`) |
| `GET /approvals` | The tenant's approval requests in one state: `status` (`pending` by default, or `approved`, `rejected`, `expired`, `consumed`) and `limit` (1 to 200, 100 by default). Pending ones come oldest first. Approver or admin |
| `GET /approvals/{id}` | One request, with the last 10 calls of the session that asked (`recent_calls`, as the audit shows them). Approver or admin |
| `POST /approvals/{id}/decision` | `{"approve": true, "note": "..."}`. Approver or admin. See Approvals |

Approving a change through the API calls the same code as `keystone tool approve-change`, with the
same checks and messages: a stale fingerprint is 409 "changed after it was shown", a tool that is
not held is 409, a tool of another tenant is 404. A refusal has the body
`{"error": "...", "reason": "..."}`.

A token for the admin role comes from `scripts/get_token.sh root keystone-cli`. For example:

```bash
TOKEN=$(bash scripts/get_token.sh root keystone-cli)
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/admin/api/v1/audit?tool=bank__transfer'
```

Browsers may call it from `KEYSTONE_CONSOLE_ORIGIN` only. The CORS rule allows `GET` and `POST`
with the `authorization` and `content-type` headers; it does not allow cookies, because the API
takes a bearer token.

## Console

The console is a React app in `console/` (Vite, TypeScript in strict mode, Tailwind, React Router and
TanStack Query). It is for people: approvers decide requests, and admins read the audit log,
review changed tools and watch spend and live sessions. Agents never use it. It runs on Vite's dev server at
`http://localhost:5173`; there is no production image of it yet. Why React and not a server-rendered
page is in ADR-0013.

```bash
make up                  # Keycloak and Keystone, which the console talks to
cd console
nvm use                  # Node 26, from console/.nvmrc
pnpm install             # pnpm 12, from "packageManager" in package.json
pnpm dev                 # http://localhost:5173
```

Open `http://localhost:5173` (the realm allows that address and not `127.0.0.1`) and the console
sends you to Keycloak. Sign in as `lena` (approver) to see the Approvals page only, or as `root`
(admin) to see Approvals, Audit, Tools, Budgets and Sessions. A user with neither role gets a page that says to ask
for one. The menu only hides what the API would refuse (the
approvals routes take an approver or an admin, every other route an admin); the API makes the real
decision.

| Role | Pages |
|---|---|
| `approver` | Approvals |
| `admin` | Approvals, Audit, Tools, Budgets, Sessions |

### Sign-in

The console is a public Keycloak client (`console`) and signs in with the authorization code flow
and PKCE (S256), through `oidc-client-ts`. The redirect address is
`http://localhost:5173/auth/callback` and the sign-out address `http://localhost:5173/signed-out`;
the realm file allows both.

- **Tokens stay in memory.** Nothing that can be used as a credential goes to `localStorage` or a
  cookie. A reload signs in again, and without a password prompt while the Keycloak session (its
  cookie) is alive. Only the state of a sign-in in progress (the PKCE verifier) goes to
  `sessionStorage`, because it must survive the trip to the sign-in page.
- **The access token is renewed with the refresh token** about a minute before it expires (the
  realm gives it five minutes), and again on demand if a call finds it about to run out. The
  renewal is a `refresh_token` request to Keycloak's token endpoint, which the client's web origin
  allows; there is no hidden iframe, so it does not depend on third-party cookies. A renewal that
  fails does not end the session by itself: the token works until it expires, and then the person
  is sent to sign in. If Keycloak's own session is gone, that sign-in shows the login form.
- **The menu and the header come from the ID token** (`roles`, `tenant`, `name`). The API reads the
  access token, which carries the same claims and the audience `keystone`.
- **Sign-out** ends the Keycloak session (with `id_token_hint`) and returns to `/signed-out`.
- The address after sign-in must be a path of the console: `//host`, `https://host` and a
  backslash are refused (a test covers this).

### Calling the API

The browser calls `/admin/api/v1` on the console's own origin, and the dev server proxies `/admin`
to Keystone (`KEYSTONE_URL`, `http://localhost:8080` by default). There is no cross-origin request,
so the API's CORS rule (`KEYSTONE_CONSOLE_ORIGIN`) is not involved in this setup.

`console/src/api/schema.d.ts` is generated from the API's own schema and is committed. After a
route or a model changes, run `make console-types` and commit the result. The `console` job of CI
runs the same command and fails if the file differs, so the console cannot drift from the API. The
client in `src/api/client.ts` takes its routes, parameters and answers from that file, so a change
that breaks a call fails the build, not a page.

### The approvals page

`/approvals` lists the tenant's pending requests, oldest first, and reads the list again every 5
seconds. The Approvals entry in the menu shows how many are waiting, from any page. A card shows:

- the tool, its risk (the word low, medium, high or critical, with a color and bars) and a red
  "tainted" badge when the session has read untrusted content;
- who asked, through which agent, and when;
- the arguments as the audit log keeps them, sorted by name. A value that was hidden or cut is
  marked, and the card says that the call runs with more than it shows;
- the reasons, which are policy ids and link to that policy's heading in `docs/policies.md`
  (every shipped id has one; a test checks that);
- the session's flags, and the time left in minutes and seconds, counted from the server's figure
  and not the browser's clock;
- the last calls of the session, loaded when the card's list is opened and read again every 5
  seconds while it is. Each row has the scan of its output (`0.88 annotate`: the score and what
  Keystone did to the output), so the call that brought an injection in is the one marked.

Approve takes an optional note. Reject needs one, because the agent is told it. The card leaves the
list at once and comes back if the decision cannot be sent. A 409 (someone else decided it, or it
expired) says "Already decided" and reads the list again. A request the person made has no buttons,
because the API would refuse them (403). The link in the webhook and Slack message,
`/approvals?id=<id>`, scrolls to that request and outlines it.

### The audit page

`/audit` is for admins. It filters by user, agent, tool, session (the id of an MCP session, which the
Sessions page links to), decision (allowed, denied, needs approval), result (ok, rejected, error) and
a time range (local time, sent to the API as absolute times).
Text fields send their filter when the person pauses for 0.3 seconds, and the filters are kept in
the address (`/audit?tool=bank__transfer&effect=deny`), so a filtered view can be sent to someone.
Records come 25 to a page, newest first. The API pages toward older records by cursor, so the page
keeps the trail of cursors and "Newer" goes back along it.

A tool name opens a drawer with the whole record: the decision and who made it, the reasons (links
to `docs/policies.md`), the policy version, the result and its reject code, the arguments as the log
keeps them (the page says when something was hidden or cut), their digest, the scan result, cost and
latency, a link to the trace in Jaeger (built from `trace_id` and `VITE_JAEGER_URL`, and only for a
trace id of hex digits) and the hashes of the chain. Escape closes the drawer and the focus goes
back to the row.

Every page shows an admin the state of the hash chain in the header, from `/audit/verify` (the
newest 10,000 records), read again every minute: a green "Chain verified", or "Chain broken at
record N" in solid red. If the check itself cannot run, the badge says "Audit chain not checked",
which is not a clean result.

### The tools page

`/tools` is for admins. It lists the tenant's tools by upstream with their risk, tags, status and
cost per call (`cost_per_call_usd`, what one call is booked at). A tool that is quarantined has
"Review change": the current and the pending definition side by side (the description by sentence
with the changed words marked, the input schema as JSON in key order), why the tool is held, and any
screening rule the pending description trips. "Approve change" needs a note and sends the
fingerprint of the definition that was read, so one that changed again after the person opened it
is refused (409) and not approved unseen. "Disable" and "Enable" switch an active tool and one an
operator disabled; the API refuses the rest and the console shows what it said.

### The budgets page

`/budgets` is for admins. It draws one bar for each budget of the tenant (`GET /budgets`), in groups:
the tenant's, then each user's, then each agent's, and in each the day before the month. A bar says
what is spent against the limit in dollars (`$0.03 of $0.03`, with the cents kept as far as there are
any: a model request costs `$0.000192`), the share as a percent, and when the window resets, as a
time from now and in UTC (`Oct 25, 00:00 UTC`), because days and months are counted in UTC. The
standing is a word in a badge before it is a color: "within limit", "near limit" (from 80%), "at
limit" and "over limit" (the check is not a reservation, so calls in flight together can pass a
limit by what they cost). A bar is a `progressbar` with its own text value. When any budget is at its
limit, a notice above the list says so. With no budgets the page says where they are set (the config
file); a failed read shows the error with "Try again". The page asks again every 15 seconds.

### The sessions page

`/sessions` is for admins. It lists the tenant's live sessions from Redis (`GET /sessions`, newest
first) with the user and the agent, when it started, its flags, a red "tainted" badge or a green
"clean" one (the word is in the badge), its count of calls and its spend, which includes the cost of
model requests that name the session. A session lives 24 hours from its last use. The user's name is
a link to `/audit?session=<id>`, which opens the audit page filtered to that session's calls; the
whole row is the link's target. The page asks for the newest 100 sessions and says so when it has that many, because
there may be more. It asks again every 10 seconds. With no session it says so.

### The browser test

`make console-e2e` runs `console/e2e/approval.spec.ts` and `console/e2e/budgets.spec.ts` in headless
chromium (Playwright, chromium only). It runs at every phase gate from phase 6 (`make gate PHASE=6`) and in the nightly workflow.
It needs the compose stack and starts it (`docker compose up --build --wait`) when Keystone,
Keycloak and the bank are not answering; a warm run takes about 14 seconds, and one that has to
start the stack takes about 75.

1. `globalSetup` puts the bank at its seed state and starts olivia's scripted agent in the
   background with `examples/agents/scripts/approval_demo.yaml`: a transfer of 900, then
   `keystone__await_approval`. Keystone holds the transfer for 10 seconds
   (`approvals.wait_seconds` in `deploy/keystone.compose.yaml`) and then answers
   `KS_APPROVAL_PENDING`, so the agent is waiting when the test starts. Playwright's `webServer`
   starts the Vite dev server unless one is already running on port 5173 (outside CI).
2. The test signs in as lena on Keycloak's own page (her password is in `.env.example`) and checks
   that the menu holds Approvals only. It finds the card for `bank__transfer` and `invoice 4471`,
   checks the risk, the requester, the amount and the link of the reason, and runs axe-core over
   the page in the light and the dark theme (WCAG 2.1 A and AA and best practices; any finding
   fails the test). It opens the session's recent calls and waits until a call with
   `KS_APPROVAL_PENDING` is listed there. That wait is the point: an approval inside the first 10
   seconds would finish the first call and leave the await tool nothing to do.
3. It approves with a note, sees the card go and the toast, and reads the agent's transcript
   (`console/test-results/approval-agent.txt`): the transfer succeeded, after
   `answered KS_APPROVAL_PENDING; waited for approval <the card's id>`, with the status
   `completed`. Then it reads `/_state` of the bank: one transfer, 900 from CHK-001 to SAV-002.

`budgets.spec.ts` signs in as root, checks that the menu holds all five pages, and opens Budgets (lena's
bar and the tenant's, their values and their reset times) and Sessions (at least the session of the
agent that the run started), each with axe-core in the light and the dark theme. A click on a session
lands on the audit page with the session in its filter.

The run asks the browser for reduced motion, which the console honors, so that colors are at rest
when axe reads them. A stopped stack, a missing `uv` or a bank that does not reset stops the run
before the browser opens, with the reason. Requests of earlier runs that nobody decided stay in the
queue until they expire (15 minutes); the test takes the newest card.

### Settings

Vite reads these from the environment or from `console/.env` (not committed) when it starts. Only the `VITE_` ones reach the browser.

| Variable | Default | What it does |
|---|---|---|
| `VITE_OIDC_AUTHORITY` | `http://localhost:8180/realms/keystone` | The realm, as a browser reaches it |
| `VITE_OIDC_CLIENT_ID` | `console` | The public client to sign in with |
| `VITE_JAEGER_URL` | `http://localhost:16686` | Where the Jaeger UI is, for the trace links of the audit page |
| `KEYSTONE_URL` | `http://localhost:8080` | Where the dev server forwards `/admin` |

### Checks

`make console-check` runs ESLint (with type information and the accessibility rules), Prettier,
the unit tests (Vitest with Testing Library) and the production build, which type checks first.
The `console` job of CI runs the same steps, one by one so that a failure is annotated on the line.

The look follows the system: light and dark themes come from `prefers-color-scheme`, the colors are
custom properties in `console/src/index.css`, and the text pairs were checked against WCAG AA.

## The MCP endpoint

`POST /mcp` on port 8080 speaks MCP over streamable HTTP. Keystone serves the handshake protocol
era only (ADR-0003). A client in its default `auto` mode falls back to it by itself. A client
pinned to the `2026-07-28` version is refused.

Every request needs `Authorization: Bearer <token>`. The Host header is checked first (421 for an
address that is not in `KEYSTONE_ALLOWED_HOSTS`), then the token:

| Answer | When |
|---|---|
| 401 with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource"` | No token, or a token that is invalid. The body says why: `{"error": "invalid_token", "reason": "expired"}` |
| 403 | The token is sound but its agent is not under `agents` (`unknown_agent`), or it names a session that another principal opened |
| 404 | The request names a session that no one opened here |
| 503 with `Retry-After` | The identity provider's keys cannot be fetched |

`GET /.well-known/oauth-protected-resource` (RFC 9728) returns
`{"resource": "<base>/mcp", "authorization_servers": ["<issuer>"], "bearer_methods_supported":
["header"]}`, so an MCP client that supports OAuth can find the identity provider from the 401
without it being written into the client. `/healthz`, `/readyz` and that document need no token.

With `KEYSTONE_AUTH__MODE=none` (dev and test only) there is no check, and every caller is the dev
principal. Keep that on localhost.

Every result carries `keystone/call_id` in its `_meta`. A call that Keystone refuses (unknown
tool, invalid arguments) comes back as a normal result with
`isError` set. Its text starts with `[keystone:<CODE>] call <id>`, and the machine-readable copy
(`keystone/code`, `keystone/call_id`) is in the `_meta` of the result and of the first content
block (ADR-0007).

Health endpoints: `GET /healthz` always returns 200. `GET /readyz` probes Postgres and Redis with
a 1 second limit each and returns 503 if either is down.

## Troubleshooting

| Symptom | Check |
|---|---|
| `make demo` says it cannot reset an upstream | The stack is down. Run `make up`. |
| An agent gets `Unsupported protocol version` | It pinned the `2026-07-28` version. Use the default mode or `mode="legacy"`. |
| `421 Invalid Host header` from `/mcp` | The `Host` is not in `KEYSTONE_ALLOWED_HOSTS`. Add it, for example `keystone:*`. |
| `make up` times out on Keycloak | `docker compose -f deploy/docker-compose.yml logs keycloak`. First start imports the realm and can take 60 seconds on a slow disk. |
| `get_token.sh` says `Invalid user credentials` | The realm was imported with other passwords (an older `.env`, or `.env` changed after the first start). Recreate Keycloak, see "Changing the realm". |
| `401` with `reason: expired` | The token is older than five minutes. Get a new one with `scripts/get_token.sh`. |
| `401` with `reason: wrong_issuer` | The token was issued under another address than `KEYSTONE_OIDC_ISSUER`. Get tokens from `http://localhost:8180`, the address in the setting. |
| `403` with `reason: unknown_agent` | The token's `azp` is not under `agents`. Add it, or run `keystone agent list`. |
| `503` from `/mcp` | Keystone cannot read the identity provider's keys. Check `KEYSTONE_OIDC_DISCOVERY_URL` and that Keycloak is up; the log says `jwks_fetch_failed` or `oidc_issuer_mismatch`. |
| Every call gets `KS_DENIED`, "audit unavailable" | The audit writer is unhealthy and `audit.fail_closed` is on. Look for `audit_flush_failed` in the Keystone log: the database is down or refusing the writer. Calls resume within a few seconds of the writer succeeding. |
| A call returns `KS_APPROVAL_PENDING` after 10 seconds | The policy sent it to approval and nobody decided in the hold (`approvals.wait_seconds`). Approve it through the admin API as an approver (`scripts/get_token.sh lena keystone-cli`), then have the agent call `keystone__await_approval`. |
| `KS_DENIED`, "approval not available" | Keystone has no master keys, so it has no approval service. Set `KEYSTONE_MASTER_KEYS`. |
| `keystone__await_approval` says "there is no such approval request for this session" | The id is not this session's: it was made in another session, by another user or agent, in another tenant, or it does not exist. Call the original tool again. |
| An approver gets `403` on a decision | The token lacks the `approver` or `admin` role, or the request is the approver's own. A person cannot decide what they asked for. |
| An approver gets `409` on a decision | The request is no longer pending. The body's `status` says what it is: decided, used, or expired. |
| An approved call ends with `KS_QUARANTINED` or `KS_DENIED` | The call was checked again after its wait and the tool or the policy had changed. The approval is left unused and expires. Fix the cause, and have the agent call the tool again. |
| Keystone does not start: "KEYSTONE_APPROVALS_WEBHOOK_SECRET must be at least 16 characters" | The signing key is too short to trust. Make one with `openssl rand -hex 32`. |
| Keystone does not start: "KEYSTONE_APPROVALS_WEBHOOK_SECRET must be set" | `approvals.webhook_url` is set and the signing key is not in the environment. It is never read from the YAML. |
| `pnpm dev` says port 5173 is in use | Another process holds it, perhaps an earlier `pnpm dev`. The port is fixed because the Keycloak client `console` allows `http://localhost:5173/*` only, so Vite refuses another one. Stop the other process. |
| The console shows "Cannot reach the sign-in service" | The browser cannot read `VITE_OIDC_AUTHORITY` (`http://localhost:8180/realms/keystone`). Is Keycloak up, and is the port the one in `KEYCLOAK_PORT`? |
| Keycloak says "Invalid parameter: redirect_uri" for the console | The console was opened at an address other than `http://localhost:5173` (`127.0.0.1` is not allowed), or the realm in Keycloak is older than `deploy/keycloak/realm-keystone.json`. The realm is imported only when it does not exist: `make reset && make up` (see "Changing the realm"). |
| The console says "Cannot reach Keystone" or its pages answer 502 | The dev server's proxy cannot reach `KEYSTONE_URL` (`http://localhost:8080`). Run `make up`. |
| The console shows "No console access yet" | The user has neither the `approver` nor the `admin` role. Lena is an approver and root is an admin; see Identity. |
| The audit page shows "Audit chain not checked" | `/audit/verify` failed (a 5xx or no answer). That is not a clean result: read the Keystone log, and run `keystone audit verify` for the whole log. |
| The `console` job of CI says `schema.d.ts` is out of date with the admin API | A route or a model changed and `console/src/api/schema.d.ts` did not. Run `make console-types` and commit the result. `make console-check` does not look for this. |
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
| `docker` tests are skipped: "no Docker daemon" or "the sandbox image ... is not built" | The tests need the daemon and the image from `make sandbox-image`. Set `KEYSTONE_REQUIRE_DOCKER=1` to make that a failure instead of a skip. |
| The sandbox says the Docker daemon cannot be reached | Keystone has no socket, or may not use it. In compose check `docker compose exec keystone ls -l /var/run/docker.sock` and `DOCKER_SOCKET_GID`; on Linux the group of the socket is not 0. |
| `ModuleNotFoundError: keystone` right after `uv sync` (macOS) | A background process flagged `.venv` as hidden, and Python skips hidden `.pth` files. Check with `ls -lO .venv/lib/python3.12/site-packages/keystone.pth`. Set `UV_PROJECT_ENVIRONMENT` to a path outside the repo, for example `$HOME/.cache/keystone-venv`, then run `uv sync`. |
