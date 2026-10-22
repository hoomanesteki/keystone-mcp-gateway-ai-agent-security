# Runbook

How to run the local stack and what each part listens on. This file grows with the phases.

## Local stack

`make up` builds and starts Postgres, Redis, Keycloak, Jaeger, Prometheus, Grafana, the four demo
upstreams and Keystone, and waits until every container reports healthy. Cold start takes about
30 seconds on a laptop with warm images. The first build of the two local images takes longer.

| Command | What it does |
|---|---|
| `make up` | Start the full stack and wait for health |
| `make up-core` | Start Postgres and Redis only (what `make check` needs) |
| `make demo` | `make up`, reset the upstreams, run the scripted agent through Keystone and print its transcript |
| `make down` | Stop the stack and keep its data |
| `make reset` | Stop the stack and delete its volumes |
| `scripts/get_token.sh alice support-agent` | Print an access token for a Keycloak user (see Identity) |
| `make test-e2e` | The end-to-end tests against the running stack. The nightly workflow runs `make up` and then this |
| `bash scripts/smoke/phase_0.sh` | Print one health row per service |
| `bash scripts/smoke/phase_1.sh` | The body of `make demo`; exits 1 if a step fails or the audit count is off |
| `bash scripts/smoke/phase_2.sh` | Lists the 15 tools, quarantines and approves a changed echo description, stops the bank server and checks the refusal. About 45 seconds. It restarts Keystone with a 2 s health probe (`SMOKE_HEALTH_INTERVAL_S`) and restores everything when it ends. |

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
| Mail, files, bank, echo | 8101, 8102, 8103, 8104 | demo upstreams, services `mail-mcp`, `files-mcp`, `bank-mcp`, `echo-mcp` |
| Web, files-globex | 8105, 8112 | later phases |
| Fake LLM | 8199 | later phase |
| Console | 5173 | later phase |

The credentials above are for local development only. Nothing in compose is meant to be exposed
beyond the machine.

## Demo upstreams

Four small MCP servers give the gateway something to proxy and give tests state to inspect. They
share one image (`deploy/Dockerfile.upstreams`), and `make up` starts them.

| Server | Port | Tools |
|---|---|---|
| mail | 8101 | `list_emails`, `read_email`, `send_email` (12 seeded emails) |
| files | 8102 | `list_files`, `read_file`, `write_file` (confined to one workspace) |
| bank | 8103 | `get_balance`, `list_transactions`, `transfer` (3 seeded accounts) |
| echo | 8104 | `echo`, `sleep`, `fail` |

Each also serves plain HTTP routes next to `/mcp` that are not tools, so an agent cannot call them:
`GET /healthz`, `POST /_reset` (back to the seed) and `GET /_state` (sent mail, transfers, written
files and the names of the tools called). The echo server adds `POST /_mutate`, which rewrites the
`echo` description, and `ECHO_POISONED=1`, which adds a tool with an injected description.

Run one outside compose: `uv run python -m examples.upstreams.mail_server --port 8101`. Add
`--transport stdio` to speak MCP over stdin and stdout.

| Variable | Purpose |
|---|---|
| `MAIL_DB`, `BANK_DB`, `FILES_DB` | SQLite file for the server's state. Default: a temp file. Every start re-seeds it. |
| `FILES_WORKSPACE` | Directory the files server confines itself to. Default: a temp directory. |
| `MAIL_API_KEY`, `FILES_API_KEY`, `BANK_API_KEY`, `ECHO_API_KEY` | When set, `/mcp` requires a matching `X-Api-Key` header. Unset in tests and compose until Phase 3. |
| `ECHO_POISONED` | `1` adds the poisoned tool. |

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

## Keystone settings

Environment variables win over the YAML file named by `KEYSTONE_CONFIG`.

| Variable | Default | Purpose |
|---|---|---|
| `KEYSTONE_ENV` | `dev` | `dev`, `test` or `prod` |
| `KEYSTONE_DATABASE_URL` | `postgresql+asyncpg://keystone:keystone@localhost:55432/keystone` | Postgres DSN |
| `KEYSTONE_REDIS_URL` | `redis://localhost:56379/0` | Redis URL. Session state lives here. Set it to an empty string to keep session state in the gateway process instead (one process only, lost on restart). |
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
| `KEYSTONE_DEV_PRINCIPAL` | tenant `acme`, user `olivia`, groups `operators`, agent `ops-agent` | JSON object. Who every caller is, until real authentication arrives in Phase 3. Refused when `KEYSTONE_ENV=prod`. |
| `KEYSTONE_AUTH__ALLOW_UNKNOWN_AGENTS` | `false` | Let an agent that is not under `agents` in with trust `low`. Also `auth.allow_unknown_agents` in the YAML. |

Three sections come from the YAML file only: `tenants`, `upstreams` and `agents` (see `keystone.example.yaml`).

## Upstreams

Each upstream has an `id` (lowercase letters, digits and single underscores, not ending in an
underscore), a `tenant` that is listed under `tenants` and, for `transport: http`, a `url`. A
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
so treat both as operator rights and keep the database closed. Phase 8 adds containerized stdio
upstreams for servers you do not trust.

### Tool lists and syncing

Keystone reads each upstream's tool list when it starts, every `registry.sync_interval_s`, and
when you run `keystone registry sync`. Each tool is stored with the SHA-256 of its description and
of its input schema. The `tools` block of an upstream in the YAML sets risk, tags, cost, timeout
and extractors by the upstream's own tool name (for example `send_email`, not `mail__send_email`).
A tool without an entry has risk `medium`, no tags and no cost.

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

A tool seen for the first time is screened too (`keystone.defense.description_check`). Five
rules look for characters a reader cannot see (tag characters, zero-width and bidirectional
controls), phrases such as "ignore all previous instructions" or "do not tell the user", the pseudo
tags `<important>` and `<system>`, "before using this tool" together with read, send or call, and a
description longer than 2,000 characters. A tool that trips any of them is created `quarantined`
with the reason `suspicious_description:<rule ids>`, and has no pending definition. The agent is
told the category only, not which rule fired. `approve-change` releases it as it is after you have
read it. This is a short list of crude patterns and a determined author will get past it. It is
meant to stop the careless cases and to make a person look; Phase 7 replaces it with a scanner.
Try it: `ECHO_POISONED=1` makes the demo echo server list a tool that is held at first sight.

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

## Sessions

Each MCP session has a state object (flags, taint, call count, spend) stored as JSON in Redis
under `ks:sess:{session id}`. The key lives 24 hours from its last use: both reading and writing
a session restart the clock. Postgres holds one `sessions` row per session, written when the
session makes its first call, as the durable reference that audit records will point at. The row's
`last_seen_at`, flags and taint are updated at most once a minute per session.

If Redis cannot be reached, a call is refused with `KS_DENIED` ("session state is unavailable") and
audited, because a call must not run without the flags and taint of its session. If Postgres
cannot write the row, the call goes ahead and the failure is logged. A request that names no MCP
session id gets a throwaway state that is never stored. Redis database 15 belongs to the tests;
they empty it.

## The MCP endpoint

`POST /mcp` on port 8080 speaks MCP over streamable HTTP. Keystone serves the handshake protocol
era only (ADR-0003). A client in its default `auto` mode falls back to it by itself. A client
pinned to the `2026-07-28` version is refused.

Phase 1 has no authentication: whoever can reach the port acts as the dev principal above, so
keep it on localhost. With `KEYSTONE_ENV=prod` there is no dev principal and the endpoint answers
every request with HTTP 401 until Phase 3.

`GET /_dev/audit` returns how many calls the in-memory audit log holds and the last 50. It exists
for the Phase 1 demo, is not mounted when `KEYSTONE_ENV=prod`, and goes away when the admin API
arrives in Phase 5.

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
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
| `ModuleNotFoundError: keystone` right after `uv sync` (macOS) | A background process flagged `.venv` as hidden, and Python skips hidden `.pth` files. Check with `ls -lO .venv/lib/python3.12/site-packages/keystone.pth`. Set `UV_PROJECT_ENVIRONMENT` to a path outside the repo, for example `$HOME/.cache/keystone-venv`, then run `uv sync`. |
