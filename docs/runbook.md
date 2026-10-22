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
| `bash scripts/smoke/phase_0.sh` | Print one health row per service |
| `bash scripts/smoke/phase_1.sh` | The body of `make demo`; exits 1 if a step fails or the audit count is off |

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

Two sections come from the YAML file only: `tenants` and `upstreams` (see `keystone.example.yaml`).

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
| `keystone db upgrade` | Apply database migrations. `keystone serve --migrate` does it before starting; the compose stack uses that. |

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
| no longer, in a complete list | `disabled`, reason `removed_from_upstream`. It returns to `active` if the upstream lists it again with the same definition. |

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
| `keystone tool disable NAME` / `enable NAME` | Take a tool out of service by hand. Sync never re-enables a tool you disabled. `enable` refuses a quarantined tool (approve it instead) and one the upstream stopped listing. |

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
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
| `ModuleNotFoundError: keystone` right after `uv sync` (macOS) | A background process flagged `.venv` as hidden, and Python skips hidden `.pth` files. Check with `ls -lO .venv/lib/python3.12/site-packages/keystone.pth`. Set `UV_PROJECT_ENVIRONMENT` to a path outside the repo, for example `$HOME/.cache/keystone-venv`, then run `uv sync`. |
