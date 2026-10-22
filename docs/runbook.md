# Runbook

How to run the local stack and what each part listens on. This file grows with the phases.

## Local stack

`make up` starts Postgres, Redis, Keycloak, Jaeger, Prometheus and Grafana and waits until every
container reports healthy. Cold start takes about 30 seconds on a laptop with warm images.

| Command | What it does |
|---|---|
| `make up` | Start the full stack and wait for health |
| `make up-core` | Start Postgres and Redis only (what `make check` needs) |
| `make down` | Stop the stack and keep its data |
| `make reset` | Stop the stack and delete its volumes |
| `bash scripts/smoke/phase_0.sh` | Print one health row per service |

## Host ports

The defaults are in `.env.example`. Copy it to `.env` to move a port, then run `make up` again.
Tests never use these ports. They start their own services on free ports.

| Service | Host port | Notes |
|---|---|---|
| Keystone | 8080 | `keystone serve` (not in compose yet). MCP endpoint: `http://localhost:8080/mcp` |
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
| `KEYSTONE_REDIS_URL` | `redis://localhost:56379/0` | Redis URL |
| `KEYSTONE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |
| `KEYSTONE_CONFIG` | unset | Path to a YAML file with the same keys |
| `KEYSTONE_ALLOWED_HOSTS` | `["127.0.0.1:*","localhost:*","[::1]:*"]` | JSON list of `Host` header values the MCP endpoint accepts (DNS rebinding guard). `:*` matches any port. Add the service name, for example `keystone:*`, to reach it from another container. |
| `KEYSTONE_DEV_PRINCIPAL` | tenant `acme`, user `olivia`, groups `operators`, agent `ops-agent` | JSON object. Who every caller is, until real authentication arrives in Phase 3. Refused when `KEYSTONE_ENV=prod`. |

Two sections come from the YAML file only: `tenants` and `upstreams` (see `keystone.example.yaml`).
Each upstream has an `id` (lowercase letters, digits and single underscores, not ending in an
underscore), a `tenant` and, for `transport: http`, a `url`. Keystone reads each upstream's tool
list once when it starts. An upstream that is down then is skipped and logged, and its tools stay
missing until Keystone restarts. Phase 2 adds syncing.

## The MCP endpoint

`POST /mcp` on port 8080 speaks MCP over streamable HTTP. Keystone serves the handshake protocol
era only (ADR-0003). A client in its default `auto` mode falls back to it by itself. A client
pinned to the `2026-07-28` version is refused.

Phase 1 has no authentication: whoever can reach the port acts as the dev principal above, so
keep it on localhost. With `KEYSTONE_ENV=prod` there is no dev principal and the endpoint answers
every request with HTTP 401 until Phase 3.

A call that Keystone refuses (unknown tool, invalid arguments) comes back as a normal result with
`isError` set. Its text starts with `[keystone:<CODE>] call <id>`, and the machine-readable copy is
in the `_meta` of the first content block (ADR-0007).

Health endpoints: `GET /healthz` always returns 200. `GET /readyz` probes Postgres and Redis with
a 1 second limit each and returns 503 if either is down.

## Troubleshooting

| Symptom | Check |
|---|---|
| `make up` times out on Keycloak | `docker compose -f deploy/docker-compose.yml logs keycloak`. First start imports the realm and can take 60 seconds on a slow disk. |
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
| `ModuleNotFoundError: keystone` right after `uv sync` (macOS) | A background process flagged `.venv` as hidden, and Python skips hidden `.pth` files. Check with `ls -lO .venv/lib/python3.12/site-packages/keystone.pth`. Set `UV_PROJECT_ENVIRONMENT` to a path outside the repo, for example `$HOME/.cache/keystone-venv`, then run `uv sync`. |
