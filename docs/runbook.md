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
| Keystone | 8080 | `keystone serve` (not in compose yet) |
| Postgres | 55432 | database, user and password are all `keystone` |
| Redis | 56379 | tests use db 15 |
| Keycloak | 8180 | admin console login `admin` / `admin`, realm `keystone` |
| Jaeger UI | 16686 | |
| OTLP gRPC / HTTP | 4317 / 4318 | sent to Jaeger |
| Prometheus | 9090 | |
| Grafana | 3000 | login `admin` / `admin`, Prometheus and Jaeger provisioned |
| Demo upstreams | 8101 to 8105, 8112 | mail, files, bank, echo, web, files-globex (later phases) |
| Fake LLM | 8199 | later phase |
| Console | 5173 | later phase |

The credentials above are for local development only. Nothing in compose is meant to be exposed
beyond the machine.

## Keystone settings

Environment variables win over the YAML file named by `KEYSTONE_CONFIG`.

| Variable | Default | Purpose |
|---|---|---|
| `KEYSTONE_ENV` | `dev` | `dev`, `test` or `prod` |
| `KEYSTONE_DATABASE_URL` | `postgresql+asyncpg://keystone:keystone@localhost:55432/keystone` | Postgres DSN |
| `KEYSTONE_REDIS_URL` | `redis://localhost:56379/0` | Redis URL |
| `KEYSTONE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |
| `KEYSTONE_CONFIG` | unset | Path to a YAML file with the same keys |

Health endpoints: `GET /healthz` always returns 200. `GET /readyz` probes Postgres and Redis with
a 1 second limit each and returns 503 if either is down.

## Troubleshooting

| Symptom | Check |
|---|---|
| `make up` times out on Keycloak | `docker compose -f deploy/docker-compose.yml logs keycloak`. First start imports the realm and can take 60 seconds on a slow disk. |
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
