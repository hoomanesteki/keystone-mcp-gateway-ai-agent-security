# ADR-0002: Pin dependencies at project start

Status: accepted
Date: 2026-10-21

## Context

An unpinned dependency can change behaviour between two CI runs, and an unpinned container tag can
change the whole stack under a running demo. Gate reports and benchmark numbers only mean
something if the same inputs can be rebuilt.

## Decision

Every Python package is pinned by `uv.lock`, which is committed. Every container image is pinned
to an exact tag, never `latest`. At project start I took the latest stable release of each. An
upgrade is its own `chore/` story that updates this file and the lock together.

A new dependency needs a line in the commit body and a row here. `tests/unit/test_adr_pins.py`
fails when a direct dependency, a compose image or a Dockerfile base image is missing from this
file or listed with a different version.

## Container images

| Image | Tag | Used in |
|---|---|---|
| postgres | 16.15 | `deploy/docker-compose.yml`, CI integration job |
| redis | 7.4.11 | `deploy/docker-compose.yml`, CI integration job |
| quay.io/keycloak/keycloak | 26.8.1 | `deploy/docker-compose.yml` |
| jaegertracing/jaeger | 2.22.0 | `deploy/docker-compose.yml` (the v2 image; all-in-one is the retired v1 line) |
| prom/prometheus | v3.15.1 | `deploy/docker-compose.yml` |
| grafana/grafana | 13.2.4 | `deploy/docker-compose.yml` |
| python | 3.12.15-slim-trixie | `Dockerfile` and `deploy/Dockerfile.upstreams`, build and runtime stages |
| ghcr.io/astral-sh/uv | 0.12.3 | `Dockerfile` and `deploy/Dockerfile.upstreams` (copy the uv binary) |
| keystone-upstreams | dev | built locally from `deploy/Dockerfile.upstreams`, never pulled; the tag is the compose service name for the build |

## CI actions and tools

| Item | Version | Notes |
|---|---|---|
| actions/checkout | v7 | |
| astral-sh/setup-uv | v10.3.1 | no moving major tag is published |
| gitleaks | 8.30.1 | downloaded in the security job and checked against its SHA-256 |
| ubuntu runner | ubuntu-24.04 | pinned so the toolchain does not move with the `latest` label |

## Python packages: direct runtime dependencies

| Package | Version | Used for |
|---|---|---|
| alembic | 1.20.0 | schema migrations |
| anyio | 4.15.1 | timeouts and task groups (fail_after, create_task_group) |
| asyncpg | 0.32.0 | Postgres driver, also used directly by the readiness probe |
| fastapi | 0.159.1 | HTTP app and dependency injection |
| jsonschema | 4.26.0 | Draft 2020-12 validation of tool arguments in the pipeline |
| mcp | 2.3.0 | MCP server and client SDK (ADR-0003); a new major version, see `docs/spikes/mcp-proxy.md` |
| pydantic-settings | 2.16.1 | typed settings from env and YAML |
| pyyaml | 6.0.3 | YAML config files |
| redis | 8.1.0 | Redis client (asyncio) |
| sqlalchemy | 2.1.6 | async ORM and Core |
| structlog | 26.1.0 | JSON logs with the secret scrubber |
| typer | 0.27.3 | admin CLI |
| uvicorn | 0.54.0 | ASGI server |

## Python packages: direct development dependencies

| Package | Version | Used for |
|---|---|---|
| httpx | 0.28.1 | ASGI test client |
| mypy | 2.4.0 | type checking |
| pip-audit | 2.10.1 | dependency vulnerability scan |
| pre-commit | 4.7.0 | local commit hooks |
| pytest | 9.1.1 | test runner |
| pytest-asyncio | 1.4.0 | async tests |
| pytest-github-actions-annotate-failures | 0.4.2 | failure annotations in CI |
| ruff | 0.17.1 | lint and format |
| types-jsonschema | 4.26.0.20261006 | type stubs for jsonschema |
| types-pyyaml | 6.0.12.20260906 | type stubs for PyYAML |

## Python packages: transitive (from `uv.lock`)

| Package | Version |
|---|---|
| annotated-doc | 0.0.5 |
| annotated-types | 0.8.0 |
| ast-serialize | 0.13.1 |
| attrs | 26.1.0 |
| boolean-py | 5.0 |
| cachecontrol | 0.14.4 |
| certifi | 2026.10.19 |
| cffi | 2.1.1 |
| cfgv | 3.5.0 |
| charset-normalizer | 3.5.2 |
| click | 8.5.0 |
| colorama | 0.4.6 |
| cryptography | 50.0.2 |
| cyclonedx-python-lib | 11.12.0 |
| defusedxml | 0.7.1 |
| distlib | 0.4.4 |
| filelock | 4.2.4 |
| greenlet | 3.5.6 |
| h11 | 0.16.0 |
| httpcore | 1.0.9 |
| httpcore2 | 2.16.0 |
| httpx2 | 2.16.0 |
| httpx2-jsfetch | 1.0 |
| identify | 2.6.20 |
| idna | 3.20 |
| iniconfig | 2.3.1 |
| jsonschema-specifications | 2025.9.1 |
| librt | 0.16.0 |
| license-expression | 30.4.4 |
| mako | 1.4.3 |
| markdown-it-py | 4.2.0 |
| markupsafe | 3.0.4 |
| mcp-types | 2.3.0 |
| mdurl | 0.1.2 |
| msgpack | 1.2.3 |
| mypy-extensions | 1.1.0 |
| nodeenv | 1.11.0 |
| opentelemetry-api | 1.45.1 |
| packageurl-python | 0.17.6 |
| packaging | 26.3 |
| pathspec | 1.1.1 |
| pip | 26.2.2 |
| pip-api | 0.0.35 |
| pip-requirements-parser | 32.0.1 |
| platformdirs | 4.13.5 |
| pluggy | 1.7.0 |
| py-serializable | 2.1.0 |
| pycparser | 3.11 |
| pydantic | 2.14.1 |
| pydantic-core | 2.50.1 |
| pygments | 2.21.0 |
| pyjwt | 2.15.1 |
| pyparsing | 3.3.3 |
| python-discovery | 1.6.4 |
| python-dotenv | 1.2.4 |
| python-multipart | 0.0.32 |
| pywin32 | 312 |
| referencing | 0.37.0 |
| requests | 2.34.2 |
| rich | 15.0.0 |
| rpds-py | 2026.9.1 |
| shellingham | 1.5.4 |
| sortedcontainers | 2.4.0 |
| sse-starlette | 3.5.0 |
| starlette | 1.9.0 |
| tomli | 2.5.0 |
| tomli-w | 1.2.0 |
| truststore | 0.10.5 |
| typing-extensions | 4.16.0 |
| typing-inspection | 0.4.4 |
| urllib3 | 2.8.0 |
| virtualenv | 21.14.12 |

## Consequences

- Rebuilding any commit gives the same dependency set.
- Security fixes wait for a `chore/` story, except when `pip-audit` fails CI. Then the fix is
  immediate and the row here changes with it.

## Revisit when

A dependency stops getting releases, or the lock grows large enough that this table needs
generating by a script.
