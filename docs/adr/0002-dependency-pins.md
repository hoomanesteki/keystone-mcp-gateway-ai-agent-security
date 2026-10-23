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
fails when a direct dependency, a compose image, a Dockerfile base image, a console package or a
workflow action is missing from this file or listed with a different version.

The console (Phase 6) follows the same rule with `pnpm-lock.yaml` and exact versions in
`console/package.json`, taken on 2026-10-23. Two of its pins are not the newest release, and one
is newer than the plan: see "Console: where a pin differs" below.

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
| keystone | dev | built locally from `Dockerfile`, never pulled; compose names the built image |
| keystone-upstreams | dev | built locally from `deploy/Dockerfile.upstreams`, never pulled; the tag is the compose service name for the build |

## CI actions and tools

| Item | Version | Notes |
|---|---|---|
| actions/checkout | v7 | |
| astral-sh/setup-uv | v10.3.1 | no moving major tag is published |
| gitleaks | 8.30.1 | downloaded in the security job and checked against its SHA-256 |
| actions/setup-node | v7 | the console and nightly jobs; Node's version is read from `console/.nvmrc` |
| pnpm/action-setup | v6 | the console and nightly jobs; pnpm's version is read from `console/package.json` |
| ubuntu runner | ubuntu-24.04 | pinned so the toolchain does not move with the `latest` label |

## Python packages: direct runtime dependencies

| Package | Version | Used for |
|---|---|---|
| alembic | 1.20.0 | schema migrations |
| anyio | 4.15.1 | timeouts and task groups (fail_after, create_task_group) |
| asyncpg | 0.32.0 | Postgres driver, also used directly by the readiness probe |
| cedarpy | 4.12.2 | Cedar policy engine in process (KS-401, ADR-0006); wraps Cedar 4.12.0, no runtime dependencies, wheels for macOS and Linux on x86_64 and arm64 |
| cryptography | 50.0.2 | Fernet encryption for the credential vault (KS-305), and the RSA and EC keys of the fake IdP |
| fastapi | 0.159.1 | HTTP app and dependency injection |
| jsonschema | 4.26.0 | Draft 2020-12 validation of tool arguments in the pipeline |
| mcp | 2.3.0 | MCP server and client SDK (ADR-0003); a new major version, see `docs/spikes/mcp-proxy.md` |
| opentelemetry-api | 1.45.1 | the tracing API: spans, the current span, W3C trace context propagation (KS-504) |
| opentelemetry-exporter-otlp-proto-http | 1.45.1 | sends spans to Jaeger over OTLP/HTTP (KS-504) |
| opentelemetry-sdk | 1.45.1 | the tracer provider and the in-memory exporter the tests use (KS-504) |
| prometheus-client | 0.26.0 | metrics registry and the `/metrics` text format (KS-501, KS-505); no dependencies of its own |
| pydantic-settings | 2.16.1 | typed settings from env and YAML |
| pyjwt | 2.15.1 | JWT validation against the IdP's keys (KS-303), with the `crypto` extra for RS256 and ES256; it was already installed through the MCP SDK |
| pyyaml | 6.0.3 | YAML config files |
| redis | 8.1.0 | Redis client (asyncio) |
| sqlalchemy | 2.1.6 | async ORM and Core |
| structlog | 26.1.0 | JSON logs with the secret scrubber |
| typer | 0.27.3 | admin CLI |
| uvicorn | 0.54.0 | ASGI server |

## Python packages: the scanner extra

The optional extra `keystone[scanner]` (KS-702, ADR-0011) holds the model behind the scanner's
rules. CI never installs it. The compose build does, and so does `make gate` from Phase 7, which
runs the one test that loads the real model.

| Package | Version | Used for |
|---|---|---|
| torch | 2.14.1 | CPU inference of the classifier. Linux gets the CPU wheel (`2.14.1+cpu`) from `download.pytorch.org/whl/cpu`, so no CUDA library is installed; macOS and Windows get the ordinary wheel |
| transformers | 5.20.2 | loads the model and its tokenizer; brings `huggingface-hub`, `tokenizers` and `safetensors` |

## Models

A model is pinned to a revision, which `keystone.defense.classifier.SPECS` holds and a test checks.

| Model | Revision | License | Used for |
|---|---|---|---|
| protectai/deberta-v3-base-prompt-injection-v2 | 90c9989b1a342275dd0d1a95aad283c04e075671 | Apache-2.0 | the default classifier (ADR-0011) |
| meta-llama/Llama-Prompt-Guard-2-86M | a8ded8e697ce7c355e395a0df51f94adb4a2fd27 | Llama community license, gated | the optional classifier; not downloaded unless chosen |

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

## Console toolchain

| Item | Version | Notes |
|---|---|---|
| Node.js | 26 | the major, in `console/.nvmrc`; CI reads the file (`actions/setup-node`), and 26.12.0 is what I ran locally |
| pnpm | 12.14.0 | `packageManager` in `console/package.json`, which `pnpm/action-setup` reads |
| Chromium | the build of Playwright 1.64.1 | `pnpm exec playwright install chromium`; the e2e test runs nothing else |

## Console packages: runtime dependencies

| Package | Version | Used for |
|---|---|---|
| react | 19.3.1 | the UI; the plan names 18, see below |
| react-dom | 19.3.1 | rendering |
| react-router | 8.5.0 | routes and the nav (the single package; `react-router-dom` is no longer needed) |
| @tanstack/react-query | 5.104.5 | server state: polling, caching, optimistic updates |
| oidc-client-ts | 3.5.0 | sign-in with Keycloak (authorization code with PKCE, silent renew) |

## Console packages: development dependencies

| Package | Version | Used for |
|---|---|---|
| vite | 8.3.5 | dev server (with the `/admin` proxy) and the production build |
| @vitejs/plugin-react | 6.1.2 | the React transform for Vite |
| typescript | 6.0.3 | strict type checking; see below for why it is not 7 |
| tailwindcss | 4.3.3 | styling, with the theme in `src/index.css` |
| @tailwindcss/vite | 4.3.3 | Tailwind's Vite plugin |
| vitest | 5.0.5 | unit tests |
| jsdom | 30.1.3 | the DOM the unit tests run in |
| @testing-library/react | 16.3.3 | rendering components in tests |
| @testing-library/dom | 10.4.2 | queries; a peer of the React package |
| @testing-library/user-event | 14.6.8 | clicks and typing as a person does them |
| @testing-library/jest-dom | 7.0.1 | matchers such as `toBeVisible` |
| @playwright/test | 1.64.1 | the browser test of the approval loop (KS-609) |
| @axe-core/playwright | 4.14.0 | the accessibility check inside the browser test: WCAG 2.1 A and AA and best practices, in both themes |
| openapi-typescript | 7.13.0 | `src/api/schema.d.ts` from the API's OpenAPI document |
| eslint | 10.13.0 | lint |
| @eslint/js | 10.0.1 | ESLint's recommended rules |
| typescript-eslint | 8.72.0 | TypeScript rules, with type information |
| eslint-plugin-react-hooks | 7.1.1 | the rules of hooks |
| eslint-plugin-react-refresh | 0.5.7 | components that hot reload |
| eslint-plugin-jsx-a11y | 6.10.2 | accessibility rules for JSX |
| globals | 17.13.0 | the browser and Node globals ESLint needs |
| prettier | 3.9.10 | formatting |
| @types/react | 19.3.0 | types |
| @types/react-dom | 19.3.0 | types |
| @types/node | 26.6.5 | types for the Vite and Playwright config files |

### Console: where a pin differs

- **React is 19, the plan says 18.** 19.3.1 is the current release, and React Router 8 needs
  19.2.7 or newer. Nothing in the console depends on a React 18 behaviour.
- **TypeScript is 6.0.3, not 7.0.2.** 7.0 is the native compiler and its `typescript` package no
  longer exposes the compiler API that two tools in the chain call: `require("typescript")` has
  only a version, `openapi-typescript` 7.13.0 stops with an error on it (I ran it), and
  `typescript-eslint` 8.72.0 accepts TypeScript below 6.1.0. 6.0.3 is the last release of the line
  they use. Moving to 7 waits for a release of both that names it.
- **Two peer ranges are widened on purpose** in `console/pnpm-workspace.yaml`:
  `eslint-plugin-jsx-a11y` 6.10.2 names ESLint up to 9 and runs on 10, and `openapi-typescript`
  names TypeScript `^5.x` and runs on 6. Lint and `pnpm gen:api` run in CI, so a break shows there.
- **Versions are exact** (no `^`), so `console/package.json` and this table cannot disagree.

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
| cyclonedx-python-lib | 11.12.0 |
| defusedxml | 0.7.1 |
| distlib | 0.4.4 |
| filelock | 4.2.4 |
| googleapis-common-protos | 1.76.0 |
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
| opentelemetry-exporter-http-transport | 0.66b1 |
| opentelemetry-exporter-otlp-common | 0.66b1 |
| opentelemetry-exporter-otlp-proto-common | 1.45.1 |
| opentelemetry-proto | 1.45.1 |
| opentelemetry-semantic-conventions | 0.66b1 |
| packageurl-python | 0.17.6 |
| packaging | 26.3 |
| pathspec | 1.1.1 |
| pip | 26.2.2 |
| pip-api | 0.0.35 |
| pip-requirements-parser | 32.0.1 |
| platformdirs | 4.13.5 |
| pluggy | 1.7.0 |
| protobuf | 7.36.2 |
| py-serializable | 2.1.0 |
| pycparser | 3.11 |
| pydantic | 2.14.1 |
| pydantic-core | 2.50.1 |
| pygments | 2.21.0 |
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
