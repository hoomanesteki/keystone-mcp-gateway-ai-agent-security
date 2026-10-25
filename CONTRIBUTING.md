# Contributing to Keystone

Keystone is built one story at a time from the plan in docs/PLAN.md. The story block there is the
spec: its acceptance criteria, its tests and its files. This page covers setup, how a change
moves, and how to add a tool server, a policy or an ADR.

## Set up

You need Docker with Compose v2, GNU make, uv 0.12 (it installs Python 3.12), and for the console
Node 26 and pnpm 12.

    git clone https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security.git
    cd keystone-mcp-gateway-ai-agent-security
    make setup          # uv sync, then the pre-commit hook (ruff and ruff format)
    make check          # starts Postgres and Redis, then lint, types, unit, integration, console

On macOS, if `uv run` fails with `ModuleNotFoundError: keystone` right after `uv sync`, put the
virtual environment outside the repository: `export UV_PROJECT_ENVIRONMENT=$HOME/.cache/keystone-venv`
(docs/runbook.md, Troubleshooting, says why).

`make up` starts the full stack and `make down` stops it. Tests never use the stack's ports: they
start their own services on free ports.

## How a change moves

1. Branch from `dev`. Name the branch after the story: `feat/ks-203-tool-sync`, `fix/ks-991-...`,
   `docs/...`.
2. Write the tests the story names first, with the exact file and function name, and see them fail.
3. Write the smallest code that meets every acceptance criterion. Run `make check`.
4. Mark the story `done` in docs/progress.md, in the same branch, with anything deferred.
5. Push. CI must be green on the branch tip.
6. Merge into `dev` with `git merge --no-ff`, push `dev`, delete the branch.
7. At the end of a phase, `make gate PHASE=N` runs everything, the report goes in docs/gates/,
   and `dev` is merged into `main` with a tag.

Never commit to `dev` or `main` directly, never force push, never pass `--no-verify`.

## Commits

- Subject: `type(scope): imperative lowercase summary`, at most 72 characters.
  `scripts/check_commit_msg.py` checks it, locally and in the `commits` job.
- Types: feat, fix, test, docs, refactor, perf, chore, ci, build.
- Scopes: gateway, registry, identity, policy, audit, telemetry, approvals, defense, sandbox,
  metering, admin, console, eval, deploy, and repo, ci or docs where nothing else fits.
- The body says why when it is not obvious, and ends with `Refs: KS-xxx`.
- A new dependency: `uv add <pkg>`, note it in the commit body, and record the version in
  docs/adr/0002-dependency-pins.md.

Example: `feat(registry): quarantine tools whose description hash changed`.

## Tests

Every test has `@pytest.mark.phase(n)`, the phase it belongs to. Other markers: `services` (needs
Postgres and Redis), `docker` (needs the Docker daemon), `slow`, `e2e`.

| Level | Command | Needs |
|---|---|---|
| One test | `uv run pytest tests/unit/test_x.py::test_y -x` | whatever its markers say |
| Unit and invariants | `make test-unit` | nothing |
| Integration | `make test-int` | `make up-core` and Docker (it builds the sandbox and echo images) |
| Policy cases | `make policy` | nothing |
| End to end | `make test-e2e` | `make up` |
| Console | `make console-check`, `make console-e2e` | Node and pnpm; the browser test needs the stack |
| Lint and types | `make lint`, `make type` | nothing |
| Everything CI runs | `make ci-local` | Docker and gitleaks |
| A phase gate | `make gate PHASE=N` | the full stack |

Never delete, skip or loosen a test to get green. If a test looks wrong, stop and explain why.

## Add a tool server

1. Write the MCP server. The demo servers in examples/upstreams/ are small models to copy.
2. Register it in the config (`keystone.example.yaml` shows every field; the compose stack reads
   `deploy/keystone.compose.yaml`). Give each tool a `risk` (low, medium, high, critical) and its
   tags: `reads_untrusted`, `reads_sensitive`, `external_effect`, `code_exec`. A tool with no tags
   is invisible to the Rule of Two, so tag every tool that reads outside text or changes anything.
3. If it needs a key, set `credential_mode` and `credential_env`, or store the key with
   `keystone cred set`. The key never goes in the config file.
4. Add policy cases for who may call its tools, and an integration test that calls it through
   Keystone.

## Add a policy

1. Put the rule in `policies/<tenant>/access/` or `policies/<tenant>/approval/` (`default/` for
   every tenant), with an `@id("...")` annotation. The id is the reason in the audit log.
2. Add cases to `tests/policy_cases/*.yaml`: a call it should decide, and a call it should not.
3. Run `make policy`. It fails if a case decides differently or if no case matches a policy.
4. Give the id its own heading in docs/policies.md. The console links each reason there, and a
   test checks that every shipped id has one.
5. On a running stack, `keystone policy reload` loads it. A set with a problem is refused and the
   old rules stay in force.

## Add an ADR

Write one when a decision is costly to reverse. The next free number goes in the name,
`docs/adr/00NN-short-name.md`, with these parts: title, Status, Date, Context, Decision,
Consequences, Revisit when. Keep it under a page and say what the decision costs. An accepted ADR
is not edited to change its meaning: a later one supersedes it and says so.

## Hard rules

1. Do not change src/keystone/core/* or policies/schema.cedarschema unless the story says so.
2. Every tool call goes through gateway/pipeline.py. Never call an upstream from anywhere else.
3. Secrets are SecretStr. Never log, trace, audit or return them.
4. Every network call has a timeout. Every external input is validated with pydantic.
5. Async all the way down in request paths. Wrap CPU-bound work such as the classifier with
   anyio.to_thread.
6. Keep scope tight. A bug outside your story goes in docs/progress.md under "Found".

## Style

- Python 3.12, type hints everywhere, ruff format, mypy strict in core, gateway, policy and audit.
- Comments say why, not what. No banner comments, no emoji.
- Docs: short sentences, numbers with units, no marketing words. `make prose` checks the banned
  words and the em dash.

## Before you push

- The story's named tests exist and pass.
- `make check` is green.
- The earlier phases' smoke scripts that your change touches still pass (scripts/smoke/).
- docs/progress.md is updated. A new setting is in `.env.example` or `keystone.example.yaml` and
  in docs/runbook.md.

## When to stop and ask

- A story this one depends on is not merged.
- An acceptance criterion contradicts a contract or another story.
- You need a paid API key or a cloud resource.
- The same test has failed after 3 different fix attempts.
