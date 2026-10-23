# Contributing to Keystone

Keystone is an MCP security gateway. The full plan is docs/PLAN.md.
Do one story at a time. The story block in docs/PLAN.md is the spec.

## Commands
- make up / make down / make reset      local stack (postgres, redis, keycloak, jaeger, prometheus, grafana, demo upstreams)
- make check                            lint, types, unit, integration, invariants, console
- make console-check                    the console's lint, unit tests and build (Node and pnpm, see console/.nvmrc)
- make console-types                    regenerate the console's API types after an admin API change
- make console-e2e                      the browser test of the approval loop (starts the stack if it is not up)
- make gate PHASE=N                     everything a phase gate runs
- uv run pytest path::test -x           one test
- uv run keystone --help                admin CLI

## Hard rules
1. Branch from dev, merge back into dev with --no-ff once CI is green. Never commit to dev or main directly.
2. Write the tests named in the story first. Every test needs @pytest.mark.phase(n).
3. Never delete, skip or weaken a test to get green. If a test looks wrong, stop and explain.
4. Do not change src/keystone/core/* or policies/schema.cedarschema unless the story says so.
5. Every tool call goes through gateway/pipeline.py. Never call an upstream from anywhere else.
6. Secrets are SecretStr. Never log, trace, audit or return them.
7. Every network call has a timeout. Every external input is validated with pydantic.
8. No new dependency without noting it in the commit body and docs/adr/0002 pins.
9. Keep scope tight. If you find a bug outside your story, write it in docs/progress.md under "Found".
10. Update docs/progress.md in the same branch.

## Style
- Python 3.12, type hints everywhere, ruff format, mypy strict in core, gateway, policy, audit.
- Async all the way down in request paths. No blocking calls in the event loop
  (wrap CPU-bound classifier calls with anyio.to_thread).
- Comments say why, not what. No banner comments, no emoji.
- Commit messages: conventional commits, imperative, lowercase, at most 72 chars, "Refs: KS-xxx" in the body.
- Docs: short sentences, concrete numbers, no marketing words (see docs/PLAN.md section 5.10).

## When to stop and ask
- A dependency story is not merged.
- An acceptance criterion contradicts a contract or another story.
- You need a paid API key or a cloud resource.
- The same test has failed after 3 different fix attempts.
