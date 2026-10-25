SHELL := /bin/bash
RUN := uv run
UNIT_MARKS := not services and not docker and not e2e and not slow

# pytest exits 5 when nothing was collected. That is fine while a directory is still empty.
define pytest
$(RUN) pytest $(1); rc=$$?; if [ $$rc -ne 0 ] && [ $$rc -ne 5 ]; then exit $$rc; fi
endef

# Compose reads .env from the compose file's directory by default. Point it at the repo root instead.
COMPOSE := docker compose -f deploy/docker-compose.yml $(if $(wildcard .env),--env-file .env)

# The console has its own package, and console/.nvmrc names the Node version it runs on.
CONSOLE := pnpm --dir console

.PHONY: help prose commits setup lint fmt type policy test-unit test-int test-e2e test check ci-local migrate gate up up-core down reset demo demo-attack github-setup console-types console-check console-e2e sandbox-image echo-image perf perf-smoke tf-plan

help:
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | column -t -s $$'\t'

prose: ## voice rules: banned words and em dashes
	$(RUN) python scripts/lint_prose.py

commits: ## check commit subjects since main
	@status=0; while IFS= read -r subject; do \
		python3 scripts/check_commit_msg.py "$$subject" || status=1; \
	done < <(git log origin/main..HEAD --no-merges --format=%s); exit $$status

setup: ## install dependencies and the pre-commit hook
	uv sync
	$(RUN) pre-commit install

lint: ## ruff check and format check
	$(RUN) ruff check .
	$(RUN) ruff format --check .

fmt: ## apply ruff fixes and formatting
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

type: ## mypy
	$(RUN) mypy

policy: ## the policy cases, and every policy matched by a case
	$(RUN) keystone policy test policies tests/policy_cases --coverage

test-unit: ## unit tests and invariants that need no services
	@$(call pytest,tests/unit tests/invariants -m "$(UNIT_MARKS)")

# The tests marked `docker` run the sandbox and a containerized server. Here they must run: a skip
# would hide a broken one.
test-int: sandbox-image echo-image ## integration tests (needs postgres, redis and Docker)
	@KEYSTONE_REQUIRE_DOCKER=1 $(call pytest,tests/integration tests/invariants -m "not e2e and not slow")

test-e2e: ## end-to-end tests against the compose stack
	@$(call pytest,tests/e2e -m e2e)

test: test-unit test-int ## unit plus integration

check: up-core lint type test-unit test-int console-check ## lint, types, unit, integration, console

migrate: ## apply database migrations to KEYSTONE_DATABASE_URL
	$(RUN) alembic upgrade head

ci-local: up-core ## the same steps as CI, run locally
	uv sync --locked
	$(MAKE) lint type policy test-unit test-int
	$(MAKE) console-types
	git diff --exit-code -- console/src/api/schema.d.ts
	$(MAKE) console-check
	gitleaks git --no-banner --redact .
	@req=$$(mktemp) && uv export --no-emit-project -o $$req >/dev/null \
		&& $(RUN) pip-audit -r $$req --no-deps --disable-pip; rc=$$?; rm -f $$req; exit $$rc
	docker build -t keystone:ci .
	docker run --rm keystone:ci --help >/dev/null
	docker run --rm keystone:ci version
	$(MAKE) commits prose

gate: up echo-image ## everything a phase gate runs: make gate PHASE=N (9 runs phases 0 to 8 inside phase_9.sh)
	@test -n "$(PHASE)" || { echo "usage: make gate PHASE=N" >&2; exit 2; }
	@if [ $(PHASE) -ge 7 ]; then uv sync --locked --extra scanner --extra eval; fi
	$(MAKE) lint type
	@if [ $(PHASE) -ge 4 ]; then $(MAKE) policy; fi
	KEYSTONE_REQUIRE_DOCKER=1 $(RUN) pytest --phase $(PHASE) tests/unit tests/integration tests/invariants tests/e2e
	@if [ $(PHASE) -ge 6 ]; then $(MAKE) console-check console-e2e; fi
	@k=0; while [ $$k -le $(PHASE) ]; do \
		f=scripts/smoke/phase_$$k.sh; \
		if [ $$k -lt 9 ] && [ $(PHASE) -ge 9 ]; then k=$$((k+1)); continue; fi; \
		if [ -f $$f ]; then echo "== smoke: phase $$k"; bash $$f || exit 1; fi; \
		k=$$((k+1)); \
	done

perf: ## the performance matrix against the running stack: 5 targets, 200 sessions (about an hour)
	$(RUN) python -m eval.perf.matrix

tf-plan: ## terraform plan for deploy/terraform/aws with the example variables (needs AWS credentials)
	cd deploy/terraform/aws && terraform init -input=false && terraform validate \
		&& terraform plan -input=false -var-file=terraform.tfvars.example

perf-smoke: ## 10 sessions x 5 calls against the running stack, as the nightly job does
	$(RUN) python -m eval.perf.matrix --smoke

console-types: ## regenerate console/src/api/schema.d.ts from the admin API's schema
	$(RUN) python scripts/dump_openapi.py console/openapi.json
	$(CONSOLE) install --frozen-lockfile
	$(CONSOLE) gen:api

console-check: ## console: lint, unit tests and the production build
	$(CONSOLE) install --frozen-lockfile
	$(CONSOLE) lint
	$(CONSOLE) test
	$(CONSOLE) build

console-e2e: ## console: the Playwright test, in headless chromium, against the compose stack
	$(CONSOLE) install --frozen-lockfile
	$(CONSOLE) exec playwright install chromium
	$(CONSOLE) e2e

sandbox-image: ## build the image the sandbox runs code in (the compose stack builds it too)
	docker build -q -t keystone-sandbox-python:dev -f deploy/sandbox/Dockerfile.python deploy/sandbox >/dev/null

echo-image: ## build the echo server as a stdio image, for the containerized upstream tests
	docker build -q -t keystone-echo-stdio:dev -f examples/upstreams/Dockerfile.echo . >/dev/null

up: ## build and start the local stack and wait until every service is healthy
	$(COMPOSE) up -d --build --wait

up-core: ## start only postgres and redis
	$(COMPOSE) up -d --wait postgres redis

down: ## stop the local stack
	$(COMPOSE) down

reset: ## stop the stack and remove its volumes
	$(COMPOSE) down -v

demo: up ## start the stack, reset the upstreams and run the scripted agent
	bash scripts/smoke/phase_1.sh

demo-attack: up ## the headline demo: an injected email, with and without Keystone
	bash scripts/demo_attack.sh

github-setup: ## protect main and dev, then import the backlog (needs a signed-in gh)
	@gh auth status >/dev/null 2>&1 || { \
		echo "gh is not signed in. Run 'gh auth login', then 'make github-setup'." >&2; exit 1; }
	bash scripts/protect_branches.sh
	$(RUN) python scripts/import_backlog.py
