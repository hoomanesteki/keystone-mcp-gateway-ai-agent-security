SHELL := /bin/bash
RUN := uv run
UNIT_MARKS := not services and not docker and not e2e and not slow

# pytest exits 5 when nothing was collected. That is fine while a directory is still empty.
define pytest
$(RUN) pytest $(1); rc=$$?; if [ $$rc -ne 0 ] && [ $$rc -ne 5 ]; then exit $$rc; fi
endef

# Compose reads .env from the compose file's directory by default. Point it at the repo root instead.
COMPOSE := docker compose -f deploy/docker-compose.yml $(if $(wildcard .env),--env-file .env)

.PHONY: help setup lint fmt type test-unit test-int test-e2e test check ci-local gate up up-core down reset demo github-setup

help:
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | column -t -s $$'\t'

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

test-unit: ## unit tests and invariants that need no services
	@$(call pytest,tests/unit tests/invariants -m "$(UNIT_MARKS)")

test-int: ## integration tests (needs postgres and redis)
	@$(call pytest,tests/integration tests/invariants -m "not e2e and not slow")

test-e2e: ## end-to-end tests against the compose stack
	@$(call pytest,tests/e2e -m e2e)

test: test-unit test-int ## unit plus integration

check: up-core lint type test-unit test-int ## lint, types, unit, integration

ci-local: up-core ## the same steps as CI, run locally
	uv sync --locked
	$(MAKE) lint type test-unit test-int
	gitleaks git --no-banner --redact .
	@req=$$(mktemp) && uv export --no-emit-project -o $$req >/dev/null \
		&& $(RUN) pip-audit -r $$req --no-deps --disable-pip; rc=$$?; rm -f $$req; exit $$rc
	docker build -t keystone:ci .
	docker run --rm keystone:ci --help >/dev/null
	docker run --rm keystone:ci version

gate: up ## everything a phase gate runs: make gate PHASE=N
	@test -n "$(PHASE)" || { echo "usage: make gate PHASE=N" >&2; exit 2; }
	$(MAKE) lint type
	$(RUN) pytest --phase $(PHASE) tests/unit tests/integration tests/invariants tests/e2e
	@k=0; while [ $$k -le $(PHASE) ]; do \
		f=scripts/smoke/phase_$$k.sh; \
		if [ -f $$f ]; then echo "== smoke: phase $$k"; bash $$f || exit 1; fi; \
		k=$$((k+1)); \
	done

up: ## start the local stack and wait until every service is healthy
	$(COMPOSE) up -d --wait

up-core: ## start only postgres and redis
	$(COMPOSE) up -d --wait postgres redis

down: ## stop the local stack
	$(COMPOSE) down

reset: ## stop the stack and remove its volumes
	$(COMPOSE) down -v

demo: ## run the scripted agent demo
	@echo "not available until KS-108"

github-setup: ## protect main and dev (needs a signed-in gh)
	@gh auth status >/dev/null 2>&1 || { \
		echo "gh is not signed in. Run 'gh auth login', then 'make github-setup'." >&2; exit 1; }
	bash scripts/protect_branches.sh
