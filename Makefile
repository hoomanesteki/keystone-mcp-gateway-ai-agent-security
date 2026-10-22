SHELL := /bin/bash
RUN := uv run
UNIT_MARKS := not services and not docker and not e2e and not slow

# pytest exits 5 when nothing was collected. That is fine while a directory is still empty.
define pytest
$(RUN) pytest $(1); rc=$$?; if [ $$rc -ne 0 ] && [ $$rc -ne 5 ]; then exit $$rc; fi
endef

.PHONY: help setup lint fmt type test-unit test-int test-e2e test check gate up down reset demo

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
	@echo "not available until KS-004"

test-e2e: ## end-to-end tests against the compose stack
	@echo "not available until KS-002"

test: test-unit test-int ## unit plus integration

check: lint type test-unit test-int ## lint, types, unit, integration

gate: up ## everything a phase gate runs: make gate PHASE=N
	@test -n "$(PHASE)" || { echo "usage: make gate PHASE=N" >&2; exit 2; }
	$(MAKE) lint type
	$(RUN) pytest --phase $(PHASE) tests/unit tests/integration tests/invariants tests/e2e
	@k=0; while [ $$k -le $(PHASE) ]; do \
		f=scripts/smoke/phase_$$k.sh; \
		if [ -f $$f ]; then echo "== smoke: phase $$k"; bash $$f || exit 1; fi; \
		k=$$((k+1)); \
	done

up: ## start the local stack
	@echo "not available until KS-002"

down: ## stop the local stack
	@echo "not available until KS-002"

reset: ## stop the stack and remove its volumes
	@echo "not available until KS-002"

demo: ## run the scripted agent demo
	@echo "not available until KS-108"
