# Targets from docs/DESIGN.md §2.4. Unimplemented ones fail loudly so a stub never looks like a pass.
# Anything that contacts real sites depends on `selftest`, so it can't run unless isolation is proven.
PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

RUN_ID ?= $(shell date +%Y-%m-%dT%H-%M-%S)
# The Mac's default gateway (home router), so selftest proves the proxy blocks it.
ROUTER_IP ?= $(shell route -n get default 2>/dev/null | awk '/gateway:/{print $$2}')
COMPOSE := RUN_ID=$(RUN_ID) SELFTEST_ROUTER_IP=$(ROUTER_IP) docker compose

.PHONY: build selftest triage run rescore eval report test test-browser lint venv down

$(BIN)/python: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e ".[dev]"
	@touch $(BIN)/python

venv: $(BIN)/python

test: venv
	$(BIN)/pytest -q

test-browser:
	docker compose --profile test build browser-tests
	docker compose --profile test run --rm browser-tests

lint: venv
	$(BIN)/ruff check src tests eval docker

build:
	$(COMPOSE) build

selftest: build
	@mkdir -p runs/$(RUN_ID)
	$(COMPOSE) up -d --force-recreate --wait egress-proxy llm-gateway
	$(COMPOSE) run --rm crawler python docker/selftest.py

triage: selftest
	$(COMPOSE) run --rm crawler scamhunter triage --run-id $(RUN_ID) $(ARGS)

down:
	docker compose down

run: selftest
	@echo "make run: not implemented (M2)"; exit 1

rescore:
	@echo "make rescore: not implemented (M2)"; exit 1

eval:
	@echo "make eval: not implemented (M4)"; exit 1

report:
	@echo "make report: not implemented (M2)"; exit 1
