# Targets from docs/DESIGN.md §2.4. Unimplemented ones fail loudly so a stub never looks like a pass.
# Anything that contacts real sites depends on `selftest`, so it can't run unless isolation is proven.
PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

RUN_ID ?= $(shell date +%Y-%m-%dT%H-%M-%S)
# The Mac's default gateway (home router), so selftest proves the proxy blocks it.
ROUTER_IP ?= $(shell route -n get default 2>/dev/null | awk '/gateway:/{print $$2}')
COMPOSE := RUN_ID=$(RUN_ID) SELFTEST_ROUTER_IP=$(ROUTER_IP) docker compose

.PHONY: agent-mock review build selftest triage run rescore eval report test test-browser lint check venv down

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
	$(BIN)/ruff format --check src tests eval docker

# Run before every commit: lint (incl. formatting) + unit tests.
check: lint test

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
	$(COMPOSE) run --rm crawler scamhunter run --run-id $(RUN_ID) $(ARGS)

# M3 step E: Claude (via the gateway) drives the local mock exchange. Mock mode: the browser
# reaches loopback only. Gated on selftest, which proves that. Spend cap: --spend-cap (USD).
# SELFTEST_WAIVER=rebind-probe (decided 2026-10-06, mock only): accept a selftest whose ONLY
# failures are the nip.io DNS-rebinding probe (docker/selftest_waiver.py). Real-site targets
# (triage, run) never read it and keep the full selftest gate.
SELFTEST_WAIVER ?=
agent-mock: build
	@mkdir -p runs/$(RUN_ID)
	$(COMPOSE) up -d --force-recreate --wait egress-proxy llm-gateway
ifeq ($(SELFTEST_WAIVER),rebind-probe)
	-$(COMPOSE) run --rm crawler python docker/selftest.py
	$(BIN)/python docker/selftest_waiver.py runs/$(RUN_ID)/selftest.json
else
	$(COMPOSE) run --rm crawler python docker/selftest.py
endif
	$(COMPOSE) run --rm crawler scamhunter agent-mock --run-id $(RUN_ID) $(ARGS)

# Re-classify from saved evidence; no site visits, so no selftest gate. Needs the gateway.
RUN ?=
rescore:
	@test -n "$(RUN)" || (echo "usage: make rescore RUN=runs/<id>"; exit 1)
	$(COMPOSE) up -d --wait llm-gateway
	$(COMPOSE) run --rm --no-deps crawler scamhunter rescore --run-id $(notdir $(RUN))

eval:
	@echo "make eval: not implemented (M4)"; exit 1

# Read-only: builds runs/<id>/review/index.html from saved evidence. No containers, no network.
review: venv
	@test -n "$(RUN)" || (echo "usage: make review RUN=<run id>"; exit 1)
	$(BIN)/scamhunter review --run-id $(notdir $(RUN))

report:
	@test -n "$(RUN)" || (echo "usage: make report RUN=runs/<id>"; exit 1)
	$(BIN)/scamhunter report --run-id $(notdir $(RUN))
