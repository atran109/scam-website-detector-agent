# Targets from docs/DESIGN.md §2.4. Unimplemented ones fail loudly so a stub never looks like a pass.
# Anything that contacts real sites depends on `selftest`, so it can't run unless isolation is proven.
PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

RUN_ID ?= $(shell date +%Y-%m-%dT%H-%M-%S)
# The Mac's default gateway (home router), so selftest proves the proxy blocks it.
ROUTER_IP ?= $(shell route -n get default 2>/dev/null | awk '/gateway:/{print $$2}')
COMPOSE := RUN_ID=$(RUN_ID) SELFTEST_ROUTER_IP=$(ROUTER_IP) docker compose

.PHONY: agent-mock pipeline-mock pilot review build selftest triage run capture classify label rescore eval report test test-browser lint check venv down

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
	$(BIN)/ruff check src tests eval docker scripts
	$(BIN)/ruff format --check src tests eval docker scripts

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

# Evidence only (LOG 2026-10-06 22:00): landing capture of live sites, no clicks, no agent, no LLM.
capture: selftest
	$(COMPOSE) run --rm crawler scamhunter capture --run-id $(RUN_ID) $(ARGS)

# M3 step E: Claude (via the gateway) drives the local mock exchange. Mock mode: the browser
# reaches loopback only. Gated on selftest, which proves that. Spend cap: --spend-cap (USD).
# No waiver: the rebinding probe no longer depends on the network's DNS (LOG 2026-10-07), so mock
# runs and real runs use the same full selftest gate.
agent-mock: build
	@mkdir -p runs/$(RUN_ID)
	$(COMPOSE) up -d --force-recreate --wait egress-proxy llm-gateway
	$(COMPOSE) run --rm crawler python docker/selftest.py
	$(COMPOSE) run --rm crawler scamhunter agent-mock --run-id $(RUN_ID) $(ARGS)

# The 10 mock variants through process_site (capture, judge, navigator, judge, build_result):
# the real-site path against the loopback-only mock. Same selftest gate as agent-mock.
pipeline-mock: build
	@mkdir -p runs/$(RUN_ID)
	$(COMPOSE) up -d --force-recreate --wait egress-proxy llm-gateway
	$(COMPOSE) run --rm crawler python docker/selftest.py
	$(COMPOSE) run --rm crawler scamhunter pipeline-mock --run-id $(RUN_ID) $(ARGS)

# Watched real-site pilot (LOG 2026-10-07): Sonnet 5.5 navigator and judge, 30 steps, 300 s per
# site, $5 session cap, one site at a time, navigation forced (the trigger is not under test),
# confirm before each site's first form submission, in the order below. Stop everything with:
# touch runs/<run id>/STOP. Full selftest first (via `run`). Needs a terminal for the prompts.
# Always pass a NEW RUN_ID (or none); continue a run with PILOT_ARGS=--resume.
PILOT_SITES ?= 027,055,145,012,021,128,071,117
pilot:
	$(MAKE) run ARGS="--only $(PILOT_SITES) --force-navigation --confirm-submit --max-steps 30 --max-seconds 300 --spend-cap 5 $(PILOT_ARGS)"

# Judge every site of a (capture-only) run from its saved evidence: no visits, no agent. Needs
# the gateway (a few cents per site). Rebuilds the image first, like rescore.
classify: build
	@test -n "$(RUN)" || (echo "usage: make classify RUN=<run id>"; exit 1)
	$(COMPOSE) up -d --wait llm-gateway
	$(COMPOSE) run --rm --no-deps crawler scamhunter classify --run-id $(notdir $(RUN)) $(ARGS)

# Dataset labeller (DESIGN §8.4): first-draft labels from a run's saved evidence, for human
# review. No visits. Needs the gateway (Opus; about $0.05-0.08 a site). ARGS must give
# --spend-cap; --manifest defaults to data/dataset/v1/manifest.jsonl.
label: build
	@test -n "$(RUN)" || (echo "usage: make label RUN=<run id> ARGS=\"--spend-cap 40\""; exit 1)
	$(COMPOSE) up -d --wait llm-gateway
	$(COMPOSE) run --rm --no-deps crawler scamhunter label --run-id $(notdir $(RUN)) $(ARGS)

# Re-classify from saved evidence; no site visits, so no selftest gate. Needs the gateway.
RUN ?=
# Depends on build: the rescore runs in the crawler image, so code changes must be in it
# (2026-10-07: a rescore without a rebuild ran the old code and looked like a no-op).
rescore: build
	@test -n "$(RUN)" || (echo "usage: make rescore RUN=runs/<id>"; exit 1)
	$(COMPOSE) up -d --wait llm-gateway
	$(COMPOSE) run --rm --no-deps crawler scamhunter rescore --run-id $(notdir $(RUN)) $(ARGS)

# Precision/recall at 0.45 and 0.5 against eval/labels.csv (no containers, no network).
eval: venv
	@test -n "$(RUN)" || (echo "usage: make eval RUN=<run id>"; exit 1)
	$(BIN)/python eval/evaluate.py runs/$(notdir $(RUN))/output/results.json $(ARGS)

# Read-only: builds runs/<id>/review/index.html from saved evidence. No containers, no network.
review: venv
	@test -n "$(RUN)" || (echo "usage: make review RUN=<run id>"; exit 1)
	$(BIN)/scamhunter review --run-id $(notdir $(RUN))

report:
	@test -n "$(RUN)" || (echo "usage: make report RUN=runs/<id>"; exit 1)
	$(BIN)/scamhunter report --run-id $(notdir $(RUN)) $(ARGS)
