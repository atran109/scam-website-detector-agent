# Targets from docs/DESIGN.md §2.4. Unimplemented ones fail loudly so a stub never looks like a pass.
PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

.PHONY: build selftest triage run rescore eval report test lint venv

$(BIN)/python: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e ".[dev]"
	@touch $(BIN)/python

venv: $(BIN)/python

test: venv
	$(BIN)/pytest -q

lint: venv
	$(BIN)/ruff check src tests eval

build:
	@echo "make build: not implemented (M1: docker build)"; exit 1

selftest:
	@echo "make selftest: not implemented (M1: egress/isolation checks)"; exit 1

triage:
	@echo "make triage: not implemented (M1)"; exit 1

run:
	@echo "make run: not implemented (M2)"; exit 1

rescore:
	@echo "make rescore: not implemented (M2)"; exit 1

eval:
	@echo "make eval: not implemented (M4)"; exit 1

report:
	@echo "make report: not implemented (M2)"; exit 1
