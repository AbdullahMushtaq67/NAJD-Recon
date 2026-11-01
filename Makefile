VENV := backend/.venv
PY := $(if $(wildcard $(VENV)/bin/python),$(CURDIR)/$(VENV)/bin/python,python3)
HAS_NPM := $(shell command -v npm 2>/dev/null)

.PHONY: help setup up down demo dev-backend dev-frontend test lint

help:          ## List the available commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-13s %s\n", $$1, $$2}'

setup:         ## One-time: create backend/.venv with dev tools (and frontend packages if npm exists)
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -q --upgrade pip
	$(VENV)/bin/python -m pip install -q -r backend/requirements-dev.txt
ifdef HAS_NPM
	cd frontend && npm ci
else
	@echo "npm not found: skipped frontend packages (only needed for the typecheck in 'make lint')"
endif

up:            ## Build and start the app + practice lab (http://localhost:8080)
	docker compose up --build -d

down:          ## Stop everything
	docker compose down

demo:          ## Start in demo mode (replays a recorded scan, sends no packets)
	DEMO_MODE=true docker compose up --build -d backend frontend

dev-backend:   ## Run the API locally with auto-reload (needs nmap installed)
	cd backend && $(PY) -m uvicorn app.main:app --reload

dev-frontend:  ## Run the Vite dev server (http://localhost:5173)
	cd frontend && npm run dev

test:          ## Run the backend test suite
	cd backend && $(PY) -m pytest -q

lint:          ## Lint + security-scan the backend, typecheck the frontend
	cd backend && $(PY) -m ruff check . && $(PY) -m bandit -q -c pyproject.toml -r app
ifdef HAS_NPM
	@if [ -d frontend/node_modules ]; then cd frontend && npm run typecheck; \
	else echo "frontend/node_modules missing: run 'make setup' to typecheck the frontend"; fi
else
	@echo "npm not found: skipped the frontend typecheck"
endif
