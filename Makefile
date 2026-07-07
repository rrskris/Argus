# Argus developer Makefile.
# Goal: git clone -> scanning a deliberately-vulnerable cluster in under 2 minutes.
#
# Quick start for a new contributor:
#   make setup-dev        # kind cluster + planted RBAC misconfigurations
#   make db               # throwaway Postgres for the control plane / tests
#   make test             # run the control-plane test suite
#   make scan             # run the RBAC scanner against the testbed (no server needed)
#   make teardown-dev     # tear it all down

KIND_CLUSTER  ?= argus-dev
PG_CONTAINER  ?= argus-dev-pg
PG_PORT       ?= 55432
DATABASE_URL  ?= postgresql://argus:password@127.0.0.1:$(PG_PORT)/argus_db
FIXTURES      ?= hack/dev/rbac-fixtures.yaml
VENV          ?= .venv
PY            := $(VENV)/bin/python

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ── Vulnerable testbed ─────────────────────────────────────────────────────────

.PHONY: setup-dev
setup-dev: ## Create a kind cluster with planted RBAC misconfigurations (the testbed)
	kind create cluster --name $(KIND_CLUSTER) --wait 120s
	kubectl --context kind-$(KIND_CLUSTER) apply -f $(FIXTURES)
	@echo "\nTestbed ready. It contains deliberately-vulnerable RBAC objects."
	@echo "Run 'make scan' to see the scanner rank them, or point the control plane at it."

.PHONY: teardown-dev
teardown-dev: ## Delete the kind testbed cluster
	kind delete cluster --name $(KIND_CLUSTER)

# ── Python env / database ──────────────────────────────────────────────────────

$(VENV): control-plane/requirements.txt
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r control-plane/requirements.txt
	@touch $(VENV)

.PHONY: venv
venv: $(VENV) ## Create the control-plane virtualenv with pinned deps

.PHONY: db
db: ## Start a throwaway Postgres (for tests or a local control plane)
	docker run -d --name $(PG_CONTAINER) \
		-e POSTGRES_USER=argus -e POSTGRES_PASSWORD=password -e POSTGRES_DB=argus_db \
		-p $(PG_PORT):5432 postgres:16-alpine
	@echo "Waiting for Postgres..."
	@until docker exec $(PG_CONTAINER) pg_isready -U argus -d argus_db >/dev/null 2>&1; do sleep 1; done
	@echo "Postgres ready on port $(PG_PORT)."

.PHONY: db-stop
db-stop: ## Remove the throwaway Postgres
	-docker rm -f $(PG_CONTAINER)

# ── Test / scan / run ──────────────────────────────────────────────────────────

.PHONY: test
test: venv ## Run the control-plane test suite (needs 'make db' first)
	cd control-plane && DATABASE_URL="$(DATABASE_URL)" ../$(PY) -m pytest tests/ -q

.PHONY: scan
scan: venv ## Run the RBAC scanner against the current kubeconfig context (no server)
	cd control-plane && ../$(PY) -m app.cli scan rbac --output table

.PHONY: scan-manifests
scan-manifests: venv ## Shift-left: scan the fixture manifests without a cluster
	cd control-plane && ../$(PY) -m app.cli scan rbac --manifests ../$(FIXTURES) --output table

.PHONY: dev-api
dev-api: venv ## Run the control plane locally against $(DATABASE_URL) + your kubeconfig
	cd control-plane && DATABASE_URL="$(DATABASE_URL)" ../$(PY) -m uvicorn app.main:app --reload --port 8000

.PHONY: dev-dashboard
dev-dashboard: ## Run the Next.js dashboard in dev mode
	cd dashboard && npm install && NEXT_PUBLIC_API_URL=http://127.0.0.1:8000 npm run dev

.PHONY: up
up: ## Bring up the full docker-compose stack (Postgres + control plane + dashboard)
	docker compose -f deploy/docker-compose.yml up -d

.PHONY: down
down: ## Stop the docker-compose stack
	docker compose -f deploy/docker-compose.yml down

.PHONY: clean
clean: teardown-dev db-stop ## Tear down the testbed and throwaway Postgres
	rm -rf $(VENV)
