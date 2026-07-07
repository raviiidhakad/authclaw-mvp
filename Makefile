# AuthClaw local validation entry point.
# Backend validation is container-first to avoid host Python/pytest drift.

COMPOSE ?= docker compose
API := $(COMPOSE) exec -T api
WEB := apps/web

.PHONY: help preflight services services-api compose-check test-backend test-integration test-frontend test-playwright test-playwright-host quality tf-check validate security-note

help:
	@echo "AuthClaw validation targets:"
	@echo "  make preflight        Check Docker/Compose access"
	@echo "  make services-api     Start db/redis/redpanda/vault/clickhouse/api"
	@echo "  make test-backend     Run full backend suite inside api container"
	@echo "  make test-integration Run focused integration slices inside api container"
	@echo "  make test-frontend    Run lint, typecheck, and build"
	@echo "  make test-playwright  Run Playwright in the official browser container"
	@echo "  make quality          Run compileall plus CI-equivalent ruff correctness check"
	@echo "  make tf-check         Run Terraform static validation if terraform is available"
	@echo "  make validate         Run the canonical fast local gate"

preflight:
	@echo "Checking Docker daemon and Compose config..."
	@docker info >/dev/null 2>&1 || (echo "Docker is not accessible. Start Docker Desktop and ensure this shell can access the Docker pipe." && exit 1)
	@$(COMPOSE) config --quiet
	@echo "Preflight passed."

compose-check:
	$(COMPOSE) config --quiet

services:
	$(COMPOSE) up -d --wait db redis redpanda vault clickhouse

services-api: preflight
	$(COMPOSE) up -d --wait db redis redpanda vault clickhouse api

test-backend: services-api
	$(API) python -m pytest -q --timeout=180 --timeout-method=thread

test-integration: services-api
	$(API) python -m pytest tests/test_rls_isolation.py tests/test_engine.py tests/test_limiter.py tests/test_streaming.py tests/test_azure_auth.py tests/integration/test_event_backbone.py -q --timeout=180 --timeout-method=thread

test-frontend:
	cd $(WEB) && npm run lint
	cd $(WEB) && npx tsc --noEmit
	cd $(WEB) && NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 npm run build

test-playwright-host:
	@echo "Host Playwright is optional on Windows. If Chromium spawn fails, use: make test-playwright"
	cd $(WEB) && npx playwright test

test-playwright:
	@echo "Running Playwright in official container. Requires services-api and network authclawproject_default."
	docker run --rm --network authclawproject_default \
	  --mount type=bind,source="$(CURDIR)/apps/web",target=/app \
	  -v authclaw_playwright_node_modules:/app/node_modules \
	  -w /app \
	  -e CI=1 \
	  -e PLAYWRIGHT_BASE_URL=http://127.0.0.1:3000 \
	  -e NEXT_PUBLIC_API_URL=http://api:8000/api/v1 \
	  mcr.microsoft.com/playwright:v1.60.0-jammy \
	  sh -lc "npm ci && npx playwright test"

quality: services-api
	$(API) python -m compileall -q app
	$(COMPOSE) exec -T -u root api python -m pip install ruff -q
	$(API) python -m ruff check app --select E9,F821,F822,F823

tf-check:
	@if command -v terraform >/dev/null 2>&1; then \
	  terraform fmt -check -recursive infrastructure/terraform && \
	  terraform -chdir=infrastructure/terraform/environments/dev init -backend=false && \
	  terraform -chdir=infrastructure/terraform/environments/dev validate; \
	else \
	  echo "Terraform is not on PATH. Use the repo-local .tools/terraform binary if available, or install Terraform."; \
	  exit 1; \
	fi

validate: services-api test-backend test-frontend quality compose-check
	@echo "Canonical fast validation passed. Run make test-integration, make test-playwright, and make tf-check for extended gates."

security-note:
	@echo "Security scans are CI-owned: bandit, semgrep, Trivy, OSV, pip-audit."

