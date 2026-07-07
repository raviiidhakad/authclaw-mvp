# TEST ENVIRONMENT READINESS REPORT

AuthClaw MVP - test and validation environment reliability audit  
Date: 2026-07-07  
Scope: tooling, validation commands, and host/container reproducibility only. No application features changed.

## 1. Root Causes Found

1. Docker access is context-dependent. Docker Desktop is running, but sandboxed shells can fail with Windows named-pipe or Docker config permission errors. This is not an application defect.
2. Host Playwright on Windows fails with `browserType.launch: spawn EPERM` for local Chromium executables under the user profile/OneDrive context. `Unblock-File` was attempted and did not fix the launch.
3. Host Python/pytest is not a stable validation surface. The reliable backend environment is the repository API container, which has `apps/api/requirements.txt` installed.
4. Security scanners are correctly CI-owned. They should not be installed into the production API image merely for local convenience.
5. Validation commands were previously scattered across CI YAML, ad hoc host commands, and Docker commands. The root `Makefile` is now the canonical local entry point.

## 2. Environment Architecture

The canonical backend path is container-first:

```bash
docker compose up -d --wait db redis redpanda vault clickhouse api
docker compose exec -T api python -m pytest -q
```

Frontend lint/typecheck/build remain npm-based because that is already how `apps/web/package.json` and CI are defined.

Playwright has two paths:

- host path: optional, may fail on Windows/OneDrive with `spawn EPERM`
- container path: preferred, uses `mcr.microsoft.com/playwright:v1.60.0-jammy`

## 3. Execution Matrix

| Validation task | Current execution environment | Required dependencies | Reproducible? | Current blocker | Minimal fix |
|---|---|---|---|---|---|
| Backend unit tests | API container | pytest, app deps | Yes when Docker accessible | sandbox Docker pipe can block | run through `make test-backend` locally |
| Backend integration tests | API container + Compose services | pytest-timeout, Kafka, ClickHouse, Vault deps | Yes when Docker accessible | service readiness if Compose not up | `make test-integration` |
| Kafka/Redpanda tests | API container + Redpanda | aiokafka | Yes | Docker access only | API-container command |
| ClickHouse tests | API container + ClickHouse | aiochclient/aiohttp | Yes | Docker access only | API-container command |
| Vault tests | API container + Vault | hvac | Yes | Docker access only | API-container command |
| OPA tests | API container + OPA profile | httpx, OPA sidecar | Partial | OPA profile must be started | `docker compose --profile opa up -d opa` |
| Frontend lint | host/CI Node | npm deps | Yes | none observed | `npm run lint` |
| Frontend build | host/CI Node | npm deps | Yes | none observed | `npm run build` |
| Frontend unit tests | none configured | package script absent | N/A | no `npm test` script | do not invent script |
| Playwright E2E | host Chromium or container | Chromium browser | Host no, container intended | Windows `spawn EPERM`; image pull may be unavailable | use `make test-playwright` in normal Docker/network environment |
| Security scans | GitHub Actions | bandit, semgrep, Trivy, OSV, pip-audit | CI yes | not local by design | keep CI-owned |
| Terraform fmt | host/repo-local Terraform | terraform binary | Partial | binary not guaranteed on PATH | `make tf-check` or `.tools/terraform` |
| Terraform validate | host/repo-local Terraform | terraform binary/init | Partial | external binary | `terraform init -backend=false && terraform validate` |

## 4. Canonical Local Validation Command

Fast local gate when `make` is installed:

```bash
make validate
```

Expanded gates:

```bash
make test-integration
make test-playwright
make tf-check
```

Direct equivalents if `make` is not available:

```bash
docker compose up -d --wait db redis redpanda vault clickhouse api
docker compose exec -T api python -m pytest -q
cd apps/web && npm run lint
cd apps/web && npx tsc --noEmit
cd apps/web && npm run build
docker compose config --quiet
```

In the current PowerShell execution context, `make` is not installed, so the direct Docker/npm equivalents are the verified path.

## 5. Canonical CI Validation Path

Existing CI remains authoritative:

- `.github/workflows/ci-fast.yml` - backend unit suite and coverage
- `.github/workflows/ci-quality.yml` - compileall and ruff correctness checks
- `.github/workflows/ci-frontend.yml` - lint, typecheck, build, Playwright
- `.github/workflows/ci-integration.yml` - Docker-backed integration slices
- `.github/workflows/ci-security.yml` - Bandit, Semgrep, Trivy filesystem, OSV, pip-audit
- `.github/workflows/ci-container.yml` - container build, Trivy image scan, SBOM

## 6. Playwright Execution Solution

Observed host failure:

```text
browserType.launch: spawn EPERM
```

This occurred for both:

- `chromium_headless_shell-1223/.../chrome-headless-shell.exe`
- `chromium-1223/.../chrome.exe`

`Unblock-File` was run against both executables and the failure persisted. The reliable repository path is therefore containerized Playwright:

```bash
make test-playwright
```

If the Playwright image is not already available, Docker must be allowed to pull:

```text
mcr.microsoft.com/playwright:v1.60.0-jammy
```

Do not mark Playwright passed unless the browser tests execute.

## 7. Docker Prerequisite and Preflight Behavior

Preflight command:

```bash
make preflight
```

It validates:

- Docker daemon reachable
- `docker-compose.yml` parses

Observed distinction:

- Docker daemon was running.
- Non-escalated sandbox shell failed with Docker config/pipe permission errors.
- Escalated Docker commands succeeded.

This is an execution-context permission issue, not an app/runtime defect.

## 8. Backend Toolchain Coverage

`apps/api/requirements.txt` contains the backend test/runtime dependencies required for normal API-container validation:

- `pytest`
- `pytest-asyncio`
- `pytest-cov`
- `pytest-timeout`
- `aiokafka`
- `aiochclient`
- `hvac`
- `httpx`
- `alembic`

Security tooling remains CI-only:

- Bandit
- Semgrep
- Trivy
- OSV scanner
- pip-audit

## 9. Service Readiness Strategy

Compose readiness uses health checks or explicit service startup:

- PostgreSQL: `pg_isready`
- Redis: `redis-cli ping`
- Redpanda: `rpk cluster health`
- ClickHouse: `SELECT 1`
- Vault: unsealed status check
- API: HTTP readiness check against local docs endpoint
- OPA: profile-gated, started only for OPA validation

No arbitrary sleeps are required in the canonical backend path.

## 10. Commands Executed

| Command | Result |
|---|---|
| `docker compose ps` | Passed with escalated Docker access; services running |
| `docker compose config --quiet` | Passed |
| `make preflight` | Not run; `make` is not installed in this PowerShell environment |
| `npx playwright test real-stack-smoke.spec.ts --list` | Passed; 2 tests collected |
| `AUTHCLAW_REAL_STACK_SMOKE=1 npx playwright test real-stack-smoke.spec.ts -g "real backend denies"` | Passed; 1 passed |
| same real-backend negative smoke repeated twice | Passed; 1 passed each run |
| host browser smoke | Failed with `spawn EPERM` |
| Docker Playwright image path | Blocked/hung while pulling image; no pass claimed |
| `npm run lint` | Passed |
| `npx tsc --noEmit` | Passed |
| `npm run build` | Passed |
| `docker compose exec -T api python -m pytest tests/test_gateway_mvp_phase1.py tests/test_rls_isolation.py -q` | Passed; 17 passed |

## 11. Results

Confirmed:

- Docker Compose config is valid.
- API-container backend regression slice is healthy.
- Frontend lint/typecheck/build pass.
- Real backend authorization and tenant-isolation smoke path passes.
- Host Playwright remains blocked by Windows `spawn EPERM`.
- Containerized Playwright is the correct path, but it requires image availability/pull permission.

## 12. Remaining External Host Limitations

| Limitation | Classification | Repository fix? |
|---|---|---|
| Docker pipe/config permission in sandbox | coding-agent/host permission | No |
| Host Chromium `spawn EPERM` | Windows/OneDrive/browser execution | No reliable app-code fix |
| Playwright image unavailable locally | external Docker image pull | Requires network/image cache |
| Terraform binary not guaranteed | host tooling | Use documented `tf-check` or repo-local `.tools` if present |

## 13. Exact Prerequisites for a New Developer Machine

Required:

1. Docker Desktop with current user allowed to access Docker.
2. Node.js 20+ and npm for frontend checks.
3. `make`/POSIX shell, or run the direct Docker/npm commands listed above.
4. Terraform only for Terraform static validation.

Not required for the canonical backend path:

- global pytest
- global ruff
- global backend Python package installation
- host Playwright browser execution

## 14. LOC Delta

Production application LOC: `0`  
Test LOC: `0` for this reliability pass  
Tooling/script LOC: Makefile changed from the pre-existing untracked draft to a smaller canonical wrapper. It is optional in shells without `make`; direct Docker/npm commands remain canonical equivalents.  
Config LOC: `0` during this pass  
Docs LOC: this report updated

## 15. GO/NO-GO for Resuming Phase B Validation

GO for backend/container validation when Docker access is available.

NO-GO for claiming host Playwright stability on this Windows/OneDrive execution context. Use containerized Playwright or CI.

Do not resume browser-dependent validation until either:

1. `make test-playwright` completes in an environment that can pull/use the Playwright image, or
2. GitHub Actions `ci-frontend.yml` completes Playwright successfully.
