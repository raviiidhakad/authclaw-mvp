# AuthClaw Safe Refactoring Report

Date: 2026-06-29

Scope: approved safe refactoring only. No architecture redesign, feature work, API contract change, schema change, authentication change, tenant isolation change, compliance logic change, or security behavior change was performed.

## Summary

This pass removed only unused imports with direct implementation evidence. No functions, classes, routes, DTOs, models, serializers, dependencies, database schemas, or business logic were removed.

| Metric | Value |
| --- | ---: |
| Total tracked LOC before | 136,868 |
| Total tracked LOC after import cleanup | 136,856 |
| Total tracked LOC removed | 12 |
| Files modified | 16 |
| Import symbols removed | 26 |
| Functions removed | 0 |
| Classes removed | 0 |
| Dependencies removed | 0 |
| API routes removed | 0 |
| Database schemas changed | 0 |

Note: the LOC totals above count tracked repository text files using the same `git ls-files` based method used before this refactor, excluding generated/runtime folders such as `node_modules`, `.next`, `.venv`, `__pycache__`, `dist`, `build`, `coverage`, and test reports. The new report document itself is not included in the before/after reduction number.

## Changes Applied

All removals below are import-only. Repository search result means `rg` found the symbol only at the import site in that file, or the imported symbol was imported in a local scope and never referenced after import.

| File | Function/Class | Removed | Reason | Evidence | Search result | Safe to remove |
| --- | --- | --- | --- | --- | --- | --- |
| `apps/api/app/api/dependencies.py` | module scope | `AsyncGenerator` | Unused typing import. | AST scan flagged it; file uses no `AsyncGenerator`. | `rg "\bAsyncGenerator\b"` returned only the import line. | YES |
| `apps/api/app/api/dependencies.py` | module scope | `AsyncSessionLocal` | Duplicate/unused database session import. | `get_db` is the dependency used by endpoints; `AsyncSessionLocal` is not referenced. | `rg "\bAsyncSessionLocal\b"` returned only import lines. | YES |
| `apps/api/app/api/v1/endpoints/agent.py` | module scope | `Any` | Unused typing import. | Request model uses `List` and `Dict`, not `Any`. | `rg "\bAny\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/agent.py` | module scope | `get_current_user` | Unused dependency import. | Routes use `get_current_tenant`, `get_db`, and `require_roles`. | `rg "\bget_current_user\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/approvals.py` | module scope | `timedelta` | Unused datetime import. | Approval TTL is stored as integer minutes; no `timedelta` usage in file. | `rg "\btimedelta\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/approvals.py` | module scope | `HTTPException`, `status` | Unused FastAPI imports. | Endpoint raises project exceptions, not FastAPI `HTTPException`; no `status` constant usage. | `rg "\bHTTPException\b|\bstatus\b"` showed only import line plus model/status attribute text unrelated to FastAPI import. | YES |
| `apps/api/app/api/v1/endpoints/audit.py` | module scope | `List`, `Dict`, `Any` | Unused typing imports. | File does not use these typing names. | `rg "\bList\b|\bDict\b|\bAny\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/audit.py` | module scope | `User` | Unused model import. | Audit endpoints use tenant/role dependencies and audit models, not `User`. | `rg "\bUser\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/audit.py` | `get_audit_stats` | `RequestStatus` | Unused local import. | The function groups by `GatewayRequest.status` and never references `RequestStatus`. | Local `rg "\bRequestStatus\b"` showed only the local import line. | YES |
| `apps/api/app/api/v1/endpoints/auth.py` | module scope | `timezone` | Unused datetime import. | File uses `datetime` and `timedelta`, not `timezone`. | `rg "\btimezone\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/gateway.py` | module scope | `Dict`, `Any` | Unused typing imports. | File has no annotations using those names. | `rg "\bDict\b|\bAny\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/gateway.py` | module scope | `GatewayResponse` | Unused model import. | Gateway endpoints use `GatewayRequest` and `RequestStatus`; no direct `GatewayResponse`. | `rg "\bGatewayResponse\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/gateway_routes.py` | module scope | `HTTPException` | Unused FastAPI import. | File uses project exceptions `NotFoundException` and `BadRequestException`. | `rg "\bHTTPException\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/gateway_routes.py` | module scope | `get_current_user` | Unused dependency import. | Routes use `require_roles` for user resolution/gating. | `rg "\bget_current_user\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/policies.py` | module scope | `get_current_user` | Unused dependency import. | Policy endpoints use `require_roles` and tenant/db dependencies. | `rg "\bget_current_user\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/providers.py` | module scope | `get_current_user` | Unused dependency import. | Provider endpoints use `require_roles`, not direct `get_current_user`. | `rg "\bget_current_user\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/providers.py` | module scope | `BadRequestException` | Unused exception import. | Provider endpoints use `NotFoundException`; no `BadRequestException` reference. | `rg "\bBadRequestException\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/tenants.py` | module scope | `uuid` | Unused standard library import. | No UUID construction or annotation in the file. | `rg "\buuid\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/tenants.py` | module scope | `NotFoundException` | Unused exception import. | Tenant endpoints do not raise it. | `rg "\bNotFoundException\b"` returned only the import line. | YES |
| `apps/api/app/api/v1/endpoints/trust_common.py` | module scope | `Any` | Unused typing import. | File has `from __future__ import annotations`; no `Any` references. | `rg "\bAny\b"` returned only the import line. | YES |
| `apps/api/app/core/clickhouse.py` | module scope | `asyncio` | Unused standard library import. | ClickHouse manager uses `aiohttp`/`aiochclient`, not `asyncio`. | `rg "\basyncio\b"` returned only the import line. | YES |
| `apps/api/app/core/encryption/local.py` | module scope | `base64` | Unused standard library import. | Local encryption uses Fernet and `os.urandom`, not `base64`. | `rg "\bbase64\b"` returned only the import line. | YES |
| `apps/api/app/core/exceptions.py` | module scope | `Any`, `Dict` | Unused typing imports. | Exception handlers use `Optional`; payloads are plain dict literals. | `rg "\bAny\b|\bDict\b"` returned only the import line. | YES |
| `apps/api/app/core/providers/circuit_breaker.py` | module scope | `json` | Unused standard library import. | Circuit breaker stores simple Redis values, not JSON payloads. | `rg "\bjson\b"` returned only the import line. | YES |
| `apps/api/app/workers/security_worker.py` | module scope | `select` | Unused SQLAlchemy import. | Worker only uses `update`. | `rg "\bselect\b"` returned only the import line. | YES |
| `apps/api/app/workers/security_worker.py` | module scope | `datetime`, `timezone` | Unused datetime imports. | Worker does not generate timestamps directly. | `rg "\bdatetime\b|\btimezone\b"` returned only the import line. | YES |

## Duplicate Code Removed

None.

No duplicate helper methods, DTOs, serializers, validators, prompt templates, route handlers, or config blocks were merged in this pass. Potential duplication remains intentionally untouched because identical behavior was not proven within the time-boxed safe pass.

## Dead Code Removed

Only import-level dead code was removed.

No functions, classes, modules, routes, models, services, workers, schemas, tests, or production helpers were deleted.

## Imports Removed

Removed 26 unused import symbols across 16 files:

- `Any`
- `AsyncGenerator`
- `AsyncSessionLocal`
- `BadRequestException`
- `Dict`
- `GatewayResponse`
- `HTTPException`
- `List`
- `NotFoundException`
- `RequestStatus`
- `User`
- `asyncio`
- `base64`
- `datetime`
- `get_current_user`
- `json`
- `select`
- `status`
- `timedelta`
- `timezone`
- `uuid`

Some names appear more than once across files.

## Dependencies Identified For Manual Review

No dependencies were removed automatically.

The dependency scan was conservative and report-only. Packages below were not directly referenced by Python imports in `apps/api/app` or `apps/api/tests`, but several are likely runtime tools, entrypoints, extras, transitive security constraints, or backend plugin dependencies. They must not be uninstalled without a dedicated dependency audit.

### Python Packages Needing Manual Review

| Package | Scan result | Notes |
| --- | --- | --- |
| `uvicorn` | Not directly imported | Runtime server entrypoint; likely needed by Docker/dev commands. Do not remove without checking container commands. |
| `python-multipart` | Not directly imported | FastAPI form/file parsing support; may be needed at runtime. |
| `alembic` | Not directly imported | Migration CLI/runtime dependency; required by Docker command. |
| `email-validator` | Not directly imported | Pydantic email validation extra; may be indirectly required. |
| `bcrypt` | Not directly imported | Used by passlib backend; indirect runtime dependency. |
| `itsdangerous` | Not directly imported | Auth/session ecosystem dependency; review before removal. |
| `pytest-cov` | Not directly imported | Pytest plugin, invoked by test tooling rather than imports. |
| `azure-core` | Not directly imported | Listed as transitive security constraint; review lock/adapter needs. |
| `filelock` | Not directly imported | Transitive/security constraint. |
| `idna` | Not directly imported | HTTP/TLS transitive dependency. |
| `jaraco.context` | Not directly imported | Transitive/security constraint. |
| `Mako` | Not directly imported | Alembic template dependency. |
| `setuptools` | Not directly imported | Build/runtime packaging constraint. |
| `urllib3` | Not directly imported | HTTP stack transitive dependency. |
| `wheel` | Not directly imported | Build/runtime packaging constraint. |
| `langchain` | Not directly imported | May be unnecessary if only `langgraph` and provider-specific integrations are used; requires separate audit. |
| `langchain-groq` | Not directly imported | Review if Groq validation uses direct SDK/OpenAI-compatible path only. |
| `testcontainers` | Not directly imported | May be planned integration-test dependency. |
| `numpy` | Not directly imported | Likely transitive for ML/NLP packages. |
| `groq` | Not directly imported | Current Groq path may use OpenAI-compatible adapter; review before removal. |
| `faker` | Not directly imported | May be used indirectly by Presidio synthetic engine or tests. |

### Node Packages

All declared Node dependencies and devDependencies were found by a conservative source/config text scan. No Node package was identified as safe to remove in this pass.

### Terraform, Docker, GitHub Actions

No Terraform modules, Docker services, or GitHub Actions were removed. CI/deployment workflows are runtime/operational configuration and require a separate audit before removal.

## Utilities Consolidated

None.

No utility functions were consolidated because identical implementation and identical behavior were not proven. This avoids accidental changes in validation, serialization, tenant context, or security behavior.

## Tests And Verification

| Command | Result |
| --- | --- |
| `python -m compileall -q apps/api/app` using bundled Python | Passed |
| `npm.cmd run lint` in `apps/web` | Passed |
| `npx.cmd tsc --noEmit` in `apps/web` | Passed |
| `npm.cmd run build` in `apps/web` | Passed |
| `pytest tests/test_gateway_mvp_phase1.py ... tests/test_gateway_mvp_phase6.py -q` | Passed: 47 passed, 1 skipped |
| `pytest --collect-only -q` for gateway phase tests plus API-key singleton test | Passed: 49 tests collected |
| Initial `pytest` including `tests/test_api_keys_singleton.py` | Environment blocked: 47 passed, 1 skipped, 1 failed because Postgres refused connection before test logic |
| `git diff --check` | Passed |

### Verification Caveat

The DB-backed test `tests/test_api_keys_singleton.py::test_creating_new_gateway_key_revokes_previous_active_key` failed because the local Postgres service refused the connection (`ConnectionRefusedError [WinError 1225]`). This failure occurred during test setup/DB connection, before exercising the changed import-only code. No product code was changed to bypass or skip the test.

## Regression Risk

Risk level: Low.

Reason:

- Changes are import-only.
- No runtime symbols, functions, classes, route decorators, dependencies, schemas, models, or business logic were changed.
- Python syntax compilation passed.
- Gateway regression subset passed.
- Frontend lint/typecheck/build passed.

Remaining risk:

- Full backend suite was not run because local DB-backed testing is unavailable in this environment.
- Ruff is configured but not installed in `apps/api/.venv`, so Ruff could not be used as the linter/fixer for backend code.

## Remaining Refactoring Opportunities

These are not approved removals yet. They need separate evidence and tests before implementation:

1. Run Ruff in CI or install it in the local API dev environment, then clean remaining `F401` import findings with tool-backed evidence.
2. Audit Python dependencies marked `not-directly-referenced`, separating runtime entrypoints, transitive constraints, test plugins, and truly removable packages.
3. Review `apps/api/app/models/__init__.py` re-exports carefully; do not remove without proving no Alembic/ORM/import side effects.
4. Review repeated sanitizer helpers across gateway/reporting/risk surfaces for identical behavior before consolidation.
5. Review repeated tenant-context helpers and RBAC wrappers only if tests prove identical semantics.
6. Review duplicate gateway route aliases only after confirming API backward compatibility requirements.
7. Add a backend lint job that fails on unused imports so future cleanup stays mechanical and safe.

## Final Verdict

Safe refactoring completed.

The codebase is smaller by 12 tracked LOC, with only unused imports removed. Functionality, API contracts, schemas, authentication, tenant isolation, compliance logic, security behavior, and architecture were preserved.
