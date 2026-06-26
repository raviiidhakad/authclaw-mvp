# AuthClaw Sprint 2 Closeout

Date: 2026-06-20

## Final Verdict

READY.

Sprint 2 is accepted and scope is frozen. Core cloud connector functionality, vault-backed credential storage, connector worker processing, findings inventory, agent context integration, frontend integrations/findings console, Docker Compose topology, and CI/release gates have been verified.

## Scope Completed

- AWS, GitHub, and GCP connector implementations with credential validation, primary provider findings fetch, fallback scanners, severity normalization, deduplication, retry, timeout, and circuit breaker coverage.
- Vault-backed cloud integration credential storage using `vault_reference_id`; raw credentials are not stored in `cloud_integrations`.
- Connector worker with Redis locking, Kafka event consumption, inventory persistence, stale finding resolution, sanitized failure events, and health reporting.
- Findings inventory APIs and safe agent context assembly from persisted findings.
- Frontend integrations console and findings console with validation, sync, health, filtering, detail, and status update flows.
- Fake-connector end-to-end readiness coverage and Sprint 2 regression tests.

## Major Modules Delivered

- `apps/api/app/services/connectors/`
- `apps/api/app/services/vault_credentials.py`
- `apps/api/app/workers/connector_worker.py`
- `apps/api/app/models/integration.py`
- `apps/api/app/models/finding.py`
- `apps/api/app/api/v1/endpoints/integrations.py`
- `apps/api/app/api/v1/endpoints/findings.py`
- `apps/api/app/services/findings_context.py`
- `apps/web/src/app/(dashboard)/integrations/`
- `apps/web/src/app/(dashboard)/findings/`
- `apps/web/src/hooks/use-data.ts`
- `docker-compose.yml`

## Architecture Summary

Sprint 2 stores cloud integration metadata in Postgres and stores credentials in Vault KV behind a tenant-scoped `vault_reference_id`. Connector scans are scheduled through Kafka/Redpanda and processed by `connector-worker`, which retrieves credentials from Vault, validates provider access, fetches or derives findings, writes normalized findings to Postgres, and stores raw provider payloads only in the raw payload store. API and event surfaces sanitize credential values, raw payload labels, and provider error messages before returning or emitting them.

## APIs Delivered

- `GET /api/v1/integrations`
- `POST /api/v1/integrations`
- `POST /api/v1/integrations/validate`
- `PATCH /api/v1/integrations/{integration_id}`
- `DELETE /api/v1/integrations/{integration_id}`
- `POST /api/v1/integrations/{integration_id}/sync`
- `GET /api/v1/integrations/health`
- `GET /api/v1/integrations/{integration_id}/health`
- `GET /api/v1/findings`
- `GET /api/v1/findings/{finding_id}`
- `PATCH /api/v1/findings/{finding_id}`

## Frontend Pages Delivered

- `/integrations`
- `/findings`

## Worker And Container Coverage

- `connector-worker` starts from Docker Compose.
- Kafka producer starts successfully.
- AWS, GitHub, and GCP connectors register.
- Consumer joins `authclaw.connector.scan`.
- Worker can query active integrations and WAL events against local services.

## Verification Matrix

| Area | Command / Check | Result |
| --- | --- | --- |
| Infra startup | `docker compose up -d db redis redpanda vault clickhouse` | Pass |
| Postgres | `pg_isready -U postgres` | Pass |
| Redis | `redis-cli ping` | Pass |
| Redpanda | `rpk cluster health` | Pass |
| Vault | `vault status`, `/v1/sys/health` | Pass |
| ClickHouse | `clickhouse-client --query "SELECT 1"` | Pass |
| Compose topology | `docker compose config --quiet` | Pass |
| API health | `GET /health` | Pass |
| Security health | `GET /api/v1/health/security-pipeline` | Pass |
| Backend collection | `pytest --collect-only -q` | Pass, 363 collected |
| Backend full suite | `pytest -q` | Pass, 348 passed, 15 skipped |
| Sprint 2 regression | `pytest tests/test_sprint2_*.py -q` | Pass, 209 passed |
| Frontend lint | `npm run lint` | Pass |
| Frontend typecheck | `npx tsc --noEmit` | Pass |
| Frontend build | `npm run build` | Pass |
| Frontend E2E | `CI=1 npx playwright test` | Pass, 10 passed |
| Secret scan | `rg` for `gsk_` and credential-like patterns | Pass; remaining hits are fake fixtures or detector regexes |

## Closeout Fixes Applied

- Removed hardcoded Groq-looking key literals from backend helper/probe scripts.
- Replaced `apps/api/.env` Groq placeholder with a non-token-shaped test value.
- Fixed event backbone WAL test isolation so failed runs do not poison later Kafka tests.
- Updated stale cross-tenant isolation test to match the documented architecture: `api_keys` use DB RLS; `users` are auth-first and tenant-filtered at the application layer.
- Set transaction-local tenant context in `AuditWorker` before writing RLS-protected audit rows.
- Made ClickHouse cleanup non-fatal/idempotent for best-effort audit writes.
- Updated audit concurrency verification to read under tenant RLS context.

## Known Warnings

- Pydantic class-based `config` deprecation warnings remain.
- LangGraph `allowed_objects` pending deprecation warning remains.
- Redis test cleanup uses deprecated `close()` instead of `aclose()`.
- SQLAlchemy/botocore `datetime.utcnow()` deprecation warnings remain.
- Playwright prints `NO_COLOR` ignored because `FORCE_COLOR` is set.
- Docker reports Vault container health as unhealthy, but direct Vault status and HTTP health show initialized and unsealed.
- ClickHouse HTTP auth from the app path can warn in best-effort audit writes depending on the local image/password state; internal ClickHouse health is green.

## Deferred Follow-ups

- Normalize dependency deprecation warnings before the next release hardening pass.
- Add an explicit Docker health mapping for `connector-worker`.
- Align ClickHouse local HTTP credentials in compose with app settings.
- Decide whether to keep or remove helper scripts such as `add_provider.py` and `test_groq.py`.

## Recommended Next Track

Proceed to post-Sprint-2 release hardening / production readiness, not a new product sprint yet. Recommended focus: deployment env parity, secrets management, worker health endpoints, ClickHouse credential alignment, CI service orchestration, and release runbook.
