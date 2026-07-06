# PDF Gap Closure Evidence

## Audit Architecture

AuthClaw uses PostgreSQL as the authoritative immutable audit ledger and ClickHouse as a read-optimized analytics mirror.

- Authoritative ledger: `apps/api/app/workers/audit_worker.py`, `apps/api/app/core/audit/integrity.py`, `apps/api/app/core/audit/repository.py`
- PostgreSQL model/migrations: `apps/api/app/models/audit.py`, `apps/api/alembic/versions/4ffee7ad38f6_stream4_audit_integrity.py`, `apps/api/alembic/versions/a3f9d2c81b47_refresh_tokens_reset_token_audit_trigger.py`
- ClickHouse mirror repository: `apps/api/app/core/audit/repository.py`
- ClickHouse local service/table setup: `docker-compose.yml`, `infrastructure/clickhouse/migrations/001_initial_audit_log.sql`

`AuditWorker.storage_status` records PostgreSQL write success/failure and ClickHouse mirror success/failure. ClickHouse mirror failures are logged as `clickhouse_audit_mirror_write_failed` and do not roll back the PostgreSQL ledger write.

## Kafka / Redpanda Evidence

- Producer: `apps/api/app/core/events/producer.py`
- Consumer base: `apps/api/app/workers/consumer_base.py`
- Audit/security workers started by API lifespan: `apps/api/app/main.py`
- Local Redpanda service: `docker-compose.yml`
- Focused proof test: `apps/api/tests/test_pdf_gap_audit_kafka_clickhouse.py`

Local integration command:

```bash
docker compose up -d db clickhouse redpanda
cd apps/api
AUTHCLAW_RUN_KAFKA_INTEGRATION=1 pytest tests/test_pdf_gap_audit_kafka_clickhouse.py -q
```

Without `AUTHCLAW_RUN_KAFKA_INTEGRATION=1`, the live Redpanda test is skipped so normal unit CI does not depend on Docker.

## Dependabot Evidence

`.github/dependabot.yml` covers:

- `pip` at `/apps/api`
- `npm` at `/apps/web`
- `github-actions` at `/`

All schedules are weekly with `dependencies` and `security` labels.

## Test Commands

```bash
cd apps/api
pytest tests/test_pdf_gap_audit_kafka_clickhouse.py -q
pytest tests/test_clickhouse_repository.py tests/test_audit_concurrency.py -q
```

## Remaining Risk

ClickHouse is intentionally a mirror, not the source of truth. Production readiness still requires staging evidence that Redpanda, PostgreSQL, and ClickHouse are all healthy and that ClickHouse mirror failures are monitored operationally.
