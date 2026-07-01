# Local Test Environment

AuthClaw local tests run from the host and should use Docker Compose published
ports. Containers should keep using Docker service names on the Compose network.

## Host-side pytest URLs

Use these values when running tests from `apps/api` on the host:

```powershell
$env:DATABASE_URL="postgresql+asyncpg://authclaw_app:authclaw_app_password@127.0.0.1:5434/authclaw"
$env:ALEMBIC_DATABASE_URL="postgresql+asyncpg://postgres:password@127.0.0.1:5434/authclaw"
$env:REDIS_URL="redis://127.0.0.1:6379/0"
$env:KAFKA_BROKERS="127.0.0.1:19092"
$env:VAULT_ADDR="http://127.0.0.1:8200"
$env:VAULT_TOKEN="<local-dev-vault-token>"
$env:CLICKHOUSE_URL="http://127.0.0.1:8123"
$env:CLICKHOUSE_USER="authclaw"
$env:CLICKHOUSE_PASSWORD="authclaw_clickhouse_local_password"
$env:CLICKHOUSE_DB="authclaw"
$env:ENCRYPTION_PROVIDER="local"
```

The same defaults are captured in `apps/api/.env.test.local.example`, and
`apps/api/tests/conftest.py` sets them before importing application settings
unless the caller has already provided explicit values.

## Compose-internal URLs

Do not replace container runtime URLs with host ports. Inside Docker Compose:

- PostgreSQL: `db:5432`
- Redis: `redis:6379`
- Redpanda/Kafka: `redpanda:9092`
- Vault: `vault:8200`
- ClickHouse HTTP: `clickhouse:8123`

Those values are used by `docker-compose.yml` for `api` and
`connector-worker`.

## Published local ports

- Web: `localhost:3000`
- API: `localhost:8000`
- PostgreSQL: `localhost:5434`
- Redis: `localhost:6379`
- Redpanda/Kafka: `localhost:19092`
- Vault: `localhost:8200`
- ClickHouse HTTP: `localhost:8123`
- Redpanda Console: `localhost:8080`

## Windows temp directory

Some local Windows runs cannot write to the default `%TEMP%` path. The pytest
configuration now points test temp files to `apps/api/tmp/pytest` during test
startup to avoid host permission drift.
