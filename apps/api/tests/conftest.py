import pytest
import os
import uuid
import tempfile
from pathlib import Path

RUNNING_IN_DOCKER = Path("/.dockerenv").exists()
DEFAULT_DB_HOST = "db" if RUNNING_IN_DOCKER else "127.0.0.1"
DEFAULT_DB_PORT = "5432" if RUNNING_IN_DOCKER else "5434"

LOCAL_TEST_ENV_DEFAULTS = {
    "DATABASE_URL": "postgresql+asyncpg://authclaw_app:authclaw_app_password@127.0.0.1:5434/authclaw",
    "ALEMBIC_DATABASE_URL": "postgresql+asyncpg://postgres:password@127.0.0.1:5434/authclaw",
    "DB_HOST": DEFAULT_DB_HOST,
    "DB_PORT": DEFAULT_DB_PORT,
    "REDIS_URL": "redis://127.0.0.1:6379/0",
    "KAFKA_BROKERS": "127.0.0.1:19092",
    "VAULT_ADDR": "http://127.0.0.1:8200",
    "VAULT_TOKEN": "local-vault-root-token",
    "CLICKHOUSE_URL": "http://127.0.0.1:8123",
    "CLICKHOUSE_USER": "authclaw",
    "CLICKHOUSE_PASSWORD": "authclaw_clickhouse_local_password",
    "CLICKHOUSE_DB": "authclaw",
    "ENCRYPTION_PROVIDER": "local",
    "POLICY_ENGINE_MODE": "python",
    "ENABLE_OPA_RUNTIME_INTEGRATION": "false",
    "OPA_URL": "http://127.0.0.1:8181/v1/data/authclaw/gateway/decision",
    "OPA_POLICY_URL": "http://127.0.0.1:8181/v1/data/authclaw/gateway/decision",
    "OPA_RUNTIME_MODE": "STRICT",
    "OPA_STRICT_MODE": "true",
    "OPA_FAIL_CLOSED": "true",
    "OPA_TIMEOUT_SECONDS": "2.0",
}

for key, value in LOCAL_TEST_ENV_DEFAULTS.items():
    os.environ.setdefault(key, value)

_test_tmp = Path(__file__).resolve().parents[1] / "tmp" / "pytest"
_test_tmp.mkdir(parents=True, exist_ok=True)
for key in ("TMP", "TEMP", "TMPDIR"):
    os.environ[key] = str(_test_tmp)
tempfile.tempdir = str(_test_tmp)

from app.core.clickhouse import clickhouse_manager
from app.core.redis import RedisClient

# Isolate topics for tests
os.environ['KAFKA_TOPIC'] = f'authclaw.audit.events.test.{uuid.uuid4()}'

@pytest.fixture(autouse=True)
async def reset_singletons():
    yield
    await clickhouse_manager.disconnect()
    clickhouse_manager.client = None
    clickhouse_manager.session = None
    try:
        await RedisClient.aclose(flush=True)
    except RuntimeError as exc:
        if "different loop" not in str(exc) and "Event loop is closed" not in str(exc):
            raise
