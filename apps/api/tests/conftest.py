import pytest
from app.core.clickhouse import clickhouse_manager
from app.core.redis import RedisClient
import os
import uuid

# Isolate topics for tests
os.environ['KAFKA_TOPIC'] = f'authclaw.audit.events.test.{uuid.uuid4()}'

@pytest.fixture(autouse=True)
async def reset_singletons():
    yield
    await clickhouse_manager.disconnect()
    clickhouse_manager.client = None
    clickhouse_manager.session = None
    redis_client = RedisClient._instance
    RedisClient._instance = None
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except RuntimeError as exc:
            if "different loop" not in str(exc):
                raise
