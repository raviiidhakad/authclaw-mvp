import pytest
import asyncio
import uuid
import secrets
import os
from typing import Dict, Any
from sqlalchemy import select
from pydantic import BaseModel

from app.models.event import WALEvent, WALEventStatus, ProcessedEvent
from app.models.user import User
from app.models.tenant import Tenant
from app.models.audit import AuditLog
from app.core.config import settings
from app.schemas.events import SecurityEvent, AuditEvent
from app.core.database import AsyncSessionLocal

@pytest.fixture(scope="module", autouse=True)
def setup_kafka_topics():
    import os
    # Use the Redpanda endpoint configured by the caller. CI runs tests on the
    # host via localhost; containerized repros use the compose service name.
    settings.KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:19092")
    # Use random topics to avoid poison pills from previous runs
    os.environ["KAFKA_AUDIT_TOPIC"] = f"test.audit.events.{uuid.uuid4().hex[:8]}"
    os.environ["KAFKA_SECURITY_TOPIC"] = f"test.security.events.{uuid.uuid4().hex[:8]}"

@pytest.fixture(scope="module")
async def redpanda():
    pass
    yield "127.0.0.1:19092"

@pytest.mark.asyncio
async def test_wal_fallback():
    """
    Test WAL insertion when Kafka is not available.
    """
    async with AsyncSessionLocal() as db:
        topic = f"test.wal.topic.{uuid.uuid4().hex[:8]}"
        # Force an invalid broker to simulate Kafka down
        original_broker = settings.KAFKA_BROKERS
        from app.core.events.producer import producer
        settings.KAFKA_BROKERS = "localhost:9999"
        wal_event = None

        try:
            # Restart producer with bad broker
            await producer.stop()
            await producer.start()

            # Try to publish an event
            event = SecurityEvent(
                event_type="test.wal",
                tenant_id=uuid.uuid4(),
                actor_id=uuid.uuid4(),
                payload={"test": "data"}
            )
            await producer.publish(topic, event)

            # Check that the new event is in WAL.
            result = await db.execute(
                select(WALEvent).where(WALEvent.topic == topic)
            )
            wal_event = result.scalars().first()
            
            assert wal_event is not None
            assert wal_event.status == WALEventStatus.PENDING.value
            assert "test.wal" in wal_event.payload_bytes
        finally:
            # Cleanup and restore the shared producer settings for later tests.
            if wal_event is not None:
                await db.delete(wal_event)
                await db.commit()
            settings.KAFKA_BROKERS = original_broker
            await producer.stop()

@pytest.mark.asyncio
async def test_audit_worker(redpanda):
    """
    Test that AuditWorker correctly consumes an event and writes to AuditLog.
    """
    async with AsyncSessionLocal() as db:
        # Create a real tenant first so FK constraints pass!
        tenant_id = uuid.uuid4()
        tenant = Tenant(
            id=tenant_id,
            name=f"test-tenant-{uuid.uuid4().hex[:8]}",
            slug=f"test-tenant-{uuid.uuid4().hex[:8]}"
        )
        db.add(tenant)
        await db.commit()

        # Start producer properly with the test container
        from app.core.events.producer import producer
        from app.workers.audit_worker import AuditWorker
        
        await producer.start()
        
        audit_worker = AuditWorker()
        await audit_worker.start()

        # Wait for consumer to join group
        await asyncio.sleep(3)

        event = AuditEvent(
            event_type="policy_created",
            tenant_id=tenant_id,
            actor_id=None,
            payload={"action": "execute", "resource": "test", "ip_address": "127.0.0.1"}
        )
        
        topic = os.environ.get("KAFKA_AUDIT_TOPIC", "authclaw.audit.events")
        await producer.publish(topic, event)

        # Wait for consumer to process
        await asyncio.sleep(3)

        # Check audit log
        from sqlalchemy import text
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))
        result = await db.execute(
            select(AuditLog).where(AuditLog.action == "execute")
        )
        audit_logs = result.scalars().all()
        
        assert len(audit_logs) > 0
        assert str(audit_logs[0].ip_address) == "127.0.0.1"

        # Cleanup
        await producer.stop()
        await audit_worker.stop()

@pytest.mark.asyncio
async def test_security_worker_brute_force(redpanda):
    """
    Test that SecurityWorker correctly locks an account after 5 failed login events.
    """
    async with AsyncSessionLocal() as db:
        # Create user & tenant
        tenant_id = uuid.uuid4()
        tenant = Tenant(id=tenant_id, name=f"test-tnt-{secrets.token_hex(4)}", slug=f"test-tnt-{secrets.token_hex(4)}")
        db.add(tenant)
        await db.commit() # commit tenant first

        from sqlalchemy import text
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))
        
        user_id = uuid.uuid4()
        user = User(
            id=user_id,
            tenant_id=tenant_id,
            email=f"brute{uuid.uuid4().hex[:4]}@example.com",
            password_hash="mock_hash",
            first_name="Brute",
            last_name="Force",
            is_active=True
        )
        db.add(user)
        await db.commit()

        from app.core.events.producer import producer
        from app.workers.security_worker import SecurityWorker
        
        await producer.start()
        
        security_worker = SecurityWorker()
        await security_worker.start()

        await asyncio.sleep(3)

        # Publish 5 failed login events
        topic = os.environ.get("KAFKA_SECURITY_TOPIC", "authclaw.security.events")
        for i in range(5):
            event = SecurityEvent(
                event_type="user.login.failed",
                tenant_id=tenant_id,
                actor_id=user_id,
                payload={"reason": "bad_password"}
            )
            await producer.publish(topic, event)

        # Wait for consumer to process
        await asyncio.sleep(5)

        # Check if user is locked
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))
        await db.refresh(user)
        assert user.is_active is False
        
        # Cleanup
        await producer.stop()
        await security_worker.stop()
        
        # Reset user
        user.is_active = True
        await db.commit()
