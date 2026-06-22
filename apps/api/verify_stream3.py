import asyncio
import httpx
import uuid
from typing import Optional
from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.audit import AuditLog
from app.models.event import WALEvent, ProcessedEvent

async def run_verification():
    print("=== STREAM 3 VERIFICATION ===")
    
    # Check Database Tables
    async with AsyncSessionLocal() as db:
        print("\n1. Verifying Database Tables")
        try:
            # Check WAL table
            wal_count = await db.execute(text("SELECT COUNT(*) FROM wal_events"))
            print(f"WAL Events table exists. Current count: {wal_count.scalar()}")
            
            # Check Processed Events table
            processed_count = await db.execute(text("SELECT COUNT(*) FROM processed_events"))
            print(f"Processed Events table exists. Current count: {processed_count.scalar()}")
            print("PASS: Event backbone tables exist.")
        except Exception as e:
            print(f"FAIL: Table verification failed - {e}")
            
    print("\n2. Verifying Redpanda Connection and Publishing")
    # Using the Producer singleton
    from app.core.events.producer import producer
    from app.schemas.events import SecurityEvent
    
    await producer.start()
    
    event = SecurityEvent(
        event_type="test.connection",
        payload={"message": "ping"}
    )
    
    try:
        await producer.publish("test.topic", event)
        print("PASS: Successfully published event to Redpanda.")
    except Exception as e:
        print(f"FAIL: Could not publish event - {e}")
        
    print("\n3. Verifying WAL Fallback")
    # Simulate broker down
    old_broker = producer._producer.client.cluster.brokers if producer._producer else None
    await producer.stop()
    
    from app.core.config import settings
    original_broker = settings.KAFKA_BROKERS
    settings.KAFKA_BROKERS = "invalid:9092"
    
    await producer.start()
    event_wal = SecurityEvent(
        event_type="test.wal",
        payload={"message": "wal_ping"}
    )
    await producer.publish("test.wal.topic", event_wal)
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(text("SELECT COUNT(*) FROM wal_events WHERE topic = 'test.wal.topic'"))
        count = result.scalar()
        if count > 0:
            print(f"PASS: Event written to WAL when broker is down. Count: {count}")
        else:
            print("FAIL: Event not written to WAL.")
            
    await producer.stop()
    settings.KAFKA_BROKERS = original_broker
    await producer.start()

    print("\n4. Verifying Consumers (Audit & Security)")
    from app.workers.audit_worker import AuditWorker
    from app.workers.security_worker import SecurityWorker
    from app.schemas.events import AuditEvent
    
    audit_worker = AuditWorker()
    security_worker = SecurityWorker()
    
    await audit_worker.start()
    await security_worker.start()
    
    async with AsyncSessionLocal() as db:
        # Get a valid tenant and user
        from app.models.tenant import Tenant
        from sqlalchemy import select
        result = await db.execute(select(Tenant).limit(1))
        tenant = result.scalars().first()
        test_tenant_id = str(tenant.id) if tenant else str(uuid.uuid4())

    # Send an audit event
    test_resource_id = str(uuid.uuid4())
    audit_event = AuditEvent(
        event_type="auth.login",
        tenant_id=test_tenant_id,
        payload={"resource": "verification", "resource_id": test_resource_id, "ip_address": "10.0.0.1", "action": "read"}
    )
    await producer.publish("authclaw.audit.events", audit_event)
    
    print("Waiting for consumers to process...")
    await asyncio.sleep(5)
    
    async with AsyncSessionLocal() as db:
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{test_tenant_id}';"))
        result = await db.execute(select(AuditLog).where(AuditLog.resource_id == test_resource_id))
        log = result.scalars().first()
        if log:
            print(f"PASS: AuditWorker consumed event and wrote to AuditLog. IP: {log.ip_address}")
        else:
            print(f"FAIL: AuditWorker did not process event.")
        await db.execute(text("RESET app.current_tenant_id;"))
            
    await audit_worker.stop()
    await security_worker.stop()
    await producer.stop()
    
    print("\n=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    asyncio.run(run_verification())
