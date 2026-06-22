import pytest
import asyncio
import uuid
import secrets
from datetime import datetime, timezone

from sqlalchemy import select, text

from app.core.database import AsyncSessionLocal
from app.workers.audit_worker import AuditWorker
from app.models.tenant import Tenant
from app.models.audit import AuditLog
from app.core.events.audit_hash import GENESIS_HASH

@pytest.mark.asyncio
async def test_audit_worker_concurrency_linear_chaining():
    """
    Spins up multiple concurrent audit worker process tasks.
    Proves that the SELECT FOR UPDATE lock serializes execution and 
    prevents branching in the hash chain.
    """
    tenant_id = uuid.uuid4()
    
    # Create the tenant first because the worker locks the tenant row!
    async with AsyncSessionLocal() as session:
        tenant = Tenant(
            id=tenant_id,
            name=f"test-tenant-{uuid.uuid4().hex[:8]}", 
            slug=f"test-tenant-{uuid.uuid4().hex[:8]}"
        )
        session.add(tenant)
        await session.commit()

    worker = AuditWorker()

    # We will simulate N concurrent audit events
    N_EVENTS = 15
    
    async def process_event(event_index):
        from datetime import timedelta
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "policy_created",
            "tenant_id": str(tenant_id),
            "actor_id": None,
            "timestamp": (datetime.now(timezone.utc) + timedelta(microseconds=event_index * 1000)).isoformat(),
            "payload": {
                "action": "create",
                "resource": "policy",
                "resource_id": str(uuid.uuid4()),
                "index": event_index
            }
        }
        
        # Each concurrent task must use its own distinct DB session!
        async with AsyncSessionLocal() as session:
            await worker.process(payload, session)
            await session.commit()  # Must commit to release the SELECT FOR UPDATE lock!

    # Execute all concurrently
    await asyncio.gather(*(process_event(i) for i in range(N_EVENTS)))

    # Verify the chain is strictly linear
    async with AsyncSessionLocal() as session:
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        )
        logs = result.scalars().all()
        
        assert len(logs) == N_EVENTS, f"Expected {N_EVENTS} logs, got {len(logs)}"
        
        # Check for branching: all previous_hash values MUST be unique!
        previous_hashes = set()
        for log in logs:
            assert log.previous_hash not in previous_hashes, f"BRANCH DETECTED! Duplicate previous_hash found: {log.previous_hash}"
            previous_hashes.add(log.previous_hash)
            
        # The chain must start at GENESIS_HASH
        assert GENESIS_HASH in previous_hashes, "Chain does not start at GENESIS_HASH"
