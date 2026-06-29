import asyncio
import uuid
import json
from datetime import datetime
from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.models.tenant import Tenant
from app.models.audit import AuditLog
from app.core.events.producer import producer
from app.workers.audit_worker import AuditWorker
from app.api.v1.endpoints.audit import verify_audit_integrity, export_audit_logs
from app.schemas.events import AuditEvent

async def run_verification():
    print("=== STREAM 4 VERIFICATION ===")
    
    # Initialize
    audit_worker = AuditWorker()
    await producer.start()
    await audit_worker.start()
    
    async with AsyncSessionLocal() as db:
        # 1. Get a valid tenant
        result = await db.execute(select(Tenant).limit(1))
        tenant = result.scalars().first()
        if not tenant:
            print("FAIL: No tenants found.")
            return
            
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--tamper-check":
        print("\n=== Checking Tamper Detection ===")
        async with AsyncSessionLocal() as db:
            await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant.id}';"))
            verify_result = await verify_audit_integrity(tenant=tenant, _=None, db=db)
            if verify_result["status"] == "tampered":
                print(f"PASS: Tampering detected at node {verify_result['tampered_from_id']}")
            else:
                print("FAIL: Tampering was NOT detected!")
            
            print("\n6. Verifying Signed Audit Export")
            from app.core.config import settings
            import app.core.encryption as enc
            settings.ENCRYPTION_PROVIDER = "vault"
            enc._provider = None
            export_response = await export_audit_logs(tenant=tenant, _=None, db=db)
            headers = export_response.headers
            if "X-Audit-Signature" in headers and "X-Audit-Key" in headers:
                print("PASS: Export contains Cryptographic Signatures (X-Audit-Signature, X-Audit-Key)")
            else:
                print("FAIL: Export missing signatures.")
            await db.execute(text("RESET app.current_tenant_id;"))
        await audit_worker.stop()
        await producer.stop()
        return

    # 2. Produce 3 sequential events
    print("\n2. Producing Audit Events")
    for i in range(3):
        event = AuditEvent(
            event_type="auth.login",
            tenant_id=str(tenant.id),
            payload={"action": "read", "resource": "login", "resource_id": f"test_{i}", "ip_address": f"10.0.0.{i}"}
        )
        await producer.publish("authclaw.audit.events", event)
        await asyncio.sleep(0.5) # ensure different timestamps
        
    print("Waiting for consumers to process...")
    await asyncio.sleep(5)
    
    async with AsyncSessionLocal() as db:
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant.id}';"))
        
        # 3. Verify Chain intactness
        print("\n3. Verifying Cryptographic Hash Chain")
        verify_result = await verify_audit_integrity(tenant=tenant, _=None, db=db)
        if verify_result["status"] == "intact":
            print("PASS: Hash chain is intact and valid.")
        else:
            print(f"FAIL: Hash chain is broken! {verify_result}")
            
        await db.execute(text("RESET app.current_tenant_id;"))
        
    await audit_worker.stop()
    await producer.stop()
    print("\n=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    asyncio.run(run_verification())
