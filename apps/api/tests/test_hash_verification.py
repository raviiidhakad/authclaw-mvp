import pytest
import uuid
from datetime import datetime, timezone
from app.core.audit.repository import AuditRecord
from app.core.audit.verification import HashVerificationService
from app.core.events.audit_hash import compute_audit_hash, GENESIS_HASH

class MockRepository:
    def __init__(self, records):
        self.records = records
    
    async def export(self, tenant_id, start_date, end_date):
        return self.records

    async def list(self, tenant_id, limit=1000, offset=0):
        return self.records[offset:offset+limit]

@pytest.mark.asyncio
async def test_verify_chain_intact():
    tenant_id = uuid.uuid4()
    
    record1 = AuditRecord(
        record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        sequence_no=1,
        created_at=datetime.now(timezone.utc),
        action="create",
        previous_hash=GENESIS_HASH,
        integrity_hash="temp"
    )
    record1.integrity_hash = compute_audit_hash(
        previous_hash=GENESIS_HASH,
        id_val=str(record1.record_id),
        tenant_id=str(record1.tenant_id),
        user_id="None",
        event_type="create",
        resource="system",
        resource_id="None",
        action="create",
        metadata={},
        created_at=record1.created_at
    )
    
    # Intact chain
    repo = MockRepository([record1])
    verifier = HashVerificationService(repo)
    report = await verifier.verify_tenant_chain(tenant_id)
    
    assert report.is_valid is True
    assert report.scanned_records == 1
    assert len(report.missing_records) == 0

@pytest.mark.asyncio
async def test_verify_chain_tampered():
    tenant_id = uuid.uuid4()
    
    record1 = AuditRecord(
        record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        sequence_no=1,
        created_at=datetime.now(timezone.utc),
        action="create",
        previous_hash=GENESIS_HASH,
        integrity_hash="invalid_hash"
    )
    
    repo = MockRepository([record1])
    verifier = HashVerificationService(repo)
    report = await verifier.verify_tenant_chain(tenant_id)
    
    assert report.is_valid is False
    assert len(report.tampered_records) == 1
    assert report.tampered_records[0] == record1.record_id
