import pytest
import uuid
from datetime import datetime, timezone, timedelta
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
async def test_verify_postgres_records_without_sequence_are_ordered_by_created_at():
    tenant_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    record1 = AuditRecord(
        record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        sequence_no=0,
        created_at=created_at,
        action="execute",
        metadata={"event_type": "gateway_request"},
        previous_hash=GENESIS_HASH,
        integrity_hash="temp",
    )
    record1.integrity_hash = compute_audit_hash(
        previous_hash=record1.previous_hash,
        id_val=str(record1.record_id),
        tenant_id=str(record1.tenant_id),
        user_id="None",
        event_type="gateway_request",
        resource="system",
        resource_id="None",
        action=record1.action,
        metadata=record1.metadata,
        created_at=record1.created_at,
    )
    record2 = AuditRecord(
        record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        sequence_no=0,
        created_at=created_at + timedelta(seconds=1),
        action="execute",
        metadata={"event_type": "gateway_request"},
        previous_hash=record1.integrity_hash,
        integrity_hash="temp",
    )
    record2.integrity_hash = compute_audit_hash(
        previous_hash=record2.previous_hash,
        id_val=str(record2.record_id),
        tenant_id=str(record2.tenant_id),
        user_id="None",
        event_type="gateway_request",
        resource="system",
        resource_id="None",
        action=record2.action,
        metadata=record2.metadata,
        created_at=record2.created_at,
    )

    report = await HashVerificationService(MockRepository([record2, record1])).verify_tenant_chain(tenant_id)

    assert report.is_valid is True
    assert report.chain_breaks == []

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
