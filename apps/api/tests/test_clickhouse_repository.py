import pytest
import uuid
from datetime import datetime, timezone
from app.core.audit.repository import ClickHouseAuditRepository, AuditRecord
from app.core.audit.integrity import compute_canonical_record_hash
from app.core.events.audit_hash import GENESIS_HASH

class DummyChClient:
    def __init__(self):
        self.inserts = []
        self.fetches = []

    async def execute(self, query, *args):
        self.inserts.append((query, args))

    async def fetch(self, query, *args):
        return self.fetches

    async def fetchrow(self, query, *args):
        return self.fetches[0] if self.fetches else None

@pytest.mark.asyncio
async def test_clickhouse_repository_append():
    client = DummyChClient()
    repo = ClickHouseAuditRepository(client)
    
    record = AuditRecord(
        record_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        sequence_no=1,
        created_at=datetime.now(timezone.utc),
        actor_id=uuid.uuid4(),
        actor_type="user",
        action="read",
        metadata={"event_type": "gateway_request"},
        previous_hash=GENESIS_HASH,
        integrity_hash="",
    )
    record = record.model_copy(update={"integrity_hash": compute_canonical_record_hash(record)})
    
    await repo.append(record)
    
    assert len(client.inserts) == 1
    assert "INSERT INTO audit_logs" in client.inserts[0][0]

@pytest.mark.asyncio
async def test_clickhouse_repository_list():
    client = DummyChClient()
    repo = ClickHouseAuditRepository(client)
    
    tenant_id = uuid.uuid4()
    await repo.list(tenant_id)
    # The dummy client returns [], so records is []
