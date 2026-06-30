import abc
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class AuditRecord(BaseModel):
    record_id: uuid.UUID
    tenant_id: uuid.UUID
    sequence_no: int
    created_at: datetime
    
    actor_id: Optional[uuid.UUID] = None
    actor_type: Optional[str] = None
    
    action: str
    
    frameworks_affected: List[str] = Field(default_factory=list)
    
    resource: Optional[str] = None
    resource_id: Optional[str] = None
    
    execution_trace: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    previous_hash: str
    integrity_hash: str

class VerificationReport(BaseModel):
    is_valid: bool
    scanned_records: int
    missing_records: List[int] = Field(default_factory=list)  # list of sequence_nos missing
    tampered_records: List[uuid.UUID] = Field(default_factory=list) # records where hash doesn't match contents
    chain_breaks: List[uuid.UUID] = Field(default_factory=list) # records where previous_hash doesn't match preceding record's hash

class AuditRepository(abc.ABC):
    
    @abc.abstractmethod
    async def append(self, record: AuditRecord) -> None:
        """Appends a new audit record to the store."""
        pass

    @abc.abstractmethod
    async def bulk_append(self, records: List[AuditRecord]) -> None:
        """Appends multiple audit records to the store."""
        pass

    @abc.abstractmethod
    async def list(self, tenant_id: uuid.UUID, limit: int = 100, offset: int = 0) -> List[AuditRecord]:
        """Lists audit records for a tenant."""
        pass

    @abc.abstractmethod
    async def export(self, tenant_id: uuid.UUID, start_date: datetime, end_date: datetime) -> List[AuditRecord]:
        """Exports audit records for compliance reporting."""
        pass
        
    @abc.abstractmethod
    async def get_latest_hash(self, tenant_id: uuid.UUID) -> Optional[str]:
        """Returns the integrity_hash of the most recent record."""
        pass

    @abc.abstractmethod
    async def get_latest_sequence_no(self, tenant_id: uuid.UUID) -> int:
        """Returns the highest sequence number for a tenant."""
        pass

class PostgresAuditRepository(AuditRepository):
    def __init__(self, session):
        self.session = session
        
    async def append(self, record: AuditRecord) -> None:
        from app.models.audit import AuditLog, EventType
        from app.core.audit.integrity import validate_canonical_record
        
        # We need to map AuditRecord to Postgres AuditLog.
        from sqlalchemy.dialects.postgresql import insert
        validate_canonical_record(record)
        
        # Safely resolve event_type: normalize to underscore, fallback to 'unknown'
        raw_event_type = record.metadata.get("event_type", "unknown")
        # Normalize dots to underscores for DB compatibility
        normalized_event_type = raw_event_type.replace(".", "_") if raw_event_type else "unknown"
        # Validate against known enum values; fallback to 'unknown' if invalid
        valid_values = {e.value for e in EventType}
        safe_event_type = normalized_event_type if normalized_event_type in valid_values else "unknown"
        
        stmt = insert(AuditLog).values(
            id=str(record.record_id),
            tenant_id=record.tenant_id,
            user_id=record.actor_id,
            event_type=safe_event_type,
            action=record.action,
            resource=record.resource,
            resource_id=record.resource_id,
            metadata_=record.metadata,
            ip_address=record.ip_address,
            user_agent=record.user_agent,
            created_at=record.created_at.replace(tzinfo=None), # Naive for PG
            previous_hash=record.previous_hash,
            hash=record.integrity_hash
        )
        
        stmt = stmt.on_conflict_do_nothing(index_elements=['id'])
        
        await self.session.execute(stmt)


    async def bulk_append(self, records: List[AuditRecord]) -> None:
        for r in records:
            await self.append(r)
        await self.session.flush()

    async def list(self, tenant_id: uuid.UUID, limit: int = 100, offset: int = 0) -> List[AuditRecord]:
        from sqlalchemy import select, desc
        from app.models.audit import AuditLog
        
        result = await self.session.execute(
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(desc(AuditLog.created_at))
            .limit(limit)
            .offset(offset)
        )
        rows = result.scalars().all()
        return [self._map_pg_to_record(row) for row in rows]

    async def export(self, tenant_id: uuid.UUID, start_date: datetime, end_date: datetime) -> List[AuditRecord]:
        from sqlalchemy import select, desc
        from app.models.audit import AuditLog
        
        result = await self.session.execute(
            select(AuditLog)
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.created_at >= start_date.replace(tzinfo=None),
                AuditLog.created_at <= end_date.replace(tzinfo=None)
            )
            .order_by(desc(AuditLog.created_at))
        )
        rows = result.scalars().all()
        return [self._map_pg_to_record(row) for row in rows]

    async def get_latest_hash(self, tenant_id: uuid.UUID) -> Optional[str]:
        from sqlalchemy import text
        
        # To avoid race conditions with out-of-order created_at timestamps during concurrent inserts,
        # we find the tip of the cryptographic chain (the record whose hash is not used as a previous_hash).
        # We fallback to created_at DESC just in case there are branches (which shouldn't happen).
        query = text("""
            SELECT hash FROM audit_logs 
            WHERE tenant_id = :tenant_id
            AND hash NOT IN (
                SELECT previous_hash FROM audit_logs WHERE tenant_id = :tenant_id
            )
            ORDER BY created_at DESC
            LIMIT 1
        """)
        result = await self.session.execute(query, {"tenant_id": tenant_id})
        row = result.fetchone()
        return row[0] if row else None

    async def get_latest_sequence_no(self, tenant_id: uuid.UUID) -> int:
        # Postgres didn't track sequence_no natively in Phase 1. Return 0 for migration sync.
        from sqlalchemy import select, func
        from app.models.audit import AuditLog
        result = await self.session.execute(
            select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == tenant_id)
        )
        count = result.scalar()
        return count if count else 0

    def _map_pg_to_record(self, row) -> AuditRecord:
        import uuid
        return AuditRecord(
            record_id=uuid.UUID(str(row.id)),
            tenant_id=row.tenant_id,
            sequence_no=0, # Default for PG
            created_at=row.created_at,
            actor_id=row.user_id,
            actor_type="user" if row.user_id else "system",
            action=row.action.value,
            resource=row.resource,
            resource_id=row.resource_id,
            metadata=row.metadata_,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            previous_hash=row.previous_hash or "",
            integrity_hash=row.hash or ""
        )

class ClickHouseAuditRepository(AuditRepository):
    def __init__(self, ch_client):
        self.ch = ch_client
        
    async def append(self, record: AuditRecord) -> None:
        await self.bulk_append([record])

    async def bulk_append(self, records: List[AuditRecord]) -> None:
        import json
        from app.core.audit.integrity import validate_canonical_record
        query = '''
            INSERT INTO audit_logs (
                tenant_id, record_id, sequence_no, created_at, actor_id, actor_type, 
                action, frameworks_affected, resource, resource_id, execution_trace, 
                metadata, ip_address, user_agent, previous_hash, integrity_hash
            ) VALUES
        '''
        
        tuples = []
        for record in records:
            validate_canonical_record(record)
            actor_id_val = str(record.actor_id) if record.actor_id else None
            tuples.append((
                str(record.tenant_id),
                str(record.record_id),
                record.sequence_no,
                record.created_at,
                actor_id_val,
                record.actor_type or "",
                record.action,
                record.frameworks_affected,
                record.resource or "",
                record.resource_id or "",
                record.execution_trace or "",
                json.dumps(record.metadata),
                record.ip_address or "0.0.0.0",
                record.user_agent or "",
                record.previous_hash,
                record.integrity_hash
            ))
        
        await self.ch.execute(query, *tuples)

    async def list(self, tenant_id: uuid.UUID, limit: int = 100, offset: int = 0) -> List[AuditRecord]:
        query = f'''
            SELECT * FROM audit_logs 
            WHERE tenant_id = '{str(tenant_id)}' 
            ORDER BY sequence_no DESC, created_at DESC 
            LIMIT {limit} OFFSET {offset}
        '''
        rows = await self.ch.fetch(query)
        return [self._map_ch_to_record(row) for row in rows]

    async def export(self, tenant_id: uuid.UUID, start_date: datetime, end_date: datetime) -> List[AuditRecord]:
        query = f'''
            SELECT * FROM audit_logs 
            WHERE tenant_id = '{str(tenant_id)}' 
            AND created_at >= '{start_date.isoformat()}' 
            AND created_at <= '{end_date.isoformat()}'
            ORDER BY sequence_no DESC, created_at DESC
        '''
        rows = await self.ch.fetch(query)
        return [self._map_ch_to_record(row) for row in rows]

    async def get_latest_hash(self, tenant_id: uuid.UUID) -> Optional[str]:
        query = f'''
            SELECT integrity_hash FROM audit_logs 
            WHERE tenant_id = '{str(tenant_id)}' 
            ORDER BY sequence_no DESC, created_at DESC 
            LIMIT 1
        '''
        row = await self.ch.fetchrow(query)
        return row['integrity_hash'] if row else None

    async def get_latest_sequence_no(self, tenant_id: uuid.UUID) -> int:
        query = f'''
            SELECT max(sequence_no) as max_seq FROM audit_logs 
            WHERE tenant_id = '{str(tenant_id)}'
        '''
        row = await self.ch.fetchrow(query)
        return row['max_seq'] if row and row['max_seq'] is not None else 0

    def _map_ch_to_record(self, row) -> AuditRecord:
        import json
        import uuid
        return AuditRecord(
            record_id=uuid.UUID(row['record_id']),
            tenant_id=uuid.UUID(row['tenant_id']),
            sequence_no=row['sequence_no'],
            created_at=row['created_at'],
            actor_id=uuid.UUID(row['actor_id']) if row.get('actor_id') else None,
            actor_type=row['actor_type'],
            action=row['action'],
            frameworks_affected=row.get('frameworks_affected', []),
            resource=row['resource'],
            resource_id=row['resource_id'],
            execution_trace=row['execution_trace'],
            metadata=json.loads(row['metadata']) if row.get('metadata') else {},
            ip_address=row['ip_address'],
            user_agent=row['user_agent'],
            previous_hash=row['previous_hash'],
            integrity_hash=row['integrity_hash']
        )
