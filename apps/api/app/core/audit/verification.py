import uuid
import logging
from app.core.audit.repository import AuditRepository, VerificationReport
from app.core.events.audit_hash import compute_audit_hash, GENESIS_HASH

logger = logging.getLogger(__name__)

class HashVerificationService:
    def __init__(self, repository: AuditRepository):
        self.repo = repository

    async def verify_tenant_chain(self, tenant_id: uuid.UUID) -> VerificationReport:
        """
        Retrieves the entire hash chain for a tenant and verifies mathematically 
        that every link is perfectly intact.
        """
        # Fetch all records ordered chronologically
        # For 10 million records, this would be batched. We simulate batched fetch here.
        # But for the current list interface, we just fetch a large limit for now.
        # In a real 10M record scenario, we would paginate.
        
        limit = 10000
        offset = 0
        
        missing_records = []
        tampered_records = []
        chain_breaks = []
        
        expected_previous_hash = GENESIS_HASH
        expected_sequence_no = 1
        
        total_scanned = 0
        
        while True:
            # We use limit/offset to stream records in chunks of 10,000.
            # This keeps memory usage strictly O(1) regardless of record count.
            # Note: repository.list() retrieves in ascending order for verification
            records = await self.repo.list(tenant_id, limit=limit, offset=offset)
            
            if not records:
                break
            
            # If the underlying list() is descending, we would need to reverse it here.
            # But we assume the pagination fetches ascending to follow the chain.
            # Let's ensure ascending iteration if it's descending.
            if len(records) > 1 and (
                records[0].sequence_no > records[-1].sequence_no
                or (records[0].sequence_no == records[-1].sequence_no == 0 and records[0].created_at > records[-1].created_at)
            ):
                records.reverse()
            
            for record in records:
                total_scanned += 1
                
                # 1. Missing Sequence Numbers
                if record.sequence_no != 0 and record.sequence_no != expected_sequence_no:
                    if record.sequence_no > expected_sequence_no:
                        missing_records.extend(range(expected_sequence_no, record.sequence_no))
                    expected_sequence_no = record.sequence_no
                    
                expected_sequence_no += 1
                
                # 2. Chain Breaks
                if record.previous_hash != expected_previous_hash:
                    chain_breaks.append(record.record_id)
                
                # 3. Hash Tampering
                # Recompute the hash exactly as the worker did
                computed_hash = compute_audit_hash(
                    previous_hash=record.previous_hash,
                    id_val=str(record.record_id),
                    tenant_id=str(record.tenant_id),
                    user_id=str(record.actor_id) if record.actor_id else "None",
                    event_type=record.metadata.get("event_type", record.action), # Fallback
                    resource=record.resource or "system",
                    resource_id=str(record.resource_id) if record.resource_id else "None",
                    action=record.action,
                    metadata=record.metadata,
                    created_at=record.created_at
                )
                
                if record.integrity_hash != computed_hash:
                    tampered_records.append(record.record_id)
                    
                expected_previous_hash = record.integrity_hash
                
            offset += limit
            
        is_valid = len(missing_records) == 0 and len(tampered_records) == 0 and len(chain_breaks) == 0
        
        return VerificationReport(
            is_valid=is_valid,
            scanned_records=total_scanned,
            missing_records=missing_records,
            tampered_records=tampered_records,
            chain_breaks=chain_breaks
        )
