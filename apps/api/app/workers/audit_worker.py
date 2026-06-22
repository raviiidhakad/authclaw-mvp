import logging
import uuid
from dateutil.parser import parse
from datetime import timezone

from app.workers.consumer_base import KafkaConsumerBase
from app.core.events.audit_hash import compute_audit_hash, GENESIS_HASH
from app.models.tenant import Tenant
from app.core.audit.repository import PostgresAuditRepository, AuditRecord

from sqlalchemy import select, text

logger = logging.getLogger(__name__)


class AuditWorker(KafkaConsumerBase):
    def __init__(self):
        import os
        super().__init__(
            topics=[os.environ.get("KAFKA_AUDIT_TOPIC", "authclaw.audit.events")],
            group_id="audit-worker-group"
        )

    async def process(self, payload: dict, db):
        """
        Inserts the immutable audit event into the Compliance Ledger.
        Includes SHA-256 hash chaining to ensure audit integrity.
        Primary write is to PostgreSQL. ClickHouse write is best-effort.
        """
        tenant_id_str = payload.get("tenant_id")

        if not tenant_id_str:
            logger.warning("Audit event missing tenant_id. Skipping.")
            return

        try:
            tenant_id = uuid.UUID(tenant_id_str)
        except ValueError:
            logger.warning(f"Audit event has invalid tenant_id: {tenant_id_str}. Skipping.")
            return

        # Repositories
        pg_repo = PostgresAuditRepository(db)

        # 1. Set transaction-local tenant context for RLS-protected audit writes.
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )

        # 2. Acquire PostgreSQL Tenant Serialization Lock to prevent race conditions
        await db.execute(
            select(Tenant.id)
            .where(Tenant.id == tenant_id)
            .with_for_update()
        )

        # 3. Get latest hash from PostgreSQL (Source of Truth for chain)
        last_hash = await pg_repo.get_latest_hash(tenant_id)
        previous_hash = last_hash if last_hash else GENESIS_HASH

        latest_seq = await pg_repo.get_latest_sequence_no(tenant_id)
        next_seq = latest_seq + 1

        # 4. Extract values from payload
        new_id = uuid.uuid4()
        user_id_str = payload.get("actor_id")
        user_id = uuid.UUID(user_id_str) if user_id_str else None

        # Sanitize event_type: dots are not valid in PG enum member names
        raw_event_type = payload.get("event_type", "unknown")
        event_type = raw_event_type.replace(".", "_")

        inner_payload = payload.get("payload", {})
        action_raw = inner_payload.get("action", "read")
        action_map = {
            "created": "create",
            "updated": "update",
            "deleted": "delete",
            "approved": "update",
            "rejected": "update",
            "requested": "create",
            "read": "read",
        }
        action = action_map.get(action_raw, action_raw)
        if action not in {"create", "read", "update", "delete", "execute"}:
            action = "execute"

        resource = inner_payload.get("resource", "system")
        resource_id = inner_payload.get("resource_id")
        ip_address = inner_payload.get("ip_address")
        user_agent = inner_payload.get("user_agent")

        # Parse timestamp safely
        timestamp_str = payload.get("timestamp")
        try:
            created_at_dt = parse(timestamp_str).astimezone(timezone.utc) if timestamp_str else None
            from datetime import datetime
            created_at_dt = created_at_dt or datetime.now(timezone.utc)
        except Exception:
            from datetime import datetime
            created_at_dt = datetime.now(timezone.utc)

        # Inject event_type into metadata for PG backward compat
        inner_payload["event_type"] = event_type

        # 5. Compute Integrity Hash
        new_hash = compute_audit_hash(
            previous_hash=previous_hash,
            id_val=str(new_id),
            tenant_id=str(tenant_id),
            user_id=str(user_id) if user_id else "None",
            event_type=event_type,
            resource=resource,
            resource_id=str(resource_id) if resource_id else "None",
            action=action,
            metadata=inner_payload,
            created_at=created_at_dt
        )

        # 6. Build the abstract record
        record = AuditRecord(
            record_id=new_id,
            tenant_id=tenant_id,
            sequence_no=next_seq,
            created_at=created_at_dt,
            actor_id=user_id,
            actor_type="user" if user_id else "system",
            action=action,
            frameworks_affected=inner_payload.get("frameworks_affected", []),
            resource=resource,
            resource_id=str(resource_id) if resource_id else None,
            execution_trace=inner_payload.get("execution_trace"),
            metadata=inner_payload,
            ip_address=ip_address,
            user_agent=user_agent,
            previous_hash=previous_hash,
            integrity_hash=new_hash
        )

        # 7. Write to PostgreSQL (primary - this MUST succeed)
        await pg_repo.append(record)
        logger.info(f"Audit event written to PostgreSQL. Type={event_type}, Seq={next_seq}, Tenant={tenant_id}")

        # 8. Best-effort ClickHouse write (does NOT block Postgres commit on failure)
        try:
            from app.core.audit.repository import ClickHouseAuditRepository
            from app.core.clickhouse import get_clickhouse_client
            ch_client = await get_clickhouse_client()
            ch_repo = ClickHouseAuditRepository(ch_client)
            await ch_repo.append(record)
            logger.debug(f"Audit event also written to ClickHouse. Hash: {new_hash}, Seq: {next_seq}")
        except Exception as e:
            # ClickHouse write is best-effort during Phase E migration.
            # Log the error but DO NOT raise - Postgres write will still commit.
            logger.warning(f"ClickHouse write failed (non-critical): {e}")


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO)

    async def main():
        worker = AuditWorker()
        await worker.start()
        await asyncio.Event().wait()

    asyncio.run(main())
