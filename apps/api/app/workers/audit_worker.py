import logging
import uuid
from dateutil.parser import parse
from datetime import timezone

from app.workers.consumer_base import KafkaConsumerBase
from app.models.tenant import Tenant
from app.core.audit.repository import PostgresAuditRepository
from app.core.audit.integrity import append_canonical_audit_record

from sqlalchemy import select, text

logger = logging.getLogger(__name__)


class AuditWorker(KafkaConsumerBase):
    def __init__(self):
        import os
        super().__init__(
            topics=[os.environ.get("KAFKA_AUDIT_TOPIC", "authclaw.audit.events")],
            group_id="audit-worker-group"
        )
        self.storage_status = {
            "authoritative_store": "postgres",
            "mirror_store": "clickhouse",
            "postgres_write_success": 0,
            "postgres_write_failure": 0,
            "clickhouse_mirror_success": 0,
            "clickhouse_mirror_failure": 0,
            "clickhouse_mirror_last_error": None,
        }

    async def process(self, payload: dict, db):
        """
        Inserts the immutable audit event into the authoritative ledger.
        Includes SHA-256 hash chaining to ensure audit integrity.
        PostgreSQL is authoritative. ClickHouse is a read-optimized mirror.
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

        try:
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

            # 3. Extract values from payload
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

            # 4. Write through the canonical audit integrity path.
            record = await append_canonical_audit_record(
                pg_repo,
                record_id=new_id,
                tenant_id=tenant_id,
                event_type=event_type,
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
            )
        except Exception:
            self.storage_status["postgres_write_failure"] += 1
            logger.exception(
                "authoritative_audit_write_failed",
                extra={"audit_tenant_id": str(tenant_id), "audit_store": "postgres"},
            )
            raise

        self.storage_status["postgres_write_success"] += 1
        logger.info(
            "authoritative_audit_write_succeeded",
            extra={
                "audit_tenant_id": str(tenant_id),
                "audit_store": "postgres",
                "audit_record_id": str(record.record_id),
                "audit_sequence_no": record.sequence_no,
            },
        )

        # 5. Best-effort ClickHouse write (does NOT block Postgres commit on failure)
        try:
            from app.core.audit.repository import ClickHouseAuditRepository
            from app.core.clickhouse import get_clickhouse_client
            ch_client = await get_clickhouse_client()
            ch_repo = ClickHouseAuditRepository(ch_client)
            await ch_repo.append(record)
            self.storage_status["clickhouse_mirror_success"] += 1
            logger.info(
                "clickhouse_audit_mirror_write_succeeded",
                extra={
                    "audit_tenant_id": str(tenant_id),
                    "audit_store": "clickhouse",
                    "audit_record_id": str(record.record_id),
                    "audit_sequence_no": record.sequence_no,
                },
            )
        except Exception as e:
            self.storage_status["clickhouse_mirror_failure"] += 1
            self.storage_status["clickhouse_mirror_last_error"] = type(e).__name__
            logger.warning(
                "clickhouse_audit_mirror_write_failed",
                extra={
                    "audit_tenant_id": str(tenant_id),
                    "audit_store": "clickhouse",
                    "audit_record_id": str(record.record_id),
                    "audit_sequence_no": record.sequence_no,
                    "audit_mirror_failure_count": self.storage_status["clickhouse_mirror_failure"],
                },
                exc_info=True,
            )


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO)

    async def main():
        worker = AuditWorker()
        await worker.start()
        await asyncio.Event().wait()

    asyncio.run(main())
