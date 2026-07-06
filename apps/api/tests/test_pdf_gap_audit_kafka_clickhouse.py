import asyncio
import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import BaseModel

from app.core.audit.integrity import compute_canonical_record_hash
from app.core.audit.repository import AuditRecord
from app.core.events.audit_hash import GENESIS_HASH
from app.core.events.producer import producer
from app.workers.audit_worker import AuditWorker


class FakeDb:
    def __init__(self):
        self.calls = []

    async def execute(self, *args, **kwargs):
        self.calls.append((args, kwargs))


def _payload(tenant_id: uuid.UUID) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": "gateway.request.completed",
        "tenant_id": str(tenant_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"action": "read", "resource": "gateway", "resource_id": str(uuid.uuid4())},
    }


async def _fake_append_record(_repo, **kwargs) -> AuditRecord:
    record = AuditRecord(
        sequence_no=1,
        previous_hash=GENESIS_HASH,
        integrity_hash="",
        **kwargs,
    )
    return record.model_copy(update={"integrity_hash": compute_canonical_record_hash(record)})


@pytest.mark.asyncio
async def test_audit_worker_marks_postgres_authoritative_and_clickhouse_mirror_success(monkeypatch):
    tenant_id = uuid.uuid4()
    mirrored = []

    class FakeClickHouseRepository:
        def __init__(self, _client):
            pass

        async def append(self, record):
            mirrored.append(record.record_id)

    async def fake_get_client():
        return object()

    import app.core.audit.repository as audit_repository
    import app.core.clickhouse as clickhouse_module
    import app.workers.audit_worker as audit_worker_module

    monkeypatch.setattr(audit_worker_module, "append_canonical_audit_record", _fake_append_record)
    monkeypatch.setattr(audit_repository, "ClickHouseAuditRepository", FakeClickHouseRepository)
    monkeypatch.setattr(clickhouse_module, "get_clickhouse_client", fake_get_client)

    worker = AuditWorker()
    await worker.process(_payload(tenant_id), FakeDb())

    assert worker.storage_status["authoritative_store"] == "postgres"
    assert worker.storage_status["mirror_store"] == "clickhouse"
    assert worker.storage_status["postgres_write_success"] == 1
    assert worker.storage_status["postgres_write_failure"] == 0
    assert worker.storage_status["clickhouse_mirror_success"] == 1
    assert worker.storage_status["clickhouse_mirror_failure"] == 0
    assert len(mirrored) == 1


@pytest.mark.asyncio
async def test_audit_worker_tracks_clickhouse_mirror_failure_without_rejecting_postgres(monkeypatch, caplog):
    tenant_id = uuid.uuid4()

    async def failing_get_client():
        raise RuntimeError("mirror unavailable")

    import app.core.clickhouse as clickhouse_module
    import app.workers.audit_worker as audit_worker_module

    monkeypatch.setattr(audit_worker_module, "append_canonical_audit_record", _fake_append_record)
    monkeypatch.setattr(clickhouse_module, "get_clickhouse_client", failing_get_client)

    worker = AuditWorker()
    await worker.process(_payload(tenant_id), FakeDb())

    assert worker.storage_status["postgres_write_success"] == 1
    assert worker.storage_status["postgres_write_failure"] == 0
    assert worker.storage_status["clickhouse_mirror_success"] == 0
    assert worker.storage_status["clickhouse_mirror_failure"] == 1
    assert worker.storage_status["clickhouse_mirror_last_error"] == "RuntimeError"
    assert "clickhouse_audit_mirror_write_failed" in caplog.text


class KafkaProofEvent(BaseModel):
    event_id: str
    tenant_id: str
    event_type: str
    timestamp: str


async def _kafka_available(brokers: str) -> bool:
    client = AIOKafkaProducer(bootstrap_servers=brokers, request_timeout_ms=3000)
    try:
        await asyncio.wait_for(client.start(), timeout=5)
        return True
    except Exception:
        return False
    finally:
        try:
            await asyncio.wait_for(client.stop(), timeout=5)
        except Exception:
            pass


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(
    os.getenv("AUTHCLAW_RUN_KAFKA_INTEGRATION") != "1",
    reason="set AUTHCLAW_RUN_KAFKA_INTEGRATION=1 and run Redpanda to prove Kafka path",
)
async def test_redpanda_eventproducer_roundtrip():
    brokers = os.getenv("KAFKA_BROKERS", "127.0.0.1:19092")
    if not await _kafka_available(brokers):
        pytest.skip(f"Kafka/Redpanda broker unavailable at {brokers}")

    topic = f"authclaw.pdf-gap.kafka-proof.{uuid.uuid4().hex}"
    event_id = str(uuid.uuid4())
    event = KafkaProofEvent(
        event_id=event_id,
        tenant_id=str(uuid.uuid4()),
        event_type="pdf_gap.kafka.proof",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=brokers,
        group_id=f"pdf-gap-proof-{uuid.uuid4().hex}",
        auto_offset_reset="earliest",
        value_deserializer=lambda body: json.loads(body.decode("utf-8")),
    )

    await consumer.start()
    await producer.start()
    try:
        await producer.publish(topic, event)
        deadline = asyncio.get_running_loop().time() + 10
        received = None
        while asyncio.get_running_loop().time() < deadline:
            records = await consumer.getmany(timeout_ms=500, max_records=10)
            for messages in records.values():
                for message in messages:
                    if message.value.get("event_id") == event_id:
                        received = message.value
                        break
                if received:
                    break
            if received:
                break
        assert received is not None
        assert received["event_type"] == "pdf_gap.kafka.proof"
        assert received["tenant_id"] == event.tenant_id
    finally:
        await producer.stop()
        await consumer.stop()
