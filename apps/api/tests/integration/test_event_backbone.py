import pytest
import asyncio
import uuid
import secrets
import os
import time
from typing import Dict, Any
from sqlalchemy import select
from pydantic import BaseModel

from app.models.event import WALEvent, WALEventStatus, ProcessedEvent
from app.models.user import User
from app.models.tenant import Tenant
from app.models.audit import AuditLog
from app.core.config import settings
from app.schemas.events import SecurityEvent, AuditEvent
from app.core.database import AsyncSessionLocal
from app.workers.consumer_base import KafkaConsumerBase


class _FakeKafkaClient:
    def __init__(self):
        self.commits = 0

    async def commit(self):
        self.commits += 1


class _FakeMessage:
    def __init__(self, value, offset=1):
        self.value = value
        self.topic = "authclaw.test.events"
        self.partition = 0
        self.offset = offset


class _RecordingConsumer(KafkaConsumerBase):
    def __init__(self, failures=0, always_fail=False):
        super().__init__(
            topics=["authclaw.test.events"],
            group_id=f"test-consumer-{uuid.uuid4()}",
            max_retries=2,
            retry_backoff_seconds=0,
        )
        self._consumer = _FakeKafkaClient()
        self.failures = failures
        self.always_fail = always_fail
        self.calls = []

    async def process(self, payload, db):
        self.calls.append(dict(payload))
        if self.always_fail or len(self.calls) <= self.failures:
            raise RuntimeError("processing failed")


def _event_payload(**overrides):
    payload = {
        "version": 1,
        "event_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "event_type": "test.event",
        "payload": {"safe": "metadata"},
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def captured_dlq(monkeypatch):
    published = []

    async def fake_publish(topic, event):
        published.append((topic, event))

    from app.core.events.producer import producer
    monkeypatch.setattr(producer, "publish", fake_publish)
    return published


@pytest.mark.asyncio
async def test_consumer_retries_transient_failure_then_commits_without_dlq(captured_dlq):
    consumer = _RecordingConsumer(failures=1)
    payload = _event_payload()

    await consumer._process_message_with_retries(_FakeMessage(payload))

    assert len(consumer.calls) == 2
    assert consumer.calls[-1]["event_id"] == payload["event_id"]
    assert consumer._consumer.commits == 1
    assert captured_dlq == []


@pytest.mark.asyncio
async def test_consumer_retry_exhaustion_routes_safe_dlq(captured_dlq):
    consumer = _RecordingConsumer(always_fail=True)
    payload = _event_payload()

    await consumer._process_message_with_retries(_FakeMessage(payload))

    assert len(consumer.calls) == 3
    assert consumer._consumer.commits == 1
    assert len(captured_dlq) == 1
    topic, event = captured_dlq[0]
    assert topic == "authclaw.test.events.dlq"
    assert event["event_id"] == payload["event_id"]
    assert event["tenant_id"] == payload["tenant_id"]
    assert event["failure_classification"] == "retry_exhausted"
    assert event["attempt_count"] == 3
    assert "safe" not in event


@pytest.mark.asyncio
async def test_consumer_handles_malformed_event_then_processes_next_valid_event(captured_dlq):
    consumer = _RecordingConsumer()

    await consumer._process_message_with_retries(_FakeMessage(b"{not-json", offset=10))
    await consumer._process_message_with_retries(_FakeMessage(_event_payload(), offset=11))

    assert len(consumer.calls) == 1
    assert consumer._consumer.commits == 2
    assert captured_dlq[0][1]["failure_classification"] == "malformed_event"


@pytest.mark.asyncio
async def test_consumer_rejects_unsupported_schema_version(captured_dlq):
    consumer = _RecordingConsumer()
    payload = _event_payload(version=99)

    await consumer._process_message_with_retries(_FakeMessage(payload))

    assert consumer.calls == []
    assert consumer._consumer.commits == 1
    assert captured_dlq[0][1]["failure_classification"] == "unsupported_schema"
    assert captured_dlq[0][1]["original_schema_version"] == 99


@pytest.mark.asyncio
async def test_duplicate_delivery_does_not_repeat_destructive_side_effect(captured_dlq):
    consumer = _RecordingConsumer()
    message = _FakeMessage(_event_payload(event_type="remediation.execution.started"))

    await consumer._process_message_with_retries(message)
    await consumer._process_message_with_retries(message)

    assert len(consumer.calls) == 1
    assert consumer._consumer.commits == 2
    assert captured_dlq == []


@pytest.mark.asyncio
async def test_dlq_publication_failure_is_visible(monkeypatch):
    consumer = _RecordingConsumer(always_fail=True)

    async def fail_publish(topic, event):
        raise RuntimeError("dlq unavailable")

    from app.core.events.producer import producer
    monkeypatch.setattr(producer, "publish", fail_publish)

    with pytest.raises(RuntimeError, match="dlq unavailable"):
        await consumer._process_message_with_retries(_FakeMessage(_event_payload()), max_retries=0)

    assert consumer._consumer.commits == 0


@pytest.fixture(scope="module", autouse=True)
def setup_kafka_topics():
    # Use the Redpanda endpoint configured by the caller. CI runs tests on the
    # host via localhost; containerized repros use the compose service name.
    settings.KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:19092")
    # Use random topics to avoid poison pills from previous runs.
    os.environ["KAFKA_AUDIT_TOPIC"] = f"test.audit.events.{uuid.uuid4().hex[:8]}"
    os.environ["KAFKA_SECURITY_TOPIC"] = f"test.security.events.{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
async def redpanda():
    pass
    yield "127.0.0.1:19092"


@pytest.mark.asyncio
async def test_wal_fallback():
    """
    Test WAL insertion when Kafka is not available.
    """
    async with AsyncSessionLocal() as db:
        topic = f"test.wal.topic.{uuid.uuid4().hex[:8]}"
        # Force an invalid broker to simulate Kafka down
        original_broker = settings.KAFKA_BROKERS
        from app.core.events.producer import producer
        settings.KAFKA_BROKERS = "localhost:9999"
        wal_event = None

        try:
            # Restart producer with bad broker
            await producer.stop()
            await producer.start()

            # Try to publish an event
            event = SecurityEvent(
                event_type="test.wal",
                tenant_id=uuid.uuid4(),
                actor_id=uuid.uuid4(),
                payload={"test": "data"}
            )
            await producer.publish(topic, event)

            # Check that the new event is in WAL.
            result = await db.execute(
                select(WALEvent).where(WALEvent.topic == topic)
            )
            wal_event = result.scalars().first()

            assert wal_event is not None
            assert wal_event.status == WALEventStatus.PENDING.value
            assert "test.wal" in wal_event.payload_bytes
        finally:
            # Cleanup and restore the shared producer settings for later tests.
            if wal_event is not None:
                await db.delete(wal_event)
                await db.commit()
            settings.KAFKA_BROKERS = original_broker
            await producer.stop()


@pytest.mark.asyncio
async def test_audit_worker(redpanda):
    """
    Test that AuditWorker correctly consumes an event and writes to AuditLog.
    """
    async with AsyncSessionLocal() as db:
        # Create a real tenant first so FK constraints pass!
        tenant_id = uuid.uuid4()
        tenant = Tenant(
            id=tenant_id,
            name=f"test-tenant-{uuid.uuid4().hex[:8]}",
            slug=f"test-tenant-{uuid.uuid4().hex[:8]}"
        )
        db.add(tenant)
        await db.commit()

        # Start producer properly with the test container
        from app.core.events.producer import producer
        from app.workers.audit_worker import AuditWorker

        await producer.start()

        audit_worker = AuditWorker()
        await audit_worker.start()

        # Wait for consumer to join group
        await asyncio.sleep(3)

        event = AuditEvent(
            event_type="policy_created",
            tenant_id=tenant_id,
            actor_id=None,
            payload={"action": "execute", "resource": "test", "ip_address": "127.0.0.1"}
        )

        topic = os.environ.get("KAFKA_AUDIT_TOPIC", "authclaw.audit.events")
        await producer.publish(topic, event)

        # Wait for consumer to process
        await asyncio.sleep(3)

        # Check audit log
        from sqlalchemy import text
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))
        result = await db.execute(
            select(AuditLog).where(AuditLog.action == "execute")
        )
        audit_logs = result.scalars().all()

        assert len(audit_logs) > 0
        assert str(audit_logs[0].ip_address) == "127.0.0.1"

        # Cleanup
        await producer.stop()
        await audit_worker.stop()


@pytest.mark.asyncio
async def test_security_worker_brute_force(redpanda):
    """
    Test that SecurityWorker correctly locks an account after 5 failed login events.
    """
    async with AsyncSessionLocal() as db:
        # Create user & tenant
        tenant_id = uuid.uuid4()
        tenant = Tenant(
            id=tenant_id,
            name=f"test-tnt-{secrets.token_hex(4)}",
            slug=f"test-tnt-{secrets.token_hex(4)}"
        )
        db.add(tenant)
        await db.commit()  # commit tenant first

        from sqlalchemy import text
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))

        user_id = uuid.uuid4()
        user = User(
            id=user_id,
            tenant_id=tenant_id,
            email=f"brute{uuid.uuid4().hex[:4]}@example.com",
            password_hash="mock_hash",
            first_name="Brute",
            last_name="Force",
            is_active=True
        )
        db.add(user)
        await db.commit()

        from app.core.events.producer import producer
        from app.workers.security_worker import SecurityWorker

        await producer.start()

        security_worker = SecurityWorker()
        await security_worker.start()

        # Brief pause for consumer-group join; auto_offset_reset='earliest' ensures
        # messages published before join completes are still consumed.
        await asyncio.sleep(1)

        # Publish 5 failed login events
        topic = os.environ.get("KAFKA_SECURITY_TOPIC", "authclaw.security.events")
        for i in range(5):
            event = SecurityEvent(
                event_type="user.login.failed",
                tenant_id=tenant_id,
                actor_id=user_id,
                payload={"reason": "bad_password"}
            )
            await producer.publish(topic, event)

        # Poll the durable DB state until the user is locked or the deadline expires.
        # Replaces the fixed asyncio.sleep(5) which was not deterministic under
        # full-suite resource contention.  20 s gives the SecurityWorker ample time
        # on any loaded machine and is well within the pytest-timeout ceiling.
        _LOCK_POLL_DEADLINE = 20.0  # seconds
        _LOCK_POLL_INTERVAL = 0.5   # seconds
        _deadline = time.monotonic() + _LOCK_POLL_DEADLINE
        locked = False
        while time.monotonic() < _deadline:
            await asyncio.sleep(_LOCK_POLL_INTERVAL)
            await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))
            await db.refresh(user)
            if not user.is_active:
                locked = True
                break

        # Cleanup before assert so worker/producer are stopped even on failure.
        await producer.stop()
        await security_worker.stop()

        assert locked, (
            f"User {user_id} was NOT locked within {_LOCK_POLL_DEADLINE:.0f} s "
            f"after publishing 5 failed-login events to topic {topic!r}"
        )

        # Reset user so repeated runs start from a clean state.
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}';"))
        user.is_active = True
        await db.commit()
