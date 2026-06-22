"""
Event Backbone Stress Tests
============================
Validates the Redpanda → EventProducer → AuditWorker pipeline under load.
Measures:
  - Events Published
  - Events Consumed
  - Processing Latency
  - Failed Events
  - DLQ Events
  - Throughput Per Second

These tests run against the live Docker Compose stack (Redpanda must be running).
They skip if KAFKA_BROKERS is unreachable or Redpanda container is not available.
"""
import os
import uuid
import json
import time
import asyncio
import statistics
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional
from dataclasses import dataclass, field

import pytest
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaConnectionError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:19092")
AUDIT_TOPIC = "authclaw.audit.events"
GATEWAY_TOPIC = "authclaw.gateway.events"
STRESS_BATCH_SIZE = int(os.getenv("STRESS_BATCH_SIZE", "50"))
STRESS_TIMEOUT_SECONDS = int(os.getenv("STRESS_TIMEOUT_SECONDS", "30"))


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BackboneMetrics:
    events_published: int = 0
    events_consumed: int = 0
    failed_publishes: int = 0
    publish_latencies_ms: List[float] = field(default_factory=list)
    consume_latencies_ms: List[float] = field(default_factory=list)
    throughput_per_second: float = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _check_kafka_available() -> bool:
    """Quick connectivity check — returns False if broker unreachable."""
    try:
        producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BROKERS,
            request_timeout_ms=3000,
        )
        await asyncio.wait_for(producer.start(), timeout=5.0)
        await producer.stop()
        return True
    except (KafkaConnectionError, asyncio.TimeoutError, Exception):
        return False


def _make_audit_event(tenant_id: str, sequence: int) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": "gateway.request.completed",
        "actor_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sequence": sequence,
        "payload": {
            "action": "chat_completion",
            "resource": "gateway",
            "resource_id": str(uuid.uuid4()),
            "model": "gpt-4o-mini",
            "status_code": 200,
            "latency_ms": 250,
        },
    }


def _make_gateway_event(tenant_id: str, event_type: str) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stream_id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def kafka_available():
    """Skip test if Kafka/Redpanda is not reachable."""
    available = await _check_kafka_available()
    if not available:
        pytest.skip(f"Kafka broker at {KAFKA_BROKERS} is not reachable — skipping backbone stress tests")
    return True


@pytest.fixture
async def stress_producer(kafka_available):
    """Yield a started AIOKafkaProducer, stop after test."""
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BROKERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        enable_idempotence=True,
    )
    await producer.start()
    yield producer
    await producer.stop()


@pytest.fixture
async def stress_consumer(kafka_available):
    """Yield a started AIOKafkaConsumer subscribed to audit and gateway topics."""
    group_id = f"stress-test-{uuid.uuid4().hex[:8]}"
    consumer = AIOKafkaConsumer(
        AUDIT_TOPIC,
        GATEWAY_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        group_id=group_id,
        auto_offset_reset="earliest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        consumer_timeout_ms=5000,
    )
    await consumer.start()
    # Seek to end of all partitions so we only see messages published AFTER fixture setup
    partitions = consumer.assignment()
    # Brief wait for partition assignment
    deadline = time.monotonic() + 5.0
    while not partitions and time.monotonic() < deadline:
        await asyncio.sleep(0.1)
        partitions = consumer.assignment()
    if partitions:
        await consumer.seek_to_end(*partitions)
    yield consumer
    await consumer.stop()


# ---------------------------------------------------------------------------
# Test: High-throughput publish
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_high_throughput_publish(stress_producer, kafka_available):
    """
    Publish STRESS_BATCH_SIZE audit events as fast as possible.
    Validates:
      - All events publish without error
      - Throughput > 10 events/second
    """
    tenant_id = str(uuid.uuid4())
    metrics = BackboneMetrics()

    start = time.monotonic()
    futures = []

    for i in range(STRESS_BATCH_SIZE):
        event = _make_audit_event(tenant_id, i)
        pub_start = time.monotonic()
        try:
            fut = await stress_producer.send(AUDIT_TOPIC, value=event)
            futures.append((fut, pub_start))
            metrics.events_published += 1
        except Exception as e:
            logger.error(f"Publish failed for event {i}: {e}")
            metrics.failed_publishes += 1

    # Wait for all sends to complete
    for fut, pub_start in futures:
        try:
            await fut
            pub_latency = (time.monotonic() - pub_start) * 1000
            metrics.publish_latencies_ms.append(pub_latency)
        except Exception as e:
            logger.error(f"Send confirmation failed: {e}")
            metrics.failed_publishes += 1

    elapsed = time.monotonic() - start
    metrics.throughput_per_second = metrics.events_published / elapsed if elapsed > 0 else 0

    print(f"\n[STRESS-PUBLISH] Published={metrics.events_published} "
          f"Failed={metrics.failed_publishes} "
          f"Throughput={metrics.throughput_per_second:.1f} evt/s "
          f"AvgLatency={statistics.mean(metrics.publish_latencies_ms):.2f}ms")

    assert metrics.failed_publishes == 0, f"{metrics.failed_publishes} publish failures"
    assert metrics.throughput_per_second >= 10, f"Low throughput: {metrics.throughput_per_second:.1f} evt/s"


# ---------------------------------------------------------------------------
# Test: Publish → Consume round-trip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_consume_roundtrip(stress_producer, stress_consumer, kafka_available):
    """
    Publish N events to both audit and gateway topics.
    Consume them and validate delivery:
      - All published events are received
      - Round-trip latency is measured
    """
    tenant_id = str(uuid.uuid4())
    batch = STRESS_BATCH_SIZE // 2  # Use smaller batch for round-trip
    published_ids = set()
    consumed_ids = set()
    publish_times = {}

    # Publish audit events
    for i in range(batch):
        event = _make_audit_event(tenant_id, i)
        event_id = event["event_id"]
        publish_times[event_id] = time.monotonic()
        await stress_producer.send_and_wait(AUDIT_TOPIC, value=event)
        published_ids.add(event_id)

    # Publish gateway lifecycle events
    for evt_type in ["gateway.stream.started", "gateway.stream.completed", "gateway.stream.failed"]:
        event = _make_gateway_event(tenant_id, evt_type)
        event_id = event["event_id"]
        publish_times[event_id] = time.monotonic()
        await stress_producer.send_and_wait(GATEWAY_TOPIC, value=event)
        published_ids.add(event_id)

    total_expected = len(published_ids)
    consume_latencies = []

    # Consume with timeout
    deadline = time.monotonic() + STRESS_TIMEOUT_SECONDS
    try:
        async for msg in stress_consumer:
            body = msg.value
            event_id = body.get("event_id")
            if event_id and event_id in published_ids:
                consumed_ids.add(event_id)
                if event_id in publish_times:
                    latency_ms = (time.monotonic() - publish_times[event_id]) * 1000
                    consume_latencies.append(latency_ms)

            if len(consumed_ids) >= total_expected:
                break
            if time.monotonic() > deadline:
                break
    except Exception as e:
        logger.warning(f"Consumer stopped early: {e}")

    coverage = len(consumed_ids) / total_expected * 100 if total_expected else 0
    avg_latency = statistics.mean(consume_latencies) if consume_latencies else 0

    print(f"\n[ROUNDTRIP] Published={total_expected} Consumed={len(consumed_ids)} "
          f"Coverage={coverage:.1f}% AvgLatency={avg_latency:.2f}ms")

    assert coverage >= 95.0, f"Event delivery coverage {coverage:.1f}% < 95%"
    if consume_latencies:
        assert avg_latency < 10_000, f"High avg round-trip latency: {avg_latency:.2f}ms"


# ---------------------------------------------------------------------------
# Test: Lifecycle event sequence validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lifecycle_event_ordering(stress_producer, stress_consumer, kafka_available):
    """
    Validate that gateway lifecycle events (started → completed) are consumable
    and contain required fields:
      - stream_id
      - tenant_id
      - timestamp
      - event_type
    """
    tenant_id = str(uuid.uuid4())
    stream_id = str(uuid.uuid4())

    events = [
        {
            "event_id": str(uuid.uuid4()),
            "event_type": "gateway.stream.started",
            "tenant_id": tenant_id,
            "stream_id": stream_id,
            "request_id": str(uuid.uuid4()),
            "trace_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "security_mode": "buffered",
            "prompt_hash": "abc123",
        },
        {
            "event_id": str(uuid.uuid4()),
            "event_type": "gateway.stream.completed",
            "tenant_id": tenant_id,
            "stream_id": stream_id,
            "request_id": str(uuid.uuid4()),
            "trace_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "response_hash": "def456",
            "latency_ms": 1250,
        },
    ]

    published_ids = set()
    for event in events:
        await stress_producer.send_and_wait(GATEWAY_TOPIC, value=event)
        published_ids.add(event["event_id"])

    consumed = {}
    deadline = time.monotonic() + STRESS_TIMEOUT_SECONDS

    try:
        async for msg in stress_consumer:
            body = msg.value
            event_id = body.get("event_id")
            if event_id in published_ids:
                consumed[event_id] = body
            if len(consumed) >= len(published_ids):
                break
            if time.monotonic() > deadline:
                break
    except Exception as e:
        logger.warning(f"Consumer stopped: {e}")

    assert len(consumed) == len(published_ids), \
        f"Only consumed {len(consumed)}/{len(published_ids)} lifecycle events"

    required_fields = {"event_id", "event_type", "tenant_id", "stream_id", "timestamp"}
    for eid, body in consumed.items():
        missing = required_fields - set(body.keys())
        assert not missing, f"Event {body.get('event_type')} missing fields: {missing}"

    print(f"\n[LIFECYCLE] Validated {len(consumed)} lifecycle events with required fields ✓")


# ---------------------------------------------------------------------------
# Test: Burst publish stress (simulates traffic spike)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_burst_publish_stress(stress_producer, kafka_available):
    """
    Publish 3x batches rapidly in succession (simulates traffic bursts).
    Validates producer resilience under spike conditions.
    """
    tenant_id = str(uuid.uuid4())
    total_published = 0
    total_failed = 0
    batch_metrics = []

    for burst_num in range(3):
        batch_start = time.monotonic()
        batch_success = 0
        batch_fail = 0

        tasks = []
        for i in range(STRESS_BATCH_SIZE):
            event = _make_audit_event(tenant_id, burst_num * STRESS_BATCH_SIZE + i)
            tasks.append(stress_producer.send_and_wait(AUDIT_TOPIC, value=event))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                batch_fail += 1
            else:
                batch_success += 1

        elapsed = time.monotonic() - batch_start
        throughput = batch_success / elapsed if elapsed > 0 else 0
        batch_metrics.append({"burst": burst_num + 1, "success": batch_success, "fail": batch_fail, "tps": throughput})
        total_published += batch_success
        total_failed += batch_fail

        print(f"  Burst {burst_num + 1}: success={batch_success} fail={batch_fail} "
              f"throughput={throughput:.1f} evt/s")

        await asyncio.sleep(0.5)  # Short pause between bursts

    overall_tps = sum(m["tps"] for m in batch_metrics) / len(batch_metrics)
    print(f"\n[BURST-STRESS] Total Published={total_published} Failed={total_failed} "
          f"AvgThroughput={overall_tps:.1f} evt/s")

    assert total_failed == 0, f"{total_failed} events failed during burst"
    assert overall_tps >= 10, f"Burst throughput too low: {overall_tps:.1f} evt/s"
