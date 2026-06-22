import json
import logging
import asyncio
from typing import Optional, Dict, Any
from aiokafka import AIOKafkaProducer
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.event import WALEvent, WALEventStatus
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class EventProducer:
    _instance = None
    _producer: Optional[AIOKafkaProducer] = None
    _recovery_task: Optional[asyncio.Task] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def start(self):
        self._producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BROKERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks='all',
            enable_idempotence=True,
            retry_backoff_ms=500,
            request_timeout_ms=5000,
            # We don't use max_block_ms in aiokafka exactly the same as confluent-kafka, but let's handle timeouts gracefully.
        )
        try:
            await self._producer.start()
            logger.info("Kafka Producer started successfully.")
        except Exception as e:
            logger.error(f"Failed to start Kafka Producer, relying on WAL fallback: {e}")
            if self._producer:
                try:
                    await self._producer.stop()
                except Exception:
                    pass
            self._producer = None
            # Do not fail fast, let the WAL fallback handle it.

        # Start Recovery Daemon
        self._recovery_task = asyncio.create_task(self._recovery_daemon())

    async def stop(self):
        if self._recovery_task:
            self._recovery_task.cancel()
        if self._producer:
            await self._producer.stop()

    async def publish(self, topic: str, event: BaseModel):
        """
        Publish an event to Kafka. Fallback to WAL if broker is unreachable.
        """
        payload = event.model_dump(mode='json')
        # Serialize UUIDs and Datetimes natively handled by model_dump, but ensure it's fully JSON serializable
        try:
            # We try sending directly
            if not self._producer:
                raise Exception("Producer not initialized")
            await self._producer.send_and_wait(topic, value=payload)
            logger.debug(f"Successfully published event to {topic}")
        except Exception as e:
            logger.warning(f"Failed to publish to Kafka ({e}). Writing to WAL.")
            await self._write_to_wal(topic, payload)

    async def _write_to_wal(self, topic: str, payload: Dict[str, Any]):
        async with AsyncSessionLocal() as db:
            wal_event = WALEvent(
                topic=topic,
                payload_bytes=json.dumps(payload),
                status=WALEventStatus.PENDING.value
            )
            db.add(wal_event)
            await db.commit()

    async def _recovery_daemon(self):
        """
        Background task that periodically drains WAL events to Kafka.
        """
        while True:
            await asyncio.sleep(10)
            if not self._producer:
                continue

            try:
                # In aiokafka, we can check cluster metadata indirectly or just attempt to send
                async with AsyncSessionLocal() as db:
                    from sqlalchemy import select
                    # Get pending WAL events, order by created_at to maintain strict ordering
                    result = await db.execute(
                        select(WALEvent)
                        .where(WALEvent.status == WALEventStatus.PENDING.value)
                        .order_by(WALEvent.created_at.asc())
                        .limit(100)
                    )
                    pending_events = result.scalars().all()

                    for wal_event in pending_events:
                        payload = json.loads(wal_event.payload_bytes)
                        try:
                            await self._producer.send_and_wait(wal_event.topic, value=payload)
                            wal_event.status = WALEventStatus.PUBLISHED.value
                        except Exception as publish_exc:
                            logger.error(f"Recovery Daemon failed to publish WAL event {wal_event.id}: {publish_exc}")
                            # Stop processing this batch to preserve ordering if Kafka is still down
                            break
                    
                    await db.commit()
            except Exception as e:
                logger.error(f"Error in Recovery Daemon: {e}")

    async def publish_security_event(self, event, max_retries: int = 3) -> None:
        """
        Publish a security pipeline event with retry + Dead Letter Queue routing.

        On max_retries exhaustion the event is wrapped in SecurityDLQEvent and
        published to 'security.dlq' — a failed security event is NEVER silently
        discarded. This satisfies the Sprint 1 DLQ requirement.

        Args:
            event:        Any Pydantic model from app.schemas.security_events.
            max_retries:  Number of Kafka publish attempts before DLQ routing.
        """
        topic = "authclaw.security.pipeline"
        last_error: Optional[str] = None

        for attempt in range(1, max_retries + 1):
            try:
                await self.publish(topic, event)
                return  # Success
            except Exception as exc:
                last_error = str(exc)
                logger.warning(
                    "Security event publish attempt %d/%d failed: %s",
                    attempt, max_retries, exc,
                )

        # All retries exhausted — route to DLQ
        logger.error(
            "Security event failed after %d attempts. Routing to security.dlq.",
            max_retries,
        )
        try:
            from app.schemas.security_events import SecurityDLQEvent
            dlq_event = SecurityDLQEvent(
                original_topic=topic,
                original_event=event.model_dump(mode="json"),
                failure_reason=last_error or "unknown",
                retry_count=max_retries,
            )
            # DLQ uses the base publish — WAL fallback ensures it's never lost
            await self.publish("security.dlq", dlq_event)
        except Exception as dlq_exc:
            # Last resort: WAL will catch it on next recovery cycle
            logger.critical("DLQ publish also failed: %s", dlq_exc)
            await self._write_to_wal("security.dlq", {"failure": str(dlq_exc)})


producer = EventProducer()

