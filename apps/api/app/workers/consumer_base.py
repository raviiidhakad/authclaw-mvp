import json
import logging
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, List
from aiokafka import AIOKafkaConsumer, ConsumerRecord
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.event import ProcessedEvent
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

logger = logging.getLogger(__name__)
SUPPORTED_EVENT_VERSION = 1


class ConsumerMessageError(Exception):
    def __init__(self, classification: str, message: str):
        super().__init__(message)
        self.classification = classification

class KafkaConsumerBase:
    def __init__(self, topics: List[str], group_id: str, max_retries: int = 3, retry_backoff_seconds: float = 1.0):
        self.topics = topics
        self.group_id = group_id
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self._consumer = None
        self._running = False
        # Optional Dead Letter Queue topic
        self.dlq_topic = f"{topics[0]}.dlq"

    async def start(self):
        self._consumer = AIOKafkaConsumer(
            *self.topics,
            bootstrap_servers=settings.KAFKA_BROKERS,
            group_id=self.group_id,
            enable_auto_commit=False,
            auto_offset_reset='earliest'
        )
        await self._consumer.start()
        self._running = True
        logger.info(f"Started Kafka Consumer for {self.topics} in group {self.group_id}")
        asyncio.create_task(self._consume_loop())

    async def stop(self):
        self._running = False
        if self._consumer:
            await self._consumer.stop()
            logger.info(f"Stopped Kafka Consumer for {self.group_id}")

    async def _consume_loop(self):
        logger.info(f"Consumer loop started for {self.group_id}")
        while self._running:
            try:
                # Poll for messages
                result = await self._consumer.getmany(timeout_ms=1000, max_records=10)
                if result:
                    logger.info(f"Got {sum(len(m) for m in result.values())} messages from Kafka")
                for tp, messages in result.items():
                    for message in messages:
                        logger.info(f"Processing message {message.offset} from {tp.topic}")
                        await self._process_message_with_retries(message)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Error in consumer loop for {self.group_id}: {e}")
                await asyncio.sleep(1)

    async def _process_message_with_retries(self, message: ConsumerRecord, max_retries: int | None = None):
        max_retries = self.max_retries if max_retries is None else max_retries
        attempts = 0
        max_attempts = max_retries + 1
        while attempts < max_attempts:
            attempts += 1
            try:
                await self._process_message_idempotent(message)
                # Commit offset explicitly after processing
                await self._consumer.commit()
                return
            except ConsumerMessageError as exc:
                await self._route_to_dlq(message, exc.classification, attempts, exc)
                await self._consumer.commit()
                return
            except ValidationError as ve:
                await self._route_to_dlq(message, "validation_error", attempts, ve)
                await self._consumer.commit()
                return
            except Exception as e:
                logger.warning(
                    "Error processing message %s, attempt %s/%s: %s",
                    message.offset,
                    attempts,
                    max_attempts,
                    self._safe_error_summary(e),
                )
                if attempts >= max_attempts:
                    await self._route_to_dlq(message, "retry_exhausted", attempts, e)
                    await self._consumer.commit()
                    return
                if self.retry_backoff_seconds > 0:
                    await asyncio.sleep(min(self.retry_backoff_seconds * (2 ** (attempts - 1)), 30))

    async def _process_message_idempotent(self, message: ConsumerRecord):
        payload = self._decode_payload(message.value)
        version = payload.get("schema_version", payload.get("version", SUPPORTED_EVENT_VERSION))
        try:
            version = int(version)
        except (TypeError, ValueError) as exc:
            raise ConsumerMessageError("malformed_event", "Invalid event schema version") from exc
        if version != SUPPORTED_EVENT_VERSION:
            raise ConsumerMessageError("unsupported_schema", f"Unsupported event schema version {version}")

        event_id_str = payload.get("event_id")
        tenant_id_str = payload.get("tenant_id")
        
        if not event_id_str:
            raise ConsumerMessageError("malformed_event", "Message missing event_id")
        try:
            event_id = uuid.UUID(str(event_id_str))
            tenant_id = uuid.UUID(str(tenant_id_str)) if tenant_id_str else None
        except ValueError as exc:
            raise ConsumerMessageError("malformed_event", "Message has invalid UUID fields") from exc

        async with AsyncSessionLocal() as db:
            # Idempotency check
            stmt = select(ProcessedEvent).where(
                ProcessedEvent.event_id == event_id,
                ProcessedEvent.consumer_group == self.group_id
            )
            result = await db.execute(stmt)
            if result.scalars().first():
                logger.debug(f"Event {event_id_str} already processed by {self.group_id}. Skipping.")
                return

            # Apply RLS Context if tenant_id is present
            if tenant_id_str:
                await db.execute(
                    text("SELECT set_config('app.current_tenant_id', :tenant_id, true)").bindparams(
                        tenant_id=tenant_id_str
                    )
                )

            processed = ProcessedEvent(
                event_id=event_id,
                tenant_id=tenant_id,
                consumer_group=self.group_id
            )
            db.add(processed)
            try:
                await db.flush()
            except IntegrityError:
                await db.rollback()
                logger.info(f"Event {event_id_str} already processed by {self.group_id}. Skipping.")
                return

            # Actually process the business logic
            await self.process(payload, db)

            # Reset RLS Context (good practice before commit/rollback, though transaction isolates it)
            if tenant_id_str:
                await db.execute(text("RESET app.current_tenant_id;"))

            await db.commit()

    async def process(self, payload: dict, db):
        """
        To be implemented by subclasses.
        Contains the specific business logic for the worker.
        """
        raise NotImplementedError

    def _decode_payload(self, value: Any) -> dict:
        try:
            if isinstance(value, dict):
                payload = value
            elif isinstance(value, (bytes, bytearray)):
                payload = json.loads(value.decode("utf-8"))
            elif isinstance(value, str):
                payload = json.loads(value)
            else:
                raise TypeError(f"unsupported payload type {type(value).__name__}")
        except Exception as exc:
            raise ConsumerMessageError("malformed_event", "Malformed event payload") from exc
        if not isinstance(payload, dict):
            raise ConsumerMessageError("malformed_event", "Event payload must be a JSON object")
        return payload

    def _safe_error_summary(self, error: Exception) -> str:
        return type(error).__name__ if str(error) == "" else f"{type(error).__name__}: {str(error)[:160]}"

    async def _route_to_dlq(
        self,
        message: ConsumerRecord,
        failure_classification: str,
        attempt_count: int,
        error: Exception,
    ):
        """
        Publish safe failure metadata to a dead-letter queue topic.
        """
        payload = message.value if isinstance(message.value, dict) else {}
        if not isinstance(payload, dict):
            try:
                payload = self._decode_payload(message.value)
            except ConsumerMessageError:
                payload = {}
        topic = getattr(message, "topic", self.topics[0])
        dlq_event = {
            "schema_version": SUPPORTED_EVENT_VERSION,
            "event_id": str(payload.get("event_id") or f"{topic}:{getattr(message, 'partition', 0)}:{getattr(message, 'offset', 'unknown')}"),
            "tenant_id": payload.get("tenant_id"),
            "original_topic": topic,
            "original_schema_version": payload.get("schema_version", payload.get("version")),
            "consumer_group": self.group_id,
            "failure_classification": failure_classification,
            "attempt_count": attempt_count,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "error_summary": self._safe_error_summary(error),
        }
        try:
            from app.core.events.producer import producer
            await producer.publish(self.dlq_topic, dlq_event)
            logger.info(
                "Routed message to DLQ",
                extra={
                    "event_id": dlq_event["event_id"],
                    "tenant_id": dlq_event["tenant_id"],
                    "dlq_topic": self.dlq_topic,
                    "failure_classification": failure_classification,
                    "attempt_count": attempt_count,
                },
            )
        except Exception as e:
            logger.error(
                "Failed to route message to DLQ",
                extra={
                    "dlq_topic": self.dlq_topic,
                    "failure_classification": failure_classification,
                    "attempt_count": attempt_count,
                },
                exc_info=True,
            )
            raise
