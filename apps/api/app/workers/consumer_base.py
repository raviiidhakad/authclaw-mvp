import json
import logging
import asyncio
from typing import List, Callable, Awaitable
from aiokafka import AIOKafkaConsumer, ConsumerRecord
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.event import ProcessedEvent
from sqlalchemy import select, text
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

class KafkaConsumerBase:
    def __init__(self, topics: List[str], group_id: str):
        self.topics = topics
        self.group_id = group_id
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
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8'))
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
            except Exception as e:
                logger.error(f"Error in consumer loop for {self.group_id}: {e}")
                await asyncio.sleep(1)

    async def _process_message_with_retries(self, message: ConsumerRecord, max_retries: int = 3):
        retries = 0
        while retries <= max_retries:
            try:
                await self._process_message_idempotent(message)
                # Commit offset explicitly after processing
                await self._consumer.commit()
                return
            except ValidationError as ve:
                logger.error(f"Schema validation failed, routing to DLQ: {ve}")
                await self._route_to_dlq(message)
                await self._consumer.commit()
                return
            except Exception as e:
                retries += 1
                logger.warning(f"Error processing message {message.offset}, retry {retries}/{max_retries}: {e}")
                if retries > max_retries:
                    logger.error(f"Max retries exceeded for message {message.offset}. Routing to DLQ.")
                    await self._route_to_dlq(message)
                    await self._consumer.commit()
                    return
                await asyncio.sleep(2 ** retries)

    async def _process_message_idempotent(self, message: ConsumerRecord):
        payload = message.value
        event_id_str = payload.get("event_id")
        tenant_id_str = payload.get("tenant_id")
        
        if not event_id_str:
            raise ValueError("Message missing event_id, cannot process idempotently")

        async with AsyncSessionLocal() as db:
            # Idempotency check
            stmt = select(ProcessedEvent).where(
                ProcessedEvent.event_id == event_id_str,
                ProcessedEvent.consumer_group == self.group_id
            )
            result = await db.execute(stmt)
            if result.scalars().first():
                logger.debug(f"Event {event_id_str} already processed by {self.group_id}. Skipping.")
                return

            # Apply RLS Context if tenant_id is present
            if tenant_id_str:
                await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id_str}';"))

            # Actually process the business logic
            await self.process(payload, db)

            # Record event as processed
            processed = ProcessedEvent(
                event_id=event_id_str,
                tenant_id=tenant_id_str,
                consumer_group=self.group_id
            )
            db.add(processed)

            # Flush to ensure INSERTs execute while RLS context is active
            await db.flush()

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

    async def _route_to_dlq(self, message: ConsumerRecord):
        """
        Publish the raw unprocessable message to a dead-letter queue topic.
        """
        try:
            from app.core.events.producer import producer
            # If the value is a dict, we pass a dummy BaseModel or just use the producer's underlying AIOKafkaProducer
            if producer._producer:
                await producer._producer.send_and_wait(
                    self.dlq_topic,
                    value=json.dumps(message.value).encode('utf-8')
                )
                logger.info(f"Routed message to DLQ: {self.dlq_topic}")
        except Exception as e:
            logger.error(f"Failed to route message to DLQ: {e}")
