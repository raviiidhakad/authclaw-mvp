import logging
from sqlalchemy import update
from app.workers.consumer_base import KafkaConsumerBase
from app.models.user import User
from app.schemas.events import UserEvent
from app.core.config import settings
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

class SecurityWorker(KafkaConsumerBase):
    def __init__(self):
        import os
        super().__init__(
            topics=[os.environ.get("KAFKA_SECURITY_TOPIC", "authclaw.security.events")],
            group_id="security-worker-group"
        )
        self.redis = None

    async def start(self):
        self.redis = await aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await super().start()

    async def stop(self):
        await super().stop()
        if self.redis:
            await self.redis.aclose()

    async def process(self, payload: dict, db):
        event_type = payload.get("event_type")
        tenant_id = payload.get("tenant_id")
        user_id = payload.get("actor_id")

        if event_type == "user.login.failed" and tenant_id and user_id:
            # Increment failed attempts
            key = f"brute_force:{tenant_id}:{user_id}"
            attempts = await self.redis.incr(key)
            if attempts == 1:
                await self.redis.expire(key, 300) # 5 minute window
            
            if attempts >= 5:
                # Lock account
                await db.execute(
                    update(User)
                    .where(User.id == user_id, User.tenant_id == tenant_id)
                    .values(is_active=False)
                )
                logger.warning(f"Account {user_id} locked due to brute force threshold.")

                # Publish account locked event
                from app.core.events.producer import producer
                lock_event = UserEvent(
                    event_type="user.account.locked",
                    tenant_id=tenant_id,
                    actor_id=user_id,
                    payload={"reason": "brute_force_protection"}
                )
                await producer.publish("authclaw.user.events", lock_event)
