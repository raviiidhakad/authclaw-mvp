import redis.asyncio as redis
from typing import AsyncGenerator
from app.core.config import settings

# Create a Redis connection pool
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    decode_responses=True
)

async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    """Dependency for injecting Redis client into routes or services."""
    client = redis.Redis.from_pool(redis_pool)
    try:
        yield client
    finally:
        await client.close()

# Singleton-like instance for internal engines/services that don't use FastAPI Depends
class RedisClient:
    _instance = None

    @classmethod
    def get(cls) -> redis.Redis:
        if cls._instance is None:
            cls._instance = redis.Redis.from_pool(redis_pool)
        return cls._instance
