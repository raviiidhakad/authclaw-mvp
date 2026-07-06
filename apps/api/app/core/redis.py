import asyncio
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
        await client.aclose()

# Singleton-like instance for internal engines/services that don't use FastAPI Depends
class RedisClient:
    _instance = None
    _loop = None

    @classmethod
    def get(cls) -> redis.Redis:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if cls._instance is None or cls._loop is not loop:
            cls._instance = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
            cls._loop = loop
        return cls._instance
