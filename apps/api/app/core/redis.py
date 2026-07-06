import redis.asyncio as redis
import asyncio
from typing import AsyncGenerator
from app.core.config import settings

async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    """Dependency for injecting Redis client into routes or services."""
    client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()

# Singleton-like instance for internal engines/services that don't use FastAPI Depends
class RedisClient:
    _instance = None
    _clients = {}

    @classmethod
    def get(cls) -> redis.Redis:
        loop = asyncio.get_running_loop()
        key = id(loop)
        client = cls._clients.get(key)
        if client is None:
            client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
            cls._clients[key] = client
            cls._instance = client
        return client

    @classmethod
    async def aclose(cls, *, flush: bool = False) -> None:
        clients = list(cls._clients.values())
        cls._clients.clear()
        cls._instance = None
        for client in clients:
            if flush:
                await client.flushdb()
            await client.aclose()
