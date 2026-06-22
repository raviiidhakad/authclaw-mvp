import time
import uuid
from typing import Tuple
from redis.asyncio import Redis

class RateLimitExceeded(Exception):
    pass

class TokenBucketRateLimiter:
    """
    Distributed Token Bucket rate limiter using Redis Lua scripting for atomicity.
    Provides burst protection and quota enforcement per Tenant or per API Key.
    """
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        # Lua script ensures atomic token deduction and refill
        self.script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local requested = tonumber(ARGV[4])

        local bucket = redis.call("HMGET", key, "tokens", "last_refill")
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])

        if not tokens then
            tokens = capacity
            last_refill = now
        else
            local time_passed = now - last_refill
            local new_tokens = math.floor(time_passed * refill_rate)
            tokens = math.min(capacity, tokens + new_tokens)
            if new_tokens > 0 then
                last_refill = now
            end
        end

        if tokens >= requested then
            tokens = tokens - requested
            redis.call("HMSET", key, "tokens", tokens, "last_refill", last_refill)
            redis.call("EXPIRE", key, math.ceil(capacity / refill_rate) * 2)
            return {1, tokens}
        else
            return {0, tokens}
        end
        """

    async def consume(self, key: str, capacity: int, refill_rate: float, tokens: int = 1) -> Tuple[bool, int]:
        """
        Attempts to consume `tokens` from the bucket.
        Returns (allowed: bool, remaining_tokens: int)
        """
        now = time.time()
        result = await self.redis.eval(
            self.script, 
            1, 
            key, 
            capacity, 
            refill_rate, 
            now, 
            tokens
        )
        return bool(result[0]), int(result[1])

    async def check_tenant(self, tenant_id: uuid.UUID, capacity: int = 100, refill_rate: float = 10.0):
        key = f"rate:tenant:{tenant_id}"
        allowed, _ = await self.consume(key, capacity, refill_rate)
        if not allowed:
            raise RateLimitExceeded("Tenant rate limit exceeded")

    async def check_api_key(self, api_key_id: uuid.UUID, capacity: int = 10, refill_rate: float = 1.0):
        key = f"rate:apikey:{api_key_id}"
        allowed, _ = await self.consume(key, capacity, refill_rate)
        if not allowed:
            raise RateLimitExceeded("API Key rate limit exceeded")
