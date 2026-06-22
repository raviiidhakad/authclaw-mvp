import logging
import time
from fastapi import HTTPException
from app.core.redis import RedisClient
import redis.asyncio as redis

logger = logging.getLogger(__name__)

# Token Bucket Lua Script
# KEYS[1]: bucket key
# ARGV[1]: capacity (max tokens)
# ARGV[2]: refill rate (tokens per millisecond)
# ARGV[3]: current time (milliseconds)
# ARGV[4]: requested tokens

TOKEN_BUCKET_LUA = """
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local bucket = redis.call("HMGET", KEYS[1], "tokens", "last_update")
local tokens = tonumber(bucket[1])
local last_update = tonumber(bucket[2])

if tokens == nil then
    tokens = capacity
    last_update = now
end

local delta = math.max(0, now - last_update)
tokens = math.min(capacity, tokens + (delta * refill_rate))

if tokens >= requested then
    tokens = tokens - requested
    redis.call("HMSET", KEYS[1], "tokens", tokens, "last_update", now)
    local ttl = math.ceil(capacity / refill_rate / 1000)
    redis.call("EXPIRE", KEYS[1], ttl)
    return 1
else
    return 0
end
"""

class RateLimiter:
    def __init__(self):
        self.redis = RedisClient.get()
        self._script = None

    async def _get_script(self):
        if not self._script:
            self._script = self.redis.register_script(TOKEN_BUCKET_LUA)
        return self._script

    async def check_rate_limit(self, key: str, capacity: int, refill_rate_per_sec: float) -> bool:
        """
        Check if a request is allowed by the token bucket rate limit.
        Returns True if allowed (or if Redis is down/fail-open), False if 429.
        """
        try:
            script = await self._get_script()
            now_ms = int(time.time() * 1000)
            refill_rate_ms = refill_rate_per_sec / 1000.0
            
            allowed = await script(
                keys=[key],
                args=[capacity, refill_rate_ms, now_ms, 1]
            )
            return bool(allowed)
        except redis.RedisError as e:
            logger.error(f"Redis error during rate limiting, failing open for key {key}: {e}")
            return True

rate_limiter = RateLimiter()

from app.core.engine.audit import AuditEngine

async def check_gateway_limits(tenant_id: str, api_key_id: str, db, provider_id: str = None) -> None:
    """
    Evaluates global, tenant, apikey, and provider hierarchy.
    Raises HTTPException(429) if exceeded.
    """
    # Define limits (in a real app, these would come from the database/config)
    # For Phase A, we use hardcoded safe defaults or read from config if available.
    limits = [
        {"key": "rl:global", "capacity": 10000, "rate": 1000},
        {"key": f"rl:tnt:{tenant_id}", "capacity": 1000, "rate": 100},
        {"key": f"rl:key:{api_key_id}", "capacity": 100, "rate": 10},
    ]
    if provider_id:
        limits.append({"key": f"rl:prv:{provider_id}", "capacity": 50, "rate": 5})

    for limit in limits:
        allowed = await rate_limiter.check_rate_limit(limit["key"], limit["capacity"], limit["rate"])
        if not allowed:
            audit_engine = AuditEngine(db)
            await audit_engine.log_rate_limit_exceeded(tenant_id, api_key_id, limit["key"])
            raise HTTPException(status_code=429, detail=f"Rate limit exceeded for {limit['key']}")
