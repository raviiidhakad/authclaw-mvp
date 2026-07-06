import logging
import time
import uuid
from fastapi import HTTPException
from sqlalchemy import select

from app.core.redis import RedisClient
from app.core.rate_limit.plans import plan_limits_for
from app.models.tenant import Tenant
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
        self._redis = None
        self._script = None
        self._script_redis = None

    @property
    def redis(self):
        return self._redis or RedisClient.get()

    @redis.setter
    def redis(self, value):
        self._redis = value
        self._script = None
        self._script_redis = None

    async def _get_script(self):
        redis_client = self.redis
        if not self._script or self._script_redis is not redis_client:
            self._script = redis_client.register_script(TOKEN_BUCKET_LUA)
            self._script_redis = redis_client
        return self._script

    async def check_rate_limit(
        self,
        key: str,
        capacity: int,
        refill_rate_per_sec: float,
        *,
        fail_open: bool = True,
    ) -> bool:
        """
        Check if a request is allowed by the token bucket rate limit.
        Returns True if allowed. Redis failures fail open by default for
        legacy callers, but security-sensitive call sites pass fail_open=False.
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
            mode = "open" if fail_open else "closed"
            logger.error("Redis error during rate limiting, failing %s for key %s: %s", mode, key, e)
            return bool(fail_open)

rate_limiter = RateLimiter()

from app.core.engine.audit import AuditEngine

async def _load_tenant_plan(db, tenant_id: str):
    try:
        tenant_uuid = uuid.UUID(str(tenant_id))
        result = await db.execute(select(Tenant).where(Tenant.id == tenant_uuid))
        tenant = result.scalars().first()
        if tenant is not None:
            return plan_limits_for(tenant.plan, tenant.settings)
    except Exception:
        pass
    return plan_limits_for(None, None)


async def check_gateway_limits(
    tenant_id: str,
    api_key_id: str,
    db,
    provider_id: str = None,
    route_id: str = None,
    model: str = None,
    include_base: bool = True,
) -> None:
    """
    Evaluates global, tenant, apikey, and provider hierarchy.
    Raises HTTPException(429) if exceeded.
    """
    plan_limits = await _load_tenant_plan(db, tenant_id)
    limits = []
    if include_base:
        limits.extend([
            {
                "scope": "tenant_minute",
                "key": f"rl:tnt:{tenant_id}:minute",
                "capacity": plan_limits.requests_per_minute,
                "rate": plan_limits.requests_per_minute / 60,
            },
            {
                "scope": "tenant_day",
                "key": f"rl:tnt:{tenant_id}:day",
                "capacity": plan_limits.requests_per_day,
                "rate": plan_limits.requests_per_day / 86_400,
            },
            {
                "scope": "api_key_minute",
                "key": f"rl:key:{api_key_id}:minute",
                "capacity": plan_limits.api_key_requests_per_minute,
                "rate": plan_limits.api_key_requests_per_minute / 60,
            },
        ])
    if provider_id:
        limits.append({
            "scope": "provider_minute",
            "key": f"rl:tnt:{tenant_id}:provider:{provider_id}:minute",
            "capacity": plan_limits.provider_requests_per_minute,
            "rate": plan_limits.provider_requests_per_minute / 60,
        })
    if route_id and model:
        limits.append({
            "scope": "route_model_minute",
            "key": f"rl:tnt:{tenant_id}:route:{route_id}:model:{model}:minute",
            "capacity": plan_limits.route_model_requests_per_minute,
            "rate": plan_limits.route_model_requests_per_minute / 60,
        })

    for limit in limits:
        allowed = await rate_limiter.check_rate_limit(
            limit["key"],
            limit["capacity"],
            limit["rate"],
            fail_open=False,
        )
        if not allowed:
            audit_engine = AuditEngine(db)
            try:
                await audit_engine.log_rate_limit_exceeded(tenant_id, api_key_id, limit["scope"])
            except Exception as exc:
                logger.warning("Failed to audit gateway rate limit event: %s", exc)
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please retry later.",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Scope": limit["scope"],
                    "X-RateLimit-Plan": plan_limits.plan_name,
                },
            )
