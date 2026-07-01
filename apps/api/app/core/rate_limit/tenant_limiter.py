from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

import redis.asyncio as redis
from sqlalchemy import select

from app.core.exceptions import RateLimitException
from app.core.redis import RedisClient
from app.core.rate_limit.plans import TenantPlanLimits, plan_limits_for
from app.models.tenant import Tenant

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    scope: str
    plan: str
    retry_after: int = 60


class TenantPlanLimiter:
    """Conservative Redis-backed limiter for tenant-plan abuse controls."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self.redis = redis_client or RedisClient.get()

    async def limits_for_tenant(self, db: Any, tenant_id: uuid.UUID | str) -> TenantPlanLimits:
        tenant = await self._load_tenant(db, tenant_id)
        return plan_limits_for(
            getattr(tenant, "plan", None),
            getattr(tenant, "settings", None) if tenant is not None else None,
        )

    async def acquire_stream(
        self,
        db: Any,
        tenant_id: uuid.UUID | str,
        api_key_id: uuid.UUID | str,
    ) -> LimitDecision:
        limits = await self.limits_for_tenant(db, tenant_id)
        key = f"rl:active:stream:{tenant_id}:{api_key_id}"
        return await self._acquire_concurrency(
            key,
            limits.concurrent_streams,
            60 * 60,
            "stream_concurrency",
            limits.plan_name,
        )

    async def release_stream(self, tenant_id: uuid.UUID | str, api_key_id: uuid.UUID | str) -> None:
        await self._release(f"rl:active:stream:{tenant_id}:{api_key_id}")

    async def acquire_connector_scan(
        self,
        db: Any,
        tenant_id: uuid.UUID | str,
        provider: str,
        integration_id: uuid.UUID | str,
    ) -> LimitDecision:
        limits = await self.limits_for_tenant(db, tenant_id)
        cooldown_key = f"rl:cooldown:connector:{tenant_id}:{provider}:{integration_id}"
        cooldown_allowed = await self._cooldown(
            cooldown_key,
            limits.connector_scan_interval_seconds,
            "connector_scan_frequency",
            limits.plan_name,
        )
        if not cooldown_allowed.allowed:
            return cooldown_allowed
        active_key = f"rl:active:connector:{tenant_id}"
        return await self._acquire_concurrency(
            active_key,
            limits.connector_scan_concurrency,
            max(limits.connector_scan_interval_seconds, 60),
            "connector_scan_concurrency",
            limits.plan_name,
        )

    async def release_connector_scan(self, tenant_id: uuid.UUID | str) -> None:
        await self._release(f"rl:active:connector:{tenant_id}")

    async def acquire_remediation_job(self, db: Any, tenant_id: uuid.UUID | str) -> LimitDecision:
        limits = await self.limits_for_tenant(db, tenant_id)
        return await self._acquire_concurrency(
            f"rl:active:remediation:{tenant_id}",
            limits.remediation_job_concurrency,
            60 * 60,
            "remediation_job_concurrency",
            limits.plan_name,
        )

    async def release_remediation_job(self, tenant_id: uuid.UUID | str) -> None:
        await self._release(f"rl:active:remediation:{tenant_id}")

    async def check_report_generation(self, db: Any, tenant_id: uuid.UUID | str) -> LimitDecision:
        limits = await self.limits_for_tenant(db, tenant_id)
        key = f"rl:reports:{tenant_id}"
        return await self._fixed_window(
            key,
            limits.report_generation_per_hour,
            60 * 60,
            "report_generation",
            limits.plan_name,
        )

    async def _load_tenant(self, db: Any, tenant_id: uuid.UUID | str) -> Tenant | None:
        if db is None:
            return None
        try:
            tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))
            result = await db.execute(select(Tenant).where(Tenant.id == tenant_uuid))
            return result.scalars().first()
        except Exception:
            return None

    async def _acquire_concurrency(
        self,
        key: str,
        limit: int,
        ttl_seconds: int,
        scope: str,
        plan: str,
    ) -> LimitDecision:
        try:
            current = int(await self.redis.incr(key))
            await self.redis.expire(key, max(1, ttl_seconds))
            if current <= limit:
                return LimitDecision(True, scope, plan)
            await self._release(key)
            return LimitDecision(False, scope, plan, retry_after=60)
        except redis.RedisError as exc:
            logger.error("Rate limit store unavailable for scope=%s; failing closed: %s", scope, exc)
            return LimitDecision(False, scope, plan, retry_after=60)

    async def _release(self, key: str) -> None:
        try:
            remaining = int(await self.redis.decr(key))
            if remaining <= 0:
                await self.redis.delete(key)
        except redis.RedisError as exc:
            logger.warning("Rate limit counter release failed for key=%s: %s", key, exc)

    async def _cooldown(
        self,
        key: str,
        ttl_seconds: int,
        scope: str,
        plan: str,
    ) -> LimitDecision:
        try:
            created = await self.redis.set(key, "1", ex=max(1, ttl_seconds), nx=True)
            if created:
                return LimitDecision(True, scope, plan)
            return LimitDecision(False, scope, plan, retry_after=max(1, ttl_seconds))
        except redis.RedisError as exc:
            logger.error("Rate limit store unavailable for scope=%s; failing closed: %s", scope, exc)
            return LimitDecision(False, scope, plan, retry_after=60)

    async def _fixed_window(
        self,
        key: str,
        limit: int,
        ttl_seconds: int,
        scope: str,
        plan: str,
    ) -> LimitDecision:
        try:
            current = int(await self.redis.incr(key))
            if current == 1:
                await self.redis.expire(key, max(1, ttl_seconds))
            if current <= limit:
                return LimitDecision(True, scope, plan)
            return LimitDecision(False, scope, plan, retry_after=max(1, ttl_seconds))
        except redis.RedisError as exc:
            logger.error("Rate limit store unavailable for scope=%s; failing closed: %s", scope, exc)
            return LimitDecision(False, scope, plan, retry_after=60)


def rate_limit_exception(decision: LimitDecision) -> RateLimitException:
    return RateLimitException(
        detail="Rate limit exceeded. Please retry later.",
        retry_after=decision.retry_after,
    )


tenant_plan_limiter = TenantPlanLimiter()
