"""
AuthClaw Sprint 1 — Redis Policy Cache
---------------------------------------
Compiles tenant YAML/DB policies into a native Python dict structure
and stores it in Redis for sub-millisecond retrieval on the hot path.

Key Design Principles:
  • NO TTL — cache is purely event-driven. It is invalidated on:
      - policy.created
      - policy.updated
      - policy.deleted
      - tenant.deleted
  • Source of truth: PostgreSQL (the raw Policy + PolicyRule rows).
  • Cached payload: compiled Python dict — never raw YAML.
  • Tenant isolation: every key is namespaced by tenant_id UUID.
  • Failure fallback: if Redis is unavailable, the gateway fetches
    directly from PostgreSQL and logs a WARNING. The gateway does not
    fail open.

Cache key format:
  tenant:policy:compiled:{tenant_id}

Compiled payload format:
  {
    "entity_actions": {
      "EMAIL_ADDRESS": "MASK",
      "CREDIT_CARD": "BLOCK",
      ...
    },
    "classification_overrides": {
      "EMAIL_ADDRESS": "LOW",
      ...
    },
    "keyword_blocklist": ["confidential", "top secret"],
    "compiled_at": "2026-06-20T08:00:00Z"
  }
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models.policy import Policy, PolicyRule, PolicyAction, RuleType

logger = logging.getLogger(__name__)


class PolicyCache:
    """
    Redis-backed compiled policy cache.

    Usage:
        compiled = await policy_cache.get(tenant_id, db)
        # -> Dict with entity_actions, classification_overrides, keyword_blocklist

        await policy_cache.invalidate(tenant_id)
        # -> Deletes the cache key; next request recompiles from DB
    """

    def __init__(self, redis_url: str, key_prefix: str):
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._redis: Optional[aioredis.Redis] = None

    async def start(self) -> None:
        """Connect to Redis on application startup."""
        try:
            self._redis = await aioredis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            await self._redis.ping()
            logger.info("PolicyCache connected to Redis.")
        except Exception as exc:
            logger.error("PolicyCache failed to connect to Redis: %s", exc)
            self._redis = None

    async def stop(self) -> None:
        """Close Redis connection on application shutdown."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    def is_healthy(self) -> bool:
        return self._redis is not None

    def _make_key(self, tenant_id: uuid.UUID) -> str:
        return f"{self._key_prefix}:{tenant_id}"

    async def get(
        self,
        tenant_id: uuid.UUID,
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """
        Retrieve compiled policy for a tenant.
        Returns from Redis if cached, else compiles from DB and caches.

        Never raises — returns an empty policy dict on any failure.
        """
        # 1. Try Redis cache first
        if self._redis:
            try:
                raw = await self._redis.get(self._make_key(tenant_id))
                if raw:
                    return json.loads(raw)
            except Exception as exc:
                logger.warning("PolicyCache Redis read failed: %s. Falling back to DB.", exc)

        # 2. Compile from DB
        try:
            compiled = await self._compile_from_db(tenant_id, db)
            await self._store(tenant_id, compiled)
            return compiled
        except Exception as exc:
            logger.error("PolicyCache compile from DB failed for tenant %s: %s", tenant_id, exc)
            return self._empty_policy()

    async def invalidate(self, tenant_id: uuid.UUID) -> None:
        """
        Delete the compiled policy from Redis.
        Called on: policy.created, policy.updated, policy.deleted, tenant.deleted.
        The next request will recompile from DB automatically.
        """
        if not self._redis:
            return
        try:
            key = self._make_key(tenant_id)
            deleted = await self._redis.delete(key)
            if deleted:
                logger.info("PolicyCache invalidated for tenant %s.", tenant_id)
            else:
                logger.debug("PolicyCache invalidate: key not found for tenant %s (was already empty).", tenant_id)
        except Exception as exc:
            logger.warning("PolicyCache invalidation failed for tenant %s: %s", tenant_id, exc)

    async def _store(self, tenant_id: uuid.UUID, compiled: Dict[str, Any]) -> None:
        """Persist compiled policy dict to Redis. No TTL — event-driven invalidation only."""
        if not self._redis:
            return
        try:
            await self._redis.set(
                self._make_key(tenant_id),
                json.dumps(compiled, default=str),
                # No EX/PX — event-driven invalidation only
            )
        except Exception as exc:
            logger.warning("PolicyCache Redis write failed: %s", exc)

    async def _compile_from_db(
        self, tenant_id: uuid.UUID, db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Fetch all active policies + rules for the tenant and compile them
        into a native Python dict for fast in-memory evaluation.
        """
        result = await db.execute(
            select(Policy)
            .options(selectinload(Policy.rules))
            .where(Policy.tenant_id == tenant_id, Policy.is_active == True)
            .order_by(Policy.priority.desc())
        )
        policies: List[Policy] = list(result.scalars().all())
        return self.compile_policies(policies)

    @staticmethod
    def compile_policies(policies: List[Policy]) -> Dict[str, Any]:
        """Compile already-loaded policy ORM objects into the gateway runtime format."""
        entity_actions: Dict[str, str] = {}
        classification_overrides: Dict[str, str] = {}
        keyword_blocklist: List[str] = []
        reversible_entities: List[str] = []
        policy_ids: List[str] = []

        for policy in sorted(policies, key=lambda item: item.priority, reverse=True):
            if not policy.is_active:
                continue
            policy_ids.append(str(policy.id))
            for rule in policy.rules:
                if not rule.is_active:
                    continue

                if rule.rule_type == RuleType.pii_block:
                    for entity_type in rule.conditions.get("pii_types", []):
                        # Higher-priority policy wins; block > redact
                        existing = entity_actions.get(entity_type.upper())
                        if existing != "BLOCK":
                            entity_actions[entity_type.upper()] = "BLOCK"

                elif rule.rule_type == RuleType.pii_redact:
                    mode = rule.conditions.get("redaction_mode", "MASK").upper()
                    is_reversible = rule.conditions.get("reversible", False)
                    for entity_type in rule.conditions.get("pii_types", []):
                        et = entity_type.upper()
                        if et not in entity_actions:
                            entity_actions[et] = mode
                            if is_reversible and et not in reversible_entities:
                                reversible_entities.append(et)

                elif rule.rule_type == RuleType.pii_synthetic:
                    is_reversible = rule.conditions.get("reversible", False)
                    for entity_type in rule.conditions.get("pii_types", []):
                        et = entity_type.upper()
                        if et not in entity_actions:
                            entity_actions[et] = "SYNTHETIC"
                            if is_reversible and et not in reversible_entities:
                                reversible_entities.append(et)

                elif rule.rule_type == RuleType.content_filter:
                    for kw in rule.conditions.get("keywords", []):
                        if kw not in keyword_blocklist:
                            keyword_blocklist.append(kw)

                # classification_overrides — stored in rule.conditions under key "classification_overrides"
                for entity_type, risk_level in rule.conditions.get("classification_overrides", {}).items():
                    if entity_type.upper() not in classification_overrides:
                        classification_overrides[entity_type.upper()] = risk_level.upper()

        return {
            "entity_actions": entity_actions,
            "classification_overrides": classification_overrides,
            "keyword_blocklist": keyword_blocklist,
            "reversible_entities": reversible_entities,
            "policy_ids": policy_ids,
            "compiled_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _empty_policy() -> Dict[str, Any]:
        """Return a safe no-op policy when compilation fails."""
        return {
            "entity_actions": {},
            "classification_overrides": {},
            "keyword_blocklist": [],
            "reversible_entities": [],
            "compiled_at": None,
        }


# Module-level singleton
policy_cache = PolicyCache(
    redis_url=settings.REDIS_URL,
    key_prefix=settings.POLICY_CACHE_KEY_PREFIX,
)
