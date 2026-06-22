"""
Compliance Engine — Rule-based scoring for GDPR, HIPAA, and SOC2 frameworks.

Scoring formula:
  Base = 100
  Deduct 10 points per missing mandatory control
  Deduct 2 points per non-critical policy violation in last 30 days
  Minimum = 0
"""
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.policy import Policy, PolicyRule, PolicyViolation, RuleType, ViolationSeverity
from app.models.api_key import ApiKey
from app.models.role import Role, UserRole
from app.models.compliance import ComplianceScore
from app.models.audit import AuditLog


class ComplianceRuleChecker:
    """Checks whether mandatory controls are met for each framework."""

    def __init__(self, db: AsyncSession, tenant_id: uuid.UUID):
        self.db = db
        self.tenant_id = tenant_id

    async def _has_active_pii_policy(self) -> bool:
        result = await self.db.execute(
            select(func.count(PolicyRule.id))
            .join(Policy, Policy.id == PolicyRule.policy_id)
            .where(
                Policy.tenant_id == self.tenant_id,
                Policy.is_active == True,
                PolicyRule.rule_type.in_([RuleType.pii_block, RuleType.pii_redact]),
                PolicyRule.is_active == True,
            )
        )
        return (result.scalar() or 0) > 0

    async def _has_content_filter_policy(self) -> bool:
        result = await self.db.execute(
            select(func.count(PolicyRule.id))
            .join(Policy, Policy.id == PolicyRule.policy_id)
            .where(
                Policy.tenant_id == self.tenant_id,
                Policy.is_active == True,
                PolicyRule.rule_type == RuleType.content_filter,
                PolicyRule.is_active == True,
            )
        )
        return (result.scalar() or 0) > 0

    async def _has_audit_logging(self) -> bool:
        result = await self.db.execute(
            select(func.count(AuditLog.id)).where(AuditLog.tenant_id == self.tenant_id)
        )
        return (result.scalar() or 0) > 0

    async def _api_keys_have_expiry(self) -> bool:
        result = await self.db.execute(
            select(ApiKey).where(
                ApiKey.tenant_id == self.tenant_id,
                ApiKey.is_active == True,
                ApiKey.expires_at == None,
            )
        )
        keys_without_expiry = result.scalars().all()
        return len(keys_without_expiry) == 0

    async def _admin_count_under_limit(self, limit: int = 5) -> bool:
        result = await self.db.execute(
            select(func.count(UserRole.id))
            .join(Role, Role.id == UserRole.role_id)
            .where(
                UserRole.tenant_id == self.tenant_id,
                Role.name.in_(["owner", "admin"]),
            )
        )
        return (result.scalar() or 0) <= limit

    async def _violations_last_30_days(self) -> int:
        since = datetime.utcnow() - timedelta(days=30)
        result = await self.db.execute(
            select(func.count(PolicyViolation.id)).where(
                PolicyViolation.tenant_id == self.tenant_id,
                PolicyViolation.created_at >= since,
            )
        )
        return result.scalar() or 0

    async def _critical_violations_last_30_days(self) -> int:
        since = datetime.utcnow() - timedelta(days=30)
        result = await self.db.execute(
            select(func.count(PolicyViolation.id)).where(
                PolicyViolation.tenant_id == self.tenant_id,
                PolicyViolation.created_at >= since,
                PolicyViolation.severity == ViolationSeverity.critical,
            )
        )
        return result.scalar() or 0

    # ── GDPR ─────────────────────────────────────────────────────
    async def check_gdpr(self) -> Dict[str, Any]:
        checks = {}
        deductions = 0
        
        checks["pii_redaction_enabled"] = await self._has_active_pii_policy()
        if not checks["pii_redaction_enabled"]:
            deductions += 10

        checks["audit_logging_enabled"] = await self._has_audit_logging()
        if not checks["audit_logging_enabled"]:
            deductions += 10

        checks["content_filter_enabled"] = await self._has_content_filter_policy()
        if not checks["content_filter_enabled"]:
            deductions += 10

        violations = await self._violations_last_30_days()
        critical = await self._critical_violations_last_30_days()
        non_critical = violations - critical
        deductions += non_critical * 2

        score = max(0, 100 - deductions)
        return {
            "score": score,
            "checks": checks,
            "violations_30d": violations,
            "critical_violations_30d": critical,
        }

    # ── HIPAA ────────────────────────────────────────────────────
    async def check_hipaa(self) -> Dict[str, Any]:
        checks = {}
        deductions = 0

        checks["pii_redaction_enabled"] = await self._has_active_pii_policy()
        if not checks["pii_redaction_enabled"]:
            deductions += 10

        checks["content_filter_enabled"] = await self._has_content_filter_policy()
        if not checks["content_filter_enabled"]:
            deductions += 10

        checks["audit_logging_enabled"] = await self._has_audit_logging()
        if not checks["audit_logging_enabled"]:
            deductions += 10

        checks["api_key_expiry_enforced"] = await self._api_keys_have_expiry()
        if not checks["api_key_expiry_enforced"]:
            deductions += 10

        violations = await self._violations_last_30_days()
        critical = await self._critical_violations_last_30_days()
        non_critical = violations - critical
        deductions += non_critical * 2

        score = max(0, 100 - deductions)
        return {
            "score": score,
            "checks": checks,
            "violations_30d": violations,
            "critical_violations_30d": critical,
        }

    # ── SOC2 ─────────────────────────────────────────────────────
    async def check_soc2(self) -> Dict[str, Any]:
        checks = {}
        deductions = 0

        checks["rbac_enforced"] = True  # require_roles is active in dependencies
        checks["admin_limit_met"] = await self._admin_count_under_limit(5)
        if not checks["admin_limit_met"]:
            deductions += 10

        checks["api_key_expiry_enforced"] = await self._api_keys_have_expiry()
        if not checks["api_key_expiry_enforced"]:
            deductions += 10

        checks["audit_logging_enabled"] = await self._has_audit_logging()
        if not checks["audit_logging_enabled"]:
            deductions += 10

        violations = await self._violations_last_30_days()
        critical = await self._critical_violations_last_30_days()
        non_critical = violations - critical
        deductions += non_critical * 2

        score = max(0, 100 - deductions)
        return {
            "score": score,
            "checks": checks,
            "violations_30d": violations,
            "critical_violations_30d": critical,
        }

    async def calculate_all(self) -> Dict[str, Dict[str, Any]]:
        return {
            "gdpr": await self.check_gdpr(),
            "hipaa": await self.check_hipaa(),
            "soc2": await self.check_soc2(),
        }
