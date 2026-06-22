from __future__ import annotations

import hashlib
import inspect
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.compliance import ComplianceGap
from app.models.finding import SecurityFinding
from app.models.integration import CloudIntegration
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationArtifactStatus,
    RemediationArtifactType,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
    RemediationRollbackPlan,
)
from app.schemas.events import (
    RemediationApprovalExpiredEvent,
    RemediationApprovalRequestedEvent,
    RemediationApprovedEvent,
    RemediationArtifactCreatedEvent,
    RemediationExecutionBlockedEvent,
    RemediationPlanCreatedEvent,
    RemediationPlanStatusChangedEvent,
    RemediationRejectedEvent,
)
from app.services.api_safety import collect_secret_values, sanitize_text

logger = logging.getLogger(__name__)

REMEDIATION_EVENTS_TOPIC = "authclaw.remediation.events"
APPROVAL_TTL_MINUTES = 30
PHASE1_EXECUTION_DISABLED_REASON = "Sprint 4 Phase 1 models state only; execution is disabled."


class RemediationStateError(BadRequestException):
    pass


class RemediationExecutionDisabled(RemediationStateError):
    pass


EXECUTION_DISABLED_PLAN_STATUSES = {
    RemediationPlanStatus.queued_for_execution,
    RemediationPlanStatus.executing,
    RemediationPlanStatus.succeeded,
    RemediationPlanStatus.failed,
    RemediationPlanStatus.rollback_required,
    RemediationPlanStatus.rolled_back,
    RemediationPlanStatus.verified,
}

ALLOWED_TRANSITIONS: dict[RemediationPlanStatus, set[RemediationPlanStatus]] = {
    RemediationPlanStatus.detected: {RemediationPlanStatus.recommendation_created, RemediationPlanStatus.plan_drafted},
    RemediationPlanStatus.recommendation_created: {RemediationPlanStatus.plan_drafted},
    RemediationPlanStatus.plan_drafted: {RemediationPlanStatus.plan_validated, RemediationPlanStatus.rejected},
    RemediationPlanStatus.plan_validated: {RemediationPlanStatus.approval_requested, RemediationPlanStatus.rejected},
    RemediationPlanStatus.approval_requested: {
        RemediationPlanStatus.approved,
        RemediationPlanStatus.rejected,
        RemediationPlanStatus.expired,
    },
    RemediationPlanStatus.approved: {RemediationPlanStatus.queued_for_execution, RemediationPlanStatus.rejected},
    RemediationPlanStatus.queued_for_execution: {RemediationPlanStatus.executing, RemediationPlanStatus.expired},
    RemediationPlanStatus.executing: {RemediationPlanStatus.succeeded, RemediationPlanStatus.failed},
    RemediationPlanStatus.failed: {RemediationPlanStatus.rollback_required},
    RemediationPlanStatus.rollback_required: {RemediationPlanStatus.rolled_back},
    RemediationPlanStatus.rolled_back: {RemediationPlanStatus.verified},
    RemediationPlanStatus.succeeded: {RemediationPlanStatus.verified},
    RemediationPlanStatus.rejected: set(),
    RemediationPlanStatus.expired: set(),
    RemediationPlanStatus.verified: set(),
}


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _enum(value, enum_type):
    if isinstance(value, enum_type):
        return value
    return enum_type(str(value))


def _safe_json(value: Any) -> Any:
    secrets_found = collect_secret_values(value)
    if isinstance(value, dict):
        return {sanitize_text(key, secrets_found): _safe_json(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value, secrets_found)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return sanitize_text(value, secrets_found)


def artifact_hash(artifact_type: RemediationArtifactType | str, content_redacted: str) -> str:
    normalized = "\n".join(str(content_redacted).splitlines()).strip()
    payload = {
        "artifact_type": _enum(artifact_type, RemediationArtifactType).value,
        "content_redacted": normalized,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def policy_check_hash(plan_id: uuid.UUID | str, artifact_hash_value: str, passed: bool, blocking_reasons: list[Any]) -> str:
    payload = {
        "plan_id": str(plan_id),
        "artifact_hash": artifact_hash_value,
        "passed": bool(passed),
        "blocking_reasons": _safe_json(blocking_reasons),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class RemediationStateMachine:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer

    def can_transition(
        self,
        current_status: RemediationPlanStatus | str,
        next_status: RemediationPlanStatus | str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        current = _enum(current_status, RemediationPlanStatus)
        next_ = _enum(next_status, RemediationPlanStatus)
        if next_ in EXECUTION_DISABLED_PLAN_STATUSES and not (context or {}).get("execution_enabled", False):
            return False
        return next_ in ALLOWED_TRANSITIONS.get(current, set())

    async def transition_plan(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        next_status: RemediationPlanStatus | str,
        actor_id: uuid.UUID | str | None = None,
        reason: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> RemediationPlan:
        tenant_uuid = self._uuid(tenant_id)
        plan_uuid = self._uuid(plan_id)
        next_ = _enum(next_status, RemediationPlanStatus)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, plan_uuid)

        if next_ in EXECUTION_DISABLED_PLAN_STATUSES and not (context or {}).get("execution_enabled", False):
            await self._emit(
                RemediationExecutionBlockedEvent(
                    tenant_id=tenant_uuid,
                    actor_id=self._uuid(actor_id) if actor_id else None,
                    plan_id=plan.id,
                    attempted_status=next_.value,
                    disabled_reason=PHASE1_EXECUTION_DISABLED_REASON,
                    reason=sanitize_text(reason or PHASE1_EXECUTION_DISABLED_REASON),
                )
            )
            raise RemediationExecutionDisabled(detail=PHASE1_EXECUTION_DISABLED_REASON)

        if not self.can_transition(plan.status, next_, context):
            raise RemediationStateError(detail=f"Invalid remediation transition {plan.status.value}->{next_.value}")

        await self.validate_transition_requirements(plan, next_, context or {})

        previous = plan.status
        plan.status = next_
        await self.db.flush()
        await self._emit_status_event(plan, previous, actor_id, reason)
        return plan

    async def expire_approvals(self, tenant_id: uuid.UUID | str) -> list[RemediationApproval]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        now = utcnow()
        result = await self.db.execute(
            select(RemediationApproval, RemediationPlan)
            .join(RemediationPlan, RemediationApproval.plan_id == RemediationPlan.id)
            .where(
                RemediationApproval.tenant_id == tenant_uuid,
                RemediationApproval.status == RemediationApprovalStatus.pending,
                RemediationApproval.expires_at < now,
            )
        )
        expired: list[RemediationApproval] = []
        for approval, plan in result.all():
            approval.status = RemediationApprovalStatus.expired
            approval.resolved_at = now
            if plan.status == RemediationPlanStatus.approval_requested:
                plan.status = RemediationPlanStatus.expired
            expired.append(approval)
            await self._emit(
                RemediationApprovalExpiredEvent(
                    tenant_id=tenant_uuid,
                    plan_id=plan.id,
                    approval_id=approval.id,
                    status=approval.status.value,
                    risk_level=plan.risk_level.value,
                    reason="Approval expired before action.",
                )
            )
        await self.db.flush()
        return expired

    async def validate_transition_requirements(
        self,
        plan: RemediationPlan,
        next_status: RemediationPlanStatus | str,
        context: dict[str, Any] | None = None,
    ) -> None:
        next_ = _enum(next_status, RemediationPlanStatus)
        context = context or {}
        if next_ == RemediationPlanStatus.approval_requested:
            artifact_hash_value = str(context.get("artifact_hash") or "")
            policy_hash_value = str(context.get("policy_check_hash") or "")
            if not artifact_hash_value or not policy_hash_value:
                raise RemediationStateError(detail="approval_requested requires artifact_hash and policy_check_hash")
            artifact = await self._artifact_by_hash(plan, artifact_hash_value)
            if artifact is None:
                raise RemediationStateError(detail="approval_requested artifact_hash does not match this plan")
            check = await self._policy_check_by_hash(plan, policy_hash_value)
            if check is None or not check.passed:
                raise RemediationStateError(detail="approval_requested requires a passing policy check")
            if check.artifact_id is not None and check.artifact_id != artifact.id:
                raise RemediationStateError(detail="policy check does not match artifact")
            rollback_exists = await self.db.scalar(
                select(RemediationRollbackPlan.id).where(
                    RemediationRollbackPlan.tenant_id == plan.tenant_id,
                    RemediationRollbackPlan.plan_id == plan.id,
                )
            )
            if rollback_exists is None:
                raise RemediationStateError(detail="approval_requested requires a rollback plan")

        if next_ == RemediationPlanStatus.approved:
            approval_id = context.get("approval_id")
            nonce = context.get("nonce")
            if not approval_id or not nonce:
                raise RemediationStateError(detail="approved requires approval_id and nonce")
            approval = await self._approval(plan, self._uuid(approval_id))
            if approval.status != RemediationApprovalStatus.approved:
                raise RemediationStateError(detail="approval is not approved")
            if approval.expires_at < utcnow():
                raise RemediationStateError(detail="approval has expired")
            if approval.nonce != str(nonce):
                raise RemediationStateError(detail="approval nonce mismatch")
            if not await self._artifact_by_hash(plan, approval.artifact_hash):
                raise RemediationStateError(detail="approval artifact_hash does not match current plan artifacts")
            check = await self._policy_check_by_hash(plan, approval.policy_check_hash)
            if check is None or not check.passed:
                raise RemediationStateError(detail="approval policy_check_hash does not match a passing check")

    async def _emit_status_event(
        self,
        plan: RemediationPlan,
        previous: RemediationPlanStatus,
        actor_id: uuid.UUID | str | None,
        reason: str | None,
    ) -> None:
        event_cls = {
            RemediationPlanStatus.approval_requested: RemediationApprovalRequestedEvent,
            RemediationPlanStatus.approved: RemediationApprovedEvent,
            RemediationPlanStatus.rejected: RemediationRejectedEvent,
        }.get(plan.status)
        if event_cls is RemediationApprovalRequestedEvent:
            artifact = await self._latest_artifact(plan)
            check = await self._latest_policy_check(plan)
            await self._emit(
                event_cls(
                    tenant_id=plan.tenant_id,
                    actor_id=self._uuid(actor_id) if actor_id else None,
                    plan_id=plan.id,
                    artifact_hash=artifact.artifact_hash if artifact else "",
                    policy_check_hash=check.policy_check_hash if check else "",
                    status=plan.status.value,
                    risk_level=plan.risk_level.value,
                    reason=sanitize_text(reason or ""),
                )
            )
            return
        if event_cls is RemediationApprovedEvent:
            approval = await self._latest_approval(plan, RemediationApprovalStatus.approved)
            await self._emit(
                event_cls(
                    tenant_id=plan.tenant_id,
                    actor_id=self._uuid(actor_id) if actor_id else None,
                    plan_id=plan.id,
                    approval_id=approval.id if approval else uuid.uuid4(),
                    artifact_hash=approval.artifact_hash if approval else "",
                    policy_check_hash=approval.policy_check_hash if approval else "",
                    status=plan.status.value,
                    risk_level=plan.risk_level.value,
                    reason=sanitize_text(reason or ""),
                )
            )
            return
        if event_cls is RemediationRejectedEvent:
            await self._emit(
                event_cls(
                    tenant_id=plan.tenant_id,
                    actor_id=self._uuid(actor_id) if actor_id else None,
                    plan_id=plan.id,
                    status=plan.status.value,
                    risk_level=plan.risk_level.value,
                    reason=sanitize_text(reason or ""),
                )
            )
            return
        await self._emit(
            RemediationPlanStatusChangedEvent(
                tenant_id=plan.tenant_id,
                actor_id=self._uuid(actor_id) if actor_id else None,
                plan_id=plan.id,
                previous_status=previous.value,
                status=plan.status.value,
                risk_level=plan.risk_level.value,
                reason=sanitize_text(reason or ""),
            )
        )

    async def _plan(self, tenant_id: uuid.UUID, plan_id: uuid.UUID) -> RemediationPlan:
        result = await self.db.execute(
            select(RemediationPlan)
            .where(RemediationPlan.tenant_id == tenant_id, RemediationPlan.id == plan_id)
        )
        plan = result.scalars().first()
        if plan is None:
            raise NotFoundException(detail="Remediation plan not found")
        return plan

    async def _artifact_by_hash(self, plan: RemediationPlan, hash_value: str) -> RemediationArtifact | None:
        return (
            await self.db.execute(
                select(RemediationArtifact).where(
                    RemediationArtifact.tenant_id == plan.tenant_id,
                    RemediationArtifact.plan_id == plan.id,
                    RemediationArtifact.artifact_hash == hash_value,
                    RemediationArtifact.status.in_([
                        RemediationArtifactStatus.draft,
                        RemediationArtifactStatus.active,
                    ]),
                )
            )
        ).scalars().first()

    async def _latest_artifact(self, plan: RemediationPlan) -> RemediationArtifact | None:
        return (
            await self.db.execute(
                select(RemediationArtifact)
                .where(RemediationArtifact.tenant_id == plan.tenant_id, RemediationArtifact.plan_id == plan.id)
                .order_by(desc(RemediationArtifact.created_at))
                .limit(1)
            )
        ).scalars().first()

    async def _policy_check_by_hash(self, plan: RemediationPlan, hash_value: str) -> RemediationPolicyCheck | None:
        return (
            await self.db.execute(
                select(RemediationPolicyCheck).where(
                    RemediationPolicyCheck.tenant_id == plan.tenant_id,
                    RemediationPolicyCheck.plan_id == plan.id,
                    RemediationPolicyCheck.policy_check_hash == hash_value,
                )
            )
        ).scalars().first()

    async def _latest_policy_check(self, plan: RemediationPlan) -> RemediationPolicyCheck | None:
        return (
            await self.db.execute(
                select(RemediationPolicyCheck)
                .where(RemediationPolicyCheck.tenant_id == plan.tenant_id, RemediationPolicyCheck.plan_id == plan.id)
                .order_by(desc(RemediationPolicyCheck.created_at))
                .limit(1)
            )
        ).scalars().first()

    async def _approval(self, plan: RemediationPlan, approval_id: uuid.UUID) -> RemediationApproval:
        approval = (
            await self.db.execute(
                select(RemediationApproval).where(
                    RemediationApproval.tenant_id == plan.tenant_id,
                    RemediationApproval.plan_id == plan.id,
                    RemediationApproval.id == approval_id,
                )
            )
        ).scalars().first()
        if approval is None:
            raise RemediationStateError(detail="Approval does not belong to this plan")
        return approval

    async def _latest_approval(
        self,
        plan: RemediationPlan,
        status: RemediationApprovalStatus,
    ) -> RemediationApproval | None:
        return (
            await self.db.execute(
                select(RemediationApproval)
                .where(
                    RemediationApproval.tenant_id == plan.tenant_id,
                    RemediationApproval.plan_id == plan.id,
                    RemediationApproval.status == status,
                )
                .order_by(desc(RemediationApproval.updated_at))
                .limit(1)
            )
        ).scalars().first()

    async def _emit(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish remediation event %s: %s", event.event_type, exc)

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class RemediationPlanService:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer

    async def create_draft_plan_shell(
        self,
        *,
        tenant_id: uuid.UUID | str,
        finding_id: uuid.UUID | str | None = None,
        gap_id: uuid.UUID | str | None = None,
        actor_id: uuid.UUID | str | None = None,
        summary: str | None = None,
        expected_impact: str | None = None,
        risk_level: RemediationRiskLevel | str = RemediationRiskLevel.medium,
    ) -> RemediationPlan:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        finding, integration = await self._source_finding(tenant_uuid, finding_id)
        gap = await self._source_gap(tenant_uuid, gap_id)

        source_summary = summary or self._default_summary(finding, gap)
        plan = RemediationPlan(
            tenant_id=tenant_uuid,
            finding_id=finding.id if finding is not None else None,
            gap_id=gap.id if gap is not None else None,
            integration_id=integration.id if integration is not None else None,
            provider=integration.provider_type.value if integration is not None else None,
            resource_ref=sanitize_text(finding.resource_id) if finding is not None else None,
            risk_level=_enum(risk_level, RemediationRiskLevel),
            status=RemediationPlanStatus.plan_drafted,
            summary=sanitize_text(source_summary),
            expected_impact=sanitize_text(expected_impact or "Draft remediation plan shell only. No execution is available in Phase 1."),
            created_by=self._uuid(actor_id) if actor_id else None,
        )
        self.db.add(plan)
        await self.db.flush()
        await self._emit(
            RemediationPlanCreatedEvent(
                tenant_id=plan.tenant_id,
                actor_id=plan.created_by,
                plan_id=plan.id,
                status=plan.status.value,
                risk_level=plan.risk_level.value,
            )
        )
        return plan

    async def attach_artifact_placeholder(
        self,
        *,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        artifact_type: RemediationArtifactType | str = RemediationArtifactType.documentation_only,
        content: str = "Phase 1 placeholder artifact. No executable remediation content.",
        diff_summary: str | None = None,
        risk_flags: dict[str, Any] | None = None,
    ) -> RemediationArtifact:
        tenant_uuid = self._uuid(tenant_id)
        plan_uuid = self._uuid(plan_id)
        await self._set_tenant_context(tenant_uuid)
        await self._plan(tenant_uuid, plan_uuid)
        sanitized_content = sanitize_text(content)
        artifact_type_enum = _enum(artifact_type, RemediationArtifactType)
        artifact = RemediationArtifact(
            tenant_id=tenant_uuid,
            plan_id=plan_uuid,
            artifact_type=artifact_type_enum,
            content_redacted=sanitized_content,
            diff_summary=sanitize_text(diff_summary or "") or None,
            artifact_hash=artifact_hash(artifact_type_enum, sanitized_content),
            risk_flags=_safe_json(risk_flags or {"phase": "phase_1_placeholder", "execution": "disabled"}),
            status=RemediationArtifactStatus.draft,
        )
        self.db.add(artifact)
        await self.db.flush()
        await self._emit(
            RemediationArtifactCreatedEvent(
                tenant_id=tenant_uuid,
                plan_id=plan_uuid,
                artifact_id=artifact.id,
                artifact_type=artifact.artifact_type.value,
                artifact_hash=artifact.artifact_hash,
                status=artifact.status.value,
            )
        )
        return artifact

    async def attach_rollback_placeholder(
        self,
        *,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        rollback_steps: str = "Rollback must be defined before any future execution phase. Phase 1 does not execute.",
        risk_level: RemediationRiskLevel | str = RemediationRiskLevel.medium,
    ) -> RemediationRollbackPlan:
        tenant_uuid = self._uuid(tenant_id)
        plan_uuid = self._uuid(plan_id)
        await self._set_tenant_context(tenant_uuid)
        await self._plan(tenant_uuid, plan_uuid)
        sanitized_steps = sanitize_text(rollback_steps)
        rollback = RemediationRollbackPlan(
            tenant_id=tenant_uuid,
            plan_id=plan_uuid,
            rollback_steps=sanitized_steps,
            rollback_artifact_hash=hashlib.sha256(sanitized_steps.encode("utf-8")).hexdigest(),
            risk_level=_enum(risk_level, RemediationRiskLevel),
        )
        self.db.add(rollback)
        await self.db.flush()
        return rollback

    async def request_approval_foundation(
        self,
        *,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        artifact_hash_value: str,
        policy_check_hash_value: str,
        requested_by: uuid.UUID | str | None = None,
        approval_reason: str | None = None,
        expires_in_minutes: int = APPROVAL_TTL_MINUTES,
    ) -> RemediationApproval:
        tenant_uuid = self._uuid(tenant_id)
        plan_uuid = self._uuid(plan_id)
        await self._set_tenant_context(tenant_uuid)
        await self._plan(tenant_uuid, plan_uuid)
        approval = RemediationApproval(
            tenant_id=tenant_uuid,
            plan_id=plan_uuid,
            artifact_hash=artifact_hash_value,
            policy_check_hash=policy_check_hash_value,
            requested_by=self._uuid(requested_by) if requested_by else None,
            status=RemediationApprovalStatus.pending,
            expires_at=utcnow() + timedelta(minutes=expires_in_minutes),
            nonce=secrets.token_urlsafe(32),
            approval_reason=sanitize_text(approval_reason or "") or None,
        )
        self.db.add(approval)
        await self.db.flush()
        return approval

    async def _source_finding(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID | str | None,
    ) -> tuple[SecurityFinding | None, CloudIntegration | None]:
        if finding_id is None:
            return None, None
        result = await self.db.execute(
            select(SecurityFinding, CloudIntegration)
            .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
            .where(SecurityFinding.id == self._uuid(finding_id), CloudIntegration.tenant_id == tenant_id)
        )
        row = result.first()
        if row is None:
            raise NotFoundException(detail="Security finding not found for tenant")
        return row[0], row[1]

    async def _source_gap(self, tenant_id: uuid.UUID, gap_id: uuid.UUID | str | None) -> ComplianceGap | None:
        if gap_id is None:
            return None
        gap = (
            await self.db.execute(
                select(ComplianceGap).where(ComplianceGap.id == self._uuid(gap_id), ComplianceGap.tenant_id == tenant_id)
            )
        ).scalars().first()
        if gap is None:
            raise NotFoundException(detail="Compliance gap not found for tenant")
        return gap

    async def _plan(self, tenant_id: uuid.UUID, plan_id: uuid.UUID) -> RemediationPlan:
        plan = (
            await self.db.execute(
                select(RemediationPlan).where(RemediationPlan.id == plan_id, RemediationPlan.tenant_id == tenant_id)
            )
        ).scalars().first()
        if plan is None:
            raise NotFoundException(detail="Remediation plan not found")
        return plan

    def _default_summary(self, finding: SecurityFinding | None, gap: ComplianceGap | None) -> str:
        if finding is not None:
            return f"Draft remediation shell for finding: {finding.title}"
        if gap is not None:
            return f"Draft remediation shell for compliance gap: {gap.gap_type.value}"
        return "Draft remediation shell without source binding."

    async def _emit(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish remediation event %s: %s", event.event_type, exc)

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))
