from __future__ import annotations

import inspect
import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalLevel,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
)
from app.models.role import Role, UserRole
from app.schemas.events import (
    RemediationApprovalExpiredEvent,
    RemediationMfaChallengeEvent,
    RemediationApprovalReplayBlockedEvent,
    RemediationApprovalRequestedEvent,
    RemediationApprovalRevokedEvent,
    RemediationApprovedEvent,
    RemediationRejectedEvent,
)
from app.services.api_safety import sanitize_text
from app.services.remediation_state_machine import (
    APPROVAL_TTL_MINUTES,
    REMEDIATION_EVENTS_TOPIC,
    RemediationExecutionDisabled,
    RemediationStateMachine,
    utcnow,
)

logger = logging.getLogger(__name__)

APPROVAL_ROLE_MATRIX: dict[RemediationApprovalLevel, set[str]] = {
    RemediationApprovalLevel.operator: {"operator", "analyst", "admin", "owner", "security_admin"},
    RemediationApprovalLevel.admin: {"analyst", "admin", "owner", "security_admin"},
    RemediationApprovalLevel.owner: {"admin", "owner", "security_admin"},
    RemediationApprovalLevel.security_admin: {"admin", "owner", "security_admin"},
}

MFA_REQUIRED_LEVELS = {
    RemediationApprovalLevel.owner,
    RemediationApprovalLevel.security_admin,
}

MFA_REQUIRED_RISK_LEVELS = {
    RemediationRiskLevel.high,
    RemediationRiskLevel.critical,
}


@dataclass(frozen=True)
class ApprovalVerificationResult:
    approval: RemediationApproval
    plan: RemediationPlan
    artifact_hash: str
    policy_check_hash: str
    action_envelope_hash: str | None = None


@dataclass(frozen=True)
class ActionMfaEnvelope:
    tenant_id: str
    approver_user_id: str
    remediation_plan_id: str
    artifact_id: str
    artifact_hash: str
    policy_check_id: str
    policy_check_hash: str
    execution_action: str
    risk_level: str
    provider_scope: str | None
    resource_scope: str | None
    expires_at: str
    nonce: str

    def digest(self) -> str:
        payload = json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RemediationApprovalService:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer
        self.state_machine = RemediationStateMachine(db, event_producer=event_producer)

    async def request_approval(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        requested_by: uuid.UUID | str | None = None,
        reason: str | None = None,
        expires_in_minutes: int = APPROVAL_TTL_MINUTES,
    ) -> RemediationApproval:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, self._uuid(plan_id))
        if plan.status != RemediationPlanStatus.plan_validated:
            raise BadRequestException(detail="Only plan_validated remediation plans can request approval")

        check = await self._latest_policy_check(plan)
        if check is None:
            raise BadRequestException(detail="Approval requires a policy check")
        if not check.passed:
            raise BadRequestException(detail="Approval requires the latest policy check to pass")
        if check.artifact_id is None:
            raise BadRequestException(detail="Approval requires policy check artifact binding")
        artifact = await self._artifact(plan, check.artifact_id)

        approval = RemediationApproval(
            tenant_id=tenant_uuid,
            plan_id=plan.id,
            artifact_hash=artifact.artifact_hash,
            policy_check_hash=check.policy_check_hash,
            requested_by=self._uuid(requested_by) if requested_by else None,
            status=RemediationApprovalStatus.pending,
            expires_at=utcnow() + timedelta(minutes=max(1, int(expires_in_minutes))),
            nonce=secrets.token_urlsafe(32),
            approval_reason=sanitize_text(reason or "") or None,
            mfa_verified=False,
        )
        self.db.add(approval)
        await self.db.flush()

        await self.state_machine.transition_plan(
            tenant_uuid,
            plan.id,
            RemediationPlanStatus.approval_requested,
            actor_id=requested_by,
            reason=sanitize_text(reason or "Approval requested."),
            context={"artifact_hash": artifact.artifact_hash, "policy_check_hash": check.policy_check_hash},
        )
        await self._emit_approval_event(
            RemediationApprovalRequestedEvent,
            plan,
            approval,
            check,
            actor_id=requested_by,
            reason=reason,
        )
        return approval

    async def approve(
        self,
        tenant_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        approved_by: uuid.UUID | str,
        approval_reason: str,
        mfa_verified: bool = False,
    ) -> RemediationApproval:
        if not sanitize_text(approval_reason):
            raise BadRequestException(detail="approval_reason is required")
        tenant_uuid = self._uuid(tenant_id)
        actor_uuid = self._uuid(approved_by)
        await self._set_tenant_context(tenant_uuid)
        approval = await self._approval(tenant_uuid, self._uuid(approval_id))
        plan = await self._plan(tenant_uuid, approval.plan_id)
        check = await self._policy_check_by_hash(plan, approval.policy_check_hash)

        self._ensure_pending(approval)
        if approval.expires_at < utcnow():
            await self._expire_single(plan, approval, actor_uuid, "approval_expired_before_approval")
            raise BadRequestException(detail="Approval has expired")
        if check is None or not check.passed:
            raise BadRequestException(detail="Approval requires a passing policy check")
        artifact = await self._artifact_by_hash(plan, approval.artifact_hash)
        if artifact is None or check.artifact_id != artifact.id:
            raise BadRequestException(detail="Approval artifact binding is no longer valid")

        envelope = self._mfa_envelope(
            plan,
            artifact,
            check,
            approval,
            actor_uuid,
            execution_action="controlled_remediation_execution",
        )
        mfa_required = self._mfa_required(plan, check)
        if mfa_required:
            await self._emit_mfa_event(
                plan,
                approval,
                check,
                actor_id=actor_uuid,
                action="challenge_requested",
                envelope_hash=envelope.digest(),
                reason_category=None,
            )
            if not mfa_verified:
                await self._emit_mfa_event(
                    plan,
                    approval,
                    check,
                    actor_id=actor_uuid,
                    action="verification_failed",
                    envelope_hash=envelope.digest(),
                    reason_category="mfa_required",
                )

        await self._authorize_actor(
            tenant_uuid,
            actor_uuid,
            check.required_approval_level,
            mfa_verified=mfa_verified,
            requested_by=approval.requested_by,
        )

        approval.status = RemediationApprovalStatus.approved
        approval.approved_by = actor_uuid
        approval.resolved_at = utcnow()
        approval.mfa_verified = bool(mfa_verified)
        approval.approval_reason = sanitize_text(approval_reason)
        await self.db.flush()
        await self.state_machine.transition_plan(
            tenant_uuid,
            plan.id,
            RemediationPlanStatus.approved,
            actor_id=actor_uuid,
            reason=sanitize_text(approval_reason),
            context={"approval_id": approval.id, "nonce": approval.nonce},
        )
        await self._emit_approval_event(
            RemediationApprovedEvent,
            plan,
            approval,
            check,
            actor_id=actor_uuid,
            reason=approval_reason,
        )
        if mfa_required:
            await self._emit_mfa_event(
                plan,
                approval,
                check,
                actor_id=actor_uuid,
                action="verified",
                envelope_hash=envelope.digest(),
                reason_category=None,
            )
        return approval

    async def reject(
        self,
        tenant_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        rejected_by: uuid.UUID | str,
        rejection_reason: str,
    ) -> RemediationApproval:
        if not sanitize_text(rejection_reason):
            raise BadRequestException(detail="rejection_reason is required")
        tenant_uuid = self._uuid(tenant_id)
        actor_uuid = self._uuid(rejected_by)
        await self._set_tenant_context(tenant_uuid)
        approval = await self._approval(tenant_uuid, self._uuid(approval_id))
        plan = await self._plan(tenant_uuid, approval.plan_id)
        check = await self._policy_check_by_hash(plan, approval.policy_check_hash)
        self._ensure_pending(approval)
        await self._authorize_reviewer(tenant_uuid, actor_uuid)

        approval.status = RemediationApprovalStatus.rejected
        approval.approved_by = actor_uuid
        approval.resolved_at = utcnow()
        approval.approval_reason = sanitize_text(rejection_reason)
        await self.db.flush()
        await self.state_machine.transition_plan(
            tenant_uuid,
            plan.id,
            RemediationPlanStatus.rejected,
            actor_id=actor_uuid,
            reason=sanitize_text(rejection_reason),
        )
        await self._emit_approval_event(
            RemediationRejectedEvent,
            plan,
            approval,
            check,
            actor_id=actor_uuid,
            reason=rejection_reason,
        )
        return approval

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
            await self._expire_single(plan, approval, None, "approval_ttl_expired")
            expired.append(approval)
        await self.db.flush()
        return expired

    async def revoke_approval(
        self,
        tenant_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        revoked_by: uuid.UUID | str,
        reason: str,
    ) -> RemediationApproval:
        if not sanitize_text(reason):
            raise BadRequestException(detail="reason is required")
        tenant_uuid = self._uuid(tenant_id)
        actor_uuid = self._uuid(revoked_by)
        await self._set_tenant_context(tenant_uuid)
        approval = await self._approval(tenant_uuid, self._uuid(approval_id))
        plan = await self._plan(tenant_uuid, approval.plan_id)
        check = await self._policy_check_by_hash(plan, approval.policy_check_hash)
        if approval.status not in {RemediationApprovalStatus.pending, RemediationApprovalStatus.approved}:
            raise BadRequestException(detail=f"Approval cannot be revoked from status {approval.status.value}")
        await self._authorize_reviewer(tenant_uuid, actor_uuid, privileged_only=True)

        approval.status = RemediationApprovalStatus.revoked
        approval.approved_by = actor_uuid
        approval.resolved_at = utcnow()
        approval.approval_reason = sanitize_text(reason)
        await self.db.flush()
        if plan.status == RemediationPlanStatus.approval_requested:
            await self.state_machine.transition_plan(
                tenant_uuid,
                plan.id,
                RemediationPlanStatus.rejected,
                actor_id=actor_uuid,
                reason=sanitize_text(reason),
            )
        await self._emit_approval_event(
            RemediationApprovalRevokedEvent,
            plan,
            approval,
            check,
            actor_id=actor_uuid,
            reason=reason,
        )
        return approval

    async def get_pending_approvals(
        self,
        tenant_id: uuid.UUID | str,
        filters: dict[str, Any] | None = None,
    ) -> list[RemediationApproval]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        query = select(RemediationApproval).where(
            RemediationApproval.tenant_id == tenant_uuid,
            RemediationApproval.status == RemediationApprovalStatus.pending,
        )
        filters = filters or {}
        if filters.get("plan_id"):
            query = query.where(RemediationApproval.plan_id == self._uuid(filters["plan_id"]))
        if filters.get("requested_by"):
            query = query.where(RemediationApproval.requested_by == self._uuid(filters["requested_by"]))
        query = query.order_by(desc(RemediationApproval.created_at))
        return list((await self.db.execute(query)).scalars().all())

    async def verify_approval_for_future_execution(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        *,
        actor_id: uuid.UUID | str | None = None,
        execution_action: str = "future_execution",
    ) -> ApprovalVerificationResult:
        return await self._verify_approval_binding(
            tenant_id,
            plan_id,
            approval_id,
            consume=True,
            require_plan_approved=True,
            actor_id=actor_id,
            execution_action=execution_action,
        )

    async def verify_approval_for_controlled_execution_start(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        *,
        actor_id: uuid.UUID | str | None = None,
        execution_action: str = "controlled_execution_start",
    ) -> ApprovalVerificationResult:
        return await self._verify_approval_binding(
            tenant_id,
            plan_id,
            approval_id,
            consume=True,
            require_plan_approved=False,
            actor_id=actor_id,
            execution_action=execution_action,
        )

    async def verify_approval_for_dry_run(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        *,
        actor_id: uuid.UUID | str | None = None,
        execution_action: str = "dry_run",
    ) -> ApprovalVerificationResult:
        return await self._verify_approval_binding(
            tenant_id,
            plan_id,
            approval_id,
            consume=False,
            require_plan_approved=True,
            actor_id=actor_id,
            execution_action=execution_action,
        )

    async def _verify_approval_binding(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        *,
        consume: bool,
        require_plan_approved: bool,
        actor_id: uuid.UUID | str | None,
        execution_action: str,
    ) -> ApprovalVerificationResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, self._uuid(plan_id))
        approval = await self._approval(tenant_uuid, self._uuid(approval_id))
        try:
            if approval.plan_id != plan.id:
                raise BadRequestException(detail="Approval does not belong to this plan")
            if approval.status == RemediationApprovalStatus.used:
                raise BadRequestException(detail="Approval has already been used")
            if approval.status != RemediationApprovalStatus.approved:
                raise BadRequestException(detail="Approval is not approved")
            if approval.expires_at < utcnow():
                approval.status = RemediationApprovalStatus.expired
                approval.resolved_at = utcnow()
                await self.db.flush()
                await self._emit_mfa_event(
                    plan,
                    approval,
                    None,
                    actor_id=self._uuid(actor_id) if actor_id else approval.approved_by,
                    action="expired",
                    envelope_hash=hashlib.sha256(f"{approval.nonce}:expired".encode("utf-8")).hexdigest(),
                    reason_category="expired",
                )
                raise BadRequestException(detail="Approval has expired")
            if require_plan_approved and plan.status != RemediationPlanStatus.approved:
                raise BadRequestException(detail="Plan is not in approved status")
            artifact = await self._artifact_by_hash(plan, approval.artifact_hash)
            if artifact is None:
                raise BadRequestException(detail="Approval artifact hash does not match current plan artifacts")
            check = await self._policy_check_by_hash(plan, approval.policy_check_hash)
            if check is None or not check.passed:
                raise BadRequestException(detail="Approval policy check hash is invalid")
            latest_check = await self._latest_policy_check(plan)
            if latest_check is None or latest_check.policy_check_hash != approval.policy_check_hash:
                raise BadRequestException(detail="Approval policy check hash does not match latest policy check")
            if check.artifact_id != artifact.id:
                raise BadRequestException(detail="Approval policy check hash does not match current artifact")
            actor_uuid = self._uuid(actor_id) if actor_id else None
            envelope_hash: str | None = None
            if self._mfa_required(plan, check):
                if not approval.mfa_verified:
                    raise BadRequestException(detail="Fresh MFA verification is required for high-risk remediation execution")
                if actor_uuid is not None and approval.approved_by != actor_uuid:
                    raise BadRequestException(detail="MFA approval is bound to a different approver")
                if approval.approved_by is None:
                    raise BadRequestException(detail="MFA approval is missing approver binding")
                envelope = self._mfa_envelope(
                    plan,
                    artifact,
                    check,
                    approval,
                    approval.approved_by,
                    execution_action=execution_action,
                )
                envelope_hash = envelope.digest()
                await self._emit_mfa_event(
                    plan,
                    approval,
                    check,
                    actor_id=actor_uuid or approval.approved_by,
                    action="execution_verified",
                    envelope_hash=envelope_hash,
                    reason_category=None,
                )

            if consume:
                approval.status = RemediationApprovalStatus.used
                await self.db.flush()
            return ApprovalVerificationResult(
                approval=approval,
                plan=plan,
                artifact_hash=approval.artifact_hash,
                policy_check_hash=approval.policy_check_hash,
                action_envelope_hash=envelope_hash,
            )
        except BadRequestException:
            await self._emit_replay_blocked(plan, approval)
            raise

    async def _expire_single(
        self,
        plan: RemediationPlan,
        approval: RemediationApproval,
        actor_id: uuid.UUID | None,
        reason_category: str,
    ) -> None:
        approval.status = RemediationApprovalStatus.expired
        approval.resolved_at = utcnow()
        await self.db.flush()
        if plan.status == RemediationPlanStatus.approval_requested:
            await self.state_machine.transition_plan(
                plan.tenant_id,
                plan.id,
                RemediationPlanStatus.expired,
                actor_id=actor_id,
                reason=reason_category,
            )
        check = await self._policy_check_by_hash(plan, approval.policy_check_hash)
        await self._emit_approval_event(
            RemediationApprovalExpiredEvent,
            plan,
            approval,
            check,
            actor_id=actor_id,
            reason=reason_category,
        )

    async def _authorize_actor(
        self,
        tenant_id: uuid.UUID,
        actor_id: uuid.UUID,
        required_level: RemediationApprovalLevel,
        *,
        mfa_verified: bool,
        requested_by: uuid.UUID | None,
    ) -> None:
        roles = await self._actor_roles(tenant_id, actor_id)
        if roles & {"viewer", "auditor"} and not roles - {"viewer", "auditor"}:
            raise ForbiddenException(detail="Viewer/auditor roles cannot approve remediation")
        if not roles & APPROVAL_ROLE_MATRIX[required_level]:
            raise ForbiddenException(detail=f"Approval requires one of: {sorted(APPROVAL_ROLE_MATRIX[required_level])}")
        if required_level in MFA_REQUIRED_LEVELS and not mfa_verified:
            raise ForbiddenException(detail="MFA verification is required for elevated/critical remediation approval")
        if required_level in MFA_REQUIRED_LEVELS and requested_by and requested_by == actor_id:
            raise ForbiddenException(detail="Separation of duties prevents self-approval for elevated/critical remediation")

    async def _authorize_reviewer(
        self,
        tenant_id: uuid.UUID,
        actor_id: uuid.UUID,
        *,
        privileged_only: bool = False,
    ) -> None:
        roles = await self._actor_roles(tenant_id, actor_id)
        allowed = {"admin", "owner", "security_admin"} if privileged_only else {"operator", "analyst", "admin", "owner", "security_admin"}
        if not roles & allowed:
            raise ForbiddenException(detail=f"Action requires one of: {sorted(allowed)}")

    def _mfa_required(self, plan: RemediationPlan, check: RemediationPolicyCheck) -> bool:
        return plan.risk_level in MFA_REQUIRED_RISK_LEVELS or check.required_approval_level in MFA_REQUIRED_LEVELS

    def _mfa_envelope(
        self,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        check: RemediationPolicyCheck,
        approval: RemediationApproval,
        approver_user_id: uuid.UUID,
        *,
        execution_action: str,
    ) -> ActionMfaEnvelope:
        return ActionMfaEnvelope(
            tenant_id=str(plan.tenant_id),
            approver_user_id=str(approver_user_id),
            remediation_plan_id=str(plan.id),
            artifact_id=str(artifact.id),
            artifact_hash=artifact.artifact_hash,
            policy_check_id=str(check.id),
            policy_check_hash=check.policy_check_hash,
            execution_action=execution_action,
            risk_level=plan.risk_level.value,
            provider_scope=sanitize_text(plan.provider or "") or None,
            resource_scope=sanitize_text(plan.resource_ref or "") or None,
            expires_at=approval.expires_at.isoformat(),
            nonce=approval.nonce,
        )

    async def _actor_roles(self, tenant_id: uuid.UUID, actor_id: uuid.UUID) -> set[str]:
        result = await self.db.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.tenant_id == tenant_id, UserRole.user_id == actor_id)
        )
        return set(result.scalars().all())

    async def _plan(self, tenant_id: uuid.UUID, plan_id: uuid.UUID) -> RemediationPlan:
        plan = (
            await self.db.execute(
                select(RemediationPlan).where(RemediationPlan.tenant_id == tenant_id, RemediationPlan.id == plan_id)
            )
        ).scalars().first()
        if plan is None:
            raise NotFoundException(detail="Remediation plan not found")
        return plan

    async def _approval(self, tenant_id: uuid.UUID, approval_id: uuid.UUID) -> RemediationApproval:
        approval = (
            await self.db.execute(
                select(RemediationApproval).where(
                    RemediationApproval.tenant_id == tenant_id,
                    RemediationApproval.id == approval_id,
                )
            )
        ).scalars().first()
        if approval is None:
            raise NotFoundException(detail="Remediation approval not found")
        return approval

    async def _artifact(self, plan: RemediationPlan, artifact_id: uuid.UUID) -> RemediationArtifact:
        artifact = (
            await self.db.execute(
                select(RemediationArtifact).where(
                    RemediationArtifact.tenant_id == plan.tenant_id,
                    RemediationArtifact.plan_id == plan.id,
                    RemediationArtifact.id == artifact_id,
                )
            )
        ).scalars().first()
        if artifact is None:
            raise NotFoundException(detail="Remediation artifact not found")
        return artifact

    async def _artifact_by_hash(self, plan: RemediationPlan, artifact_hash: str) -> RemediationArtifact | None:
        return (
            await self.db.execute(
                select(RemediationArtifact).where(
                    RemediationArtifact.tenant_id == plan.tenant_id,
                    RemediationArtifact.plan_id == plan.id,
                    RemediationArtifact.artifact_hash == artifact_hash,
                )
            )
        ).scalars().first()

    async def _latest_policy_check(self, plan: RemediationPlan) -> RemediationPolicyCheck | None:
        return (
            await self.db.execute(
                select(RemediationPolicyCheck)
                .where(
                    RemediationPolicyCheck.tenant_id == plan.tenant_id,
                    RemediationPolicyCheck.plan_id == plan.id,
                )
                .order_by(desc(RemediationPolicyCheck.created_at))
                .limit(1)
            )
        ).scalars().first()

    async def _policy_check_by_hash(self, plan: RemediationPlan, check_hash: str) -> RemediationPolicyCheck | None:
        return (
            await self.db.execute(
                select(RemediationPolicyCheck).where(
                    RemediationPolicyCheck.tenant_id == plan.tenant_id,
                    RemediationPolicyCheck.plan_id == plan.id,
                    RemediationPolicyCheck.policy_check_hash == check_hash,
                )
            )
        ).scalars().first()

    def _ensure_pending(self, approval: RemediationApproval) -> None:
        if approval.status != RemediationApprovalStatus.pending:
            raise BadRequestException(detail=f"Only pending approvals can be actioned. Current status: {approval.status.value}")

    async def _emit_approval_event(
        self,
        event_cls,
        plan: RemediationPlan,
        approval: RemediationApproval,
        check: RemediationPolicyCheck | None,
        *,
        actor_id: uuid.UUID | str | None,
        reason: str | None,
    ) -> None:
        await self._emit(
            event_cls(
                tenant_id=plan.tenant_id,
                actor_id=self._uuid(actor_id) if actor_id else None,
                plan_id=plan.id,
                approval_id=approval.id,
                artifact_hash=approval.artifact_hash,
                policy_check_hash=approval.policy_check_hash,
                status=approval.status.value,
                risk_level=plan.risk_level.value,
                required_approval_level=check.required_approval_level.value if check else None,
                expires_at=approval.expires_at,
                reason=sanitize_text(reason or ""),
                reason_category=self._reason_category(reason),
            )
        )

    async def _emit_replay_blocked(self, plan: RemediationPlan, approval: RemediationApproval) -> None:
        check = await self._policy_check_by_hash(plan, approval.policy_check_hash)
        await self._emit(
            RemediationApprovalReplayBlockedEvent(
                tenant_id=plan.tenant_id,
                plan_id=plan.id,
                approval_id=approval.id,
                status=approval.status.value,
                risk_level=plan.risk_level.value,
                required_approval_level=check.required_approval_level.value if check else None,
                reason_category="verification_blocked",
            )
        )

    async def _emit_mfa_event(
        self,
        plan: RemediationPlan,
        approval: RemediationApproval,
        check: RemediationPolicyCheck | None,
        *,
        actor_id: uuid.UUID | str | None,
        action: str,
        envelope_hash: str,
        reason_category: str | None,
    ) -> None:
        await self._emit(
            RemediationMfaChallengeEvent(
                tenant_id=plan.tenant_id,
                actor_id=self._uuid(actor_id) if actor_id else None,
                plan_id=plan.id,
                approval_id=approval.id,
                artifact_hash=approval.artifact_hash,
                policy_check_hash=approval.policy_check_hash,
                status=approval.status.value,
                risk_level=plan.risk_level.value,
                required_approval_level=check.required_approval_level.value if check else None,
                action=action,
                envelope_hash=envelope_hash,
                expires_at=approval.expires_at,
                reason_category=reason_category,
            )
        )

    async def _emit(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish remediation approval event %s: %s", event.event_type, exc)

    def _reason_category(self, reason: str | None) -> str | None:
        safe = sanitize_text(reason or "").lower()
        if not safe:
            return None
        if "expire" in safe:
            return "expired"
        if "reject" in safe:
            return "rejected"
        if "revoke" in safe:
            return "revoked"
        return "operator_reason"

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))
