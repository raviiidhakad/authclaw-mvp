from __future__ import annotations

import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import func, select, text

from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalLevel,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationArtifactType,
    RemediationExecutionJob,
    RemediationPlanStatus,
    RemediationRiskLevel,
)
from app.models.role import Role, UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_policy_validator import RemediationPolicyValidator
from app.services.remediation_state_machine import (
    RemediationExecutionDisabled,
    RemediationPlanService,
    RemediationStateMachine,
    artifact_hash,
    utcnow,
)


class FakeProducer:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


async def _role(db, name: str) -> Role:
    role = (await db.execute(select(Role).where(Role.name == name))).scalars().first()
    if role is None:
        role = Role(id=uuid.uuid4(), name=name, description=f"test role {name}", is_system=True)
        db.add(role)
        await db.flush()
    return role


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint4-phase4-{suffix}",
        slug=f"sprint4-phase4-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _user(db, tenant_id: uuid.UUID, role_name: str, suffix: str | None = None) -> User:
    suffix = suffix or secrets.token_hex(5)
    role = await _role(db, role_name)
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
        {"tenant_id": str(tenant_id)},
    )
    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        email=f"{role_name}-{suffix}@phase4.test",
        password_hash="not-a-real-password-hash",
        first_name=role_name,
        last_name="Approver",
        is_active=True,
        mfa_enabled=True,
        mfa_secret="phase4-test-secret",
    )
    db.add(user)
    await db.flush()
    db.add(UserRole(id=uuid.uuid4(), user_id=user.id, role_id=role.id, tenant_id=tenant_id))
    await db.flush()
    return user


async def _validated_plan(
    db,
    tenant_id: uuid.UUID,
    *,
    artifact_type: RemediationArtifactType = RemediationArtifactType.documentation_only,
    content: str = "Documentation-only draft. Human review only. No execution.",
    risk_flags: dict | None = None,
    risk_level: RemediationRiskLevel = RemediationRiskLevel.low,
):
    plan_service = RemediationPlanService(db, event_producer=None)
    plan = await plan_service.create_draft_plan_shell(
        tenant_id=tenant_id,
        summary="Sprint 4 Phase 4 approval fixture.",
        expected_impact="Approval-only fixture. No execution.",
        risk_level=risk_level,
    )
    artifact = await plan_service.attach_artifact_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=artifact_type,
        content=content,
        diff_summary="Approval fixture diff summary.",
        risk_flags=risk_flags or {"template_key": "documentation_only", "rollback_uncertain": False},
    )
    await plan_service.attach_rollback_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        rollback_steps="Restore previous reviewed state if a future phase executes.",
        risk_level=risk_level,
    )
    validation = await RemediationPolicyValidator(db, event_producer=None).validate_plan(tenant_id, plan.id)
    return validation.plan, artifact, validation.policy_check


async def _critical_validated_plan(db, tenant_id: uuid.UUID):
    return await _validated_plan(
        db,
        tenant_id,
        artifact_type=RemediationArtifactType.iam_policy_diff,
        content=(
            "IAM diff draft only; no automatic permission removal. "
            "--- current policy <review current effective permissions> +++ proposed direction "
            "<remove only explicitly validated excessive permissions>."
        ),
        risk_flags={"template_key": "aws_iam_least_privilege_review", "rollback_uncertain": False},
        risk_level=RemediationRiskLevel.critical,
    )


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    await db.rollback()
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        for table in (
            "remediation_audit_links",
            "remediation_verification_results",
            "remediation_execution_jobs",
            "remediation_approvals",
            "remediation_policy_checks",
            "remediation_rollback_plans",
            "remediation_artifacts",
            "remediation_plans",
            "user_roles",
            "users",
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


@pytest.mark.asyncio
async def test_request_approval_for_validated_plan_binds_artifact_and_policy_hash():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator")
            plan, artifact, check = await _validated_plan(db, tenant.id)
            producer = FakeProducer()
            approval = await RemediationApprovalService(db, event_producer=producer).request_approval(
                tenant.id,
                plan.id,
                requested_by=requester.id,
                reason="Request reviewed approval.",
            )

            assert approval.status == RemediationApprovalStatus.pending
            assert approval.artifact_hash == artifact.artifact_hash
            assert approval.policy_check_hash == check.policy_check_hash
            assert approval.nonce
            assert approval.expires_at > utcnow()
            assert plan.status == RemediationPlanStatus.approval_requested
            assert "remediation.approval.requested" in [event["event_type"] for _, event in producer.events]
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_request_approval_for_unvalidated_or_failed_policy_plan_fails():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan_service = RemediationPlanService(db, event_producer=None)
            plan = await plan_service.create_draft_plan_shell(
                tenant_id=tenant.id,
                summary="Unvalidated",
                expected_impact="No approval.",
            )
            with pytest.raises(BadRequestException):
                await RemediationApprovalService(db, event_producer=None).request_approval(tenant.id, plan.id)

            failed_plan, artifact, _ = await _validated_plan(db, tenant.id)
            failed_plan.status = RemediationPlanStatus.plan_validated
            artifact.content_redacted = "terraform apply -auto-approve"
            artifact.artifact_hash = artifact_hash(artifact.artifact_type, artifact.content_redacted)
            await db.flush()
            failed = await RemediationPolicyValidator(db, event_producer=None).validate_artifact(tenant.id, artifact.id)
            assert failed.policy_check.passed is False
            with pytest.raises(BadRequestException):
                await RemediationApprovalService(db, event_producer=None).request_approval(tenant.id, failed_plan.id)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_approve_critical_plan_requires_privileged_role_mfa_and_separation_of_duties():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator", "requester")
            owner = await _user(db, tenant.id, "owner", "owner")
            viewer = await _user(db, tenant.id, "viewer", "viewer")
            plan, _, check = await _critical_validated_plan(db, tenant.id)
            service = RemediationApprovalService(db, event_producer=None)
            approval = await service.request_approval(tenant.id, plan.id, requested_by=requester.id)

            assert check.required_approval_level == RemediationApprovalLevel.security_admin
            with pytest.raises(ForbiddenException):
                await service.approve(tenant.id, approval.id, viewer.id, "viewer cannot approve", mfa_verified=True)
            with pytest.raises(ForbiddenException):
                await service.approve(tenant.id, approval.id, owner.id, "missing mfa", mfa_verified=False)

            approved = await service.approve(tenant.id, approval.id, owner.id, "Approved after review.", mfa_verified=True)
            assert approved.status == RemediationApprovalStatus.approved
            assert approved.approved_by == owner.id
            assert approved.mfa_verified is True
            assert plan.status == RemediationPlanStatus.approved
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_self_approval_for_critical_plan_is_blocked():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            owner = await _user(db, tenant.id, "owner")
            plan, _, _ = await _critical_validated_plan(db, tenant.id)
            service = RemediationApprovalService(db, event_producer=None)
            approval = await service.request_approval(tenant.id, plan.id, requested_by=owner.id)
            with pytest.raises(ForbiddenException):
                await service.approve(tenant.id, approval.id, owner.id, "Cannot approve own critical request.", mfa_verified=True)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_reject_and_revoke_approval_paths_are_stateful():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator", "requester")
            analyst = await _user(db, tenant.id, "analyst", "analyst")
            admin = await _user(db, tenant.id, "admin", "admin")
            plan, _, _ = await _validated_plan(db, tenant.id)
            service = RemediationApprovalService(db, event_producer=None)
            approval = await service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            rejected = await service.reject(tenant.id, approval.id, analyst.id, "Rejected after review.")
            assert rejected.status == RemediationApprovalStatus.rejected
            assert plan.status == RemediationPlanStatus.rejected

            second_plan, _, _ = await _validated_plan(db, tenant.id)
            second_approval = await service.request_approval(tenant.id, second_plan.id, requested_by=requester.id)
            revoked = await service.revoke_approval(tenant.id, second_approval.id, admin.id, "Revoked stale request.")
            assert revoked.status == RemediationApprovalStatus.revoked
            assert second_plan.status == RemediationPlanStatus.rejected
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_expiry_and_approval_after_expiry_are_blocked():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator")
            owner = await _user(db, tenant.id, "owner")
            plan, _, _ = await _validated_plan(db, tenant.id)
            service = RemediationApprovalService(db, event_producer=None)
            approval = await service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            approval.expires_at = utcnow() - __import__("datetime").timedelta(minutes=1)
            await db.flush()

            with pytest.raises(BadRequestException):
                await service.approve(tenant.id, approval.id, owner.id, "Too late.", mfa_verified=True)
            assert approval.status == RemediationApprovalStatus.expired
            assert plan.status == RemediationPlanStatus.expired

            other_plan, _, _ = await _validated_plan(db, tenant.id)
            other_approval = await service.request_approval(tenant.id, other_plan.id, requested_by=requester.id)
            other_approval.expires_at = utcnow() - __import__("datetime").timedelta(minutes=1)
            await db.flush()
            expired = await service.expire_approvals(tenant.id)
            assert other_approval in expired
            assert other_approval.status == RemediationApprovalStatus.expired
            assert other_plan.status == RemediationPlanStatus.expired
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_future_execution_verification_is_single_use_and_execution_stays_disabled():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator", "requester")
            owner = await _user(db, tenant.id, "owner", "owner")
            plan, _, _ = await _critical_validated_plan(db, tenant.id)
            service = RemediationApprovalService(db, event_producer=None)
            approval = await service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            await service.approve(tenant.id, approval.id, owner.id, "Approved.", mfa_verified=True)

            verification = await service.verify_approval_for_future_execution(tenant.id, plan.id, approval.id)
            assert verification.approval.status == RemediationApprovalStatus.used
            with pytest.raises(BadRequestException):
                await service.verify_approval_for_future_execution(tenant.id, plan.id, approval.id)
            with pytest.raises(RemediationExecutionDisabled):
                await RemediationStateMachine(db, event_producer=None).transition_plan(
                    tenant.id,
                    plan.id,
                    RemediationPlanStatus.queued_for_execution,
                )
            assert await db.scalar(select(func.count(RemediationExecutionJob.id)).where(RemediationExecutionJob.plan_id == plan.id)) == 0
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_artifact_or_policy_hash_mismatch_blocks_future_verification():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator", "requester")
            owner = await _user(db, tenant.id, "owner", "owner")
            service = RemediationApprovalService(db, event_producer=None)

            plan, artifact, _ = await _critical_validated_plan(db, tenant.id)
            approval = await service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            await service.approve(tenant.id, approval.id, owner.id, "Approved.", mfa_verified=True)
            artifact.artifact_hash = "1" * 64
            await db.flush()
            with pytest.raises(BadRequestException):
                await service.verify_approval_for_future_execution(tenant.id, plan.id, approval.id)

            second_plan, _, second_check = await _critical_validated_plan(db, tenant.id)
            second_approval = await service.request_approval(tenant.id, second_plan.id, requested_by=requester.id)
            await service.approve(tenant.id, second_approval.id, owner.id, "Approved.", mfa_verified=True)
            second_check.passed = False
            await db.flush()
            with pytest.raises(BadRequestException):
                await service.verify_approval_for_future_execution(tenant.id, second_plan.id, second_approval.id)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_cross_tenant_approval_and_viewer_auditor_are_blocked():
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(4))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(4))
        try:
            requester = await _user(db, tenant_a.id, "operator", "requester")
            viewer = await _user(db, tenant_a.id, "viewer", "viewer")
            auditor = await _user(db, tenant_a.id, "auditor", "auditor")
            plan, _, _ = await _validated_plan(db, tenant_a.id)
            service = RemediationApprovalService(db, event_producer=None)
            approval = await service.request_approval(tenant_a.id, plan.id, requested_by=requester.id)

            with pytest.raises(NotFoundException):
                await service.approve(tenant_b.id, approval.id, viewer.id, "wrong tenant", mfa_verified=True)
            with pytest.raises(ForbiddenException):
                await service.approve(tenant_a.id, approval.id, viewer.id, "viewer blocked", mfa_verified=True)
            with pytest.raises(ForbiddenException):
                await service.reject(tenant_a.id, approval.id, auditor.id, "auditor blocked")
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_pending_approval_listing_and_events_are_sanitized():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator")
            plan, _, _ = await _validated_plan(db, tenant.id)
            producer = FakeProducer()
            service = RemediationApprovalService(db, event_producer=producer)
            approval = await service.request_approval(
                tenant.id,
                plan.id,
                requested_by=requester.id,
                reason="token=ghp_abcdefghijklmnopqrstuvwxyz123456 raw_provider_payload",
            )
            pending = await service.get_pending_approvals(tenant.id, {"plan_id": plan.id})
            assert [item.id for item in pending] == [approval.id]

            serialized = json.dumps([event for _, event in producer.events], sort_keys=True).lower()
            assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in serialized
            assert "raw_provider_payload" not in serialized
            assert "content_redacted" not in serialized
        finally:
            await _cleanup(db, tenant.id)


def test_approval_service_has_no_execution_or_provider_clients():
    source = inspect.getsource(RemediationApprovalService).lower()
    forbidden = (
        "import subprocess",
        "os.system",
        "boto3.client",
        "botocore",
        "requests.",
        "httpx.",
        "github(",
        "create_pull",
        "terraform apply",
        "terraform destroy",
        "hvac",
        "vault",
    )
    for token in forbidden:
        assert token not in source
