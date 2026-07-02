from __future__ import annotations

import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db, require_roles
from app.core.events.producer import producer as remediation_event_producer
from app.core.exceptions import NotFoundException
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalLevel,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationDryRunResult,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
    RemediationRollbackPlan,
    RemediationVerificationResult,
)
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.remediation import (
    ApproveRemediationRequest,
    CreateDryRunRequest,
    CreateExecutionRequest,
    GenerateRemediationPlanRequest,
    RejectRemediationRequest,
    RemediationApprovalListResponse,
    RemediationApprovalResponse,
    RemediationArtifactListResponse,
    RemediationArtifactResponse,
    RemediationDryRunResultListResponse,
    RemediationDryRunResultResponse,
    RemediationExecutionJobListResponse,
    RemediationExecutionJobResponse,
    RemediationPlanDetailResponse,
    RemediationPlanListResponse,
    RemediationPlanResponse,
    RemediationExecutionResultResponse,
    RemediationPolicyCheckListResponse,
    RemediationPolicyCheckResponse,
    RemediationRollbackPlanResponse,
    RemediationVerificationResultListResponse,
    RemediationVerificationResultResponse,
    RequestApprovalRequest,
    RevokeApprovalRequest,
    ValidateRemediationPlanResponse,
)
from app.services.api_safety import sanitize_text
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_dry_run_service import RemediationDryRunService
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_plan_generator import RemediationPlanGenerator
from app.services.remediation_policy_validator import RemediationPolicyValidator

router = APIRouter()

READ_ROLES = ["owner", "admin", "operator", "analyst", "auditor", "viewer", "security_admin"]
WRITE_ROLES = ["owner", "admin", "operator", "analyst", "security_admin"]
APPROVAL_ROLES = ["owner", "admin", "operator", "analyst", "security_admin"]
event_producer = remediation_event_producer


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _plan_response(plan: RemediationPlan) -> RemediationPlanResponse:
    return RemediationPlanResponse(
        id=plan.id,
        tenant_id=plan.tenant_id,
        finding_id=plan.finding_id,
        gap_id=plan.gap_id,
        recommendation_id=plan.recommendation_id,
        integration_id=plan.integration_id,
        provider=sanitize_text(plan.provider) if plan.provider else None,
        resource_ref=sanitize_text(plan.resource_ref) if plan.resource_ref else None,
        risk_level=_enum_value(plan.risk_level),
        status=_enum_value(plan.status),
        summary=sanitize_text(plan.summary),
        expected_impact=sanitize_text(plan.expected_impact),
        created_by=plan.created_by,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


def _artifact_response(artifact: RemediationArtifact, include_content: bool = True) -> RemediationArtifactResponse:
    return RemediationArtifactResponse(
        id=artifact.id,
        tenant_id=artifact.tenant_id,
        plan_id=artifact.plan_id,
        artifact_type=_enum_value(artifact.artifact_type),
        content_redacted=sanitize_text(artifact.content_redacted) if include_content else None,
        diff_summary=sanitize_text(artifact.diff_summary) if artifact.diff_summary else None,
        artifact_hash=artifact.artifact_hash,
        risk_flags=artifact.risk_flags or {},
        status=_enum_value(artifact.status),
        created_at=artifact.created_at,
        updated_at=artifact.updated_at,
    )


def _rollback_response(rollback: RemediationRollbackPlan) -> RemediationRollbackPlanResponse:
    return RemediationRollbackPlanResponse(
        id=rollback.id,
        tenant_id=rollback.tenant_id,
        plan_id=rollback.plan_id,
        rollback_summary=sanitize_text(rollback.rollback_steps),
        rollback_artifact_hash=rollback.rollback_artifact_hash,
        risk_level=_enum_value(rollback.risk_level),
        created_at=rollback.created_at,
        updated_at=getattr(rollback, "updated_at", None),
    )


def _policy_check_response(check: RemediationPolicyCheck) -> RemediationPolicyCheckResponse:
    return RemediationPolicyCheckResponse(
        id=check.id,
        tenant_id=check.tenant_id,
        plan_id=check.plan_id,
        artifact_id=check.artifact_id,
        passed=check.passed,
        warnings=check.warnings or [],
        blocking_reasons=check.blocking_reasons or [],
        required_approval_level=_enum_value(check.required_approval_level),
        policy_check_hash=check.policy_check_hash,
        created_at=check.created_at,
        updated_at=check.updated_at,
    )


async def _required_level_for_approval(db: AsyncSession, approval: RemediationApproval) -> str | None:
    check = (
        await db.execute(
            select(RemediationPolicyCheck).where(
                RemediationPolicyCheck.tenant_id == approval.tenant_id,
                RemediationPolicyCheck.plan_id == approval.plan_id,
                RemediationPolicyCheck.policy_check_hash == approval.policy_check_hash,
            )
        )
    ).scalars().first()
    return _enum_value(check.required_approval_level) if check else None


async def _approval_response(db: AsyncSession, approval: RemediationApproval) -> RemediationApprovalResponse:
    return RemediationApprovalResponse(
        id=approval.id,
        tenant_id=approval.tenant_id,
        plan_id=approval.plan_id,
        artifact_hash=approval.artifact_hash,
        policy_check_hash=approval.policy_check_hash,
        required_approval_level=await _required_level_for_approval(db, approval),
        requested_by=approval.requested_by,
        approved_by=approval.approved_by,
        status=_enum_value(approval.status),
        expires_at=approval.expires_at,
        resolved_at=approval.resolved_at,
        mfa_verified=approval.mfa_verified,
        approval_reason=sanitize_text(approval.approval_reason) if approval.approval_reason else None,
        created_at=approval.created_at,
        updated_at=approval.updated_at,
    )


def _job_response(job: RemediationExecutionJob) -> RemediationExecutionJobResponse:
    return RemediationExecutionJobResponse(
        id=job.id,
        tenant_id=job.tenant_id,
        plan_id=job.plan_id,
        approval_id=job.approval_id,
        sandbox_id=sanitize_text(job.sandbox_id) if job.sandbox_id else None,
        dry_run_result_id=job.dry_run_result_id,
        status=_enum_value(job.status),
        disabled_reason=sanitize_text(job.disabled_reason) if job.disabled_reason else None,
        started_at=job.started_at,
        completed_at=job.completed_at,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


def _dry_run_response(result: RemediationDryRunResult) -> RemediationDryRunResultResponse:
    return RemediationDryRunResultResponse(
        id=result.id,
        tenant_id=result.tenant_id,
        job_id=result.job_id,
        plan_id=result.plan_id,
        artifact_id=result.artifact_id,
        approval_id=result.approval_id,
        sandbox_id=sanitize_text(result.sandbox_id),
        dry_run_type=sanitize_text(result.dry_run_type),
        status=_enum_value(result.status),
        output_summary=sanitize_text(result.output_summary),
        warnings=result.warnings or [],
        blocking_reasons=result.blocking_reasons or [],
        started_at=result.started_at,
        completed_at=result.completed_at,
        created_at=result.created_at,
        updated_at=result.updated_at,
    )


def _verification_response(result: RemediationVerificationResult) -> RemediationVerificationResultResponse:
    return RemediationVerificationResultResponse(
        id=result.id,
        tenant_id=result.tenant_id,
        plan_id=result.plan_id,
        job_id=result.job_id,
        finding_status_before=sanitize_text(result.finding_status_before) if result.finding_status_before else None,
        finding_status_after=sanitize_text(result.finding_status_after) if result.finding_status_after else None,
        evidence_id=result.evidence_id,
        verified=result.verified,
        verification_summary=sanitize_text(result.verification_summary),
        status=_enum_value(result.status),
        created_at=result.created_at,
        updated_at=result.updated_at,
    )


def _execution_result_response(
    job: RemediationExecutionJob,
    verification: RemediationVerificationResult | None,
) -> RemediationExecutionResultResponse:
    return RemediationExecutionResultResponse(
        job=_job_response(job),
        verification_result=_verification_response(verification) if verification else None,
    )


async def _plan_or_404(db: AsyncSession, tenant_id: uuid.UUID, plan_id: uuid.UUID) -> RemediationPlan:
    plan = (
        await db.execute(
            select(RemediationPlan).where(RemediationPlan.tenant_id == tenant_id, RemediationPlan.id == plan_id)
        )
    ).scalars().first()
    if plan is None:
        raise NotFoundException(detail="Remediation plan not found")
    return plan


async def _artifact_or_404(db: AsyncSession, tenant_id: uuid.UUID, artifact_id: uuid.UUID) -> RemediationArtifact:
    artifact = (
        await db.execute(
            select(RemediationArtifact).where(
                RemediationArtifact.tenant_id == tenant_id,
                RemediationArtifact.id == artifact_id,
            )
        )
    ).scalars().first()
    if artifact is None:
        raise NotFoundException(detail="Remediation artifact not found")
    return artifact


async def _approval_or_404(db: AsyncSession, tenant_id: uuid.UUID, approval_id: uuid.UUID) -> RemediationApproval:
    approval = (
        await db.execute(
            select(RemediationApproval).where(
                RemediationApproval.tenant_id == tenant_id,
                RemediationApproval.id == approval_id,
            )
        )
    ).scalars().first()
    if approval is None:
        raise NotFoundException(detail="Remediation approval not found")
    return approval


async def _job_or_404(db: AsyncSession, tenant_id: uuid.UUID, job_id: uuid.UUID) -> RemediationExecutionJob:
    job = (
        await db.execute(
            select(RemediationExecutionJob).where(
                RemediationExecutionJob.tenant_id == tenant_id,
                RemediationExecutionJob.id == job_id,
            )
        )
    ).scalars().first()
    if job is None:
        raise NotFoundException(detail="Remediation execution job not found")
    return job


async def _set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
        {"tenant_id": str(tenant_id)},
    )


@router.get("/plans", response_model=RemediationPlanListResponse)
async def list_plans(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    status: RemediationPlanStatus | None = None,
    risk_level: RemediationRiskLevel | None = None,
    provider: str | None = None,
    source_type: str | None = None,
    finding_id: uuid.UUID | None = None,
    gap_id: uuid.UUID | None = None,
    recommendation_id: uuid.UUID | None = None,
    created_by: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    query = select(RemediationPlan).where(RemediationPlan.tenant_id == tenant.id)
    if status is not None:
        query = query.where(RemediationPlan.status == status)
    if risk_level is not None:
        query = query.where(RemediationPlan.risk_level == risk_level)
    if provider:
        query = query.where(RemediationPlan.provider == sanitize_text(provider).lower())
    if finding_id:
        query = query.where(RemediationPlan.finding_id == finding_id)
    if gap_id:
        query = query.where(RemediationPlan.gap_id == gap_id)
    if recommendation_id:
        query = query.where(RemediationPlan.recommendation_id == recommendation_id)
    if created_by:
        query = query.where(RemediationPlan.created_by == created_by)
    if source_type == "finding":
        query = query.where(RemediationPlan.finding_id.is_not(None))
    elif source_type == "gap":
        query = query.where(RemediationPlan.gap_id.is_not(None))
    elif source_type == "recommendation":
        query = query.where(RemediationPlan.recommendation_id.is_not(None))

    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(RemediationPlan.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    return RemediationPlanListResponse(items=[_plan_response(item) for item in rows], total=total or 0, skip=skip, limit=limit)


@router.post("/plans/generate", response_model=RemediationPlanDetailResponse)
async def generate_plan(
    body: GenerateRemediationPlanRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(WRITE_ROLES)),
):
    generator = RemediationPlanGenerator(db, event_producer=event_producer)
    if body.source_type == "finding":
        result = await generator.generate_from_finding(tenant.id, body.source_id, actor_id=current_user.id)
    elif body.source_type == "gap":
        result = await generator.generate_from_gap(tenant.id, body.source_id, actor_id=current_user.id)
    else:
        result = await generator.generate_from_recommendation(tenant.id, body.source_id, actor_id=current_user.id)
    plan_id = result.plan.id
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return await get_plan(plan_id, tenant=tenant, db=db, _user=current_user)


@router.get("/plans/{plan_id}", response_model=RemediationPlanDetailResponse)
async def get_plan(
    plan_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    plan = await _plan_or_404(db, tenant.id, plan_id)
    artifacts = (
        await db.execute(select(RemediationArtifact).where(RemediationArtifact.tenant_id == tenant.id, RemediationArtifact.plan_id == plan.id))
    ).scalars().all()
    rollback = (
        await db.execute(select(RemediationRollbackPlan).where(RemediationRollbackPlan.tenant_id == tenant.id, RemediationRollbackPlan.plan_id == plan.id))
    ).scalars().first()
    checks = (
        await db.execute(select(RemediationPolicyCheck).where(RemediationPolicyCheck.tenant_id == tenant.id, RemediationPolicyCheck.plan_id == plan.id))
    ).scalars().all()
    approvals = (
        await db.execute(select(RemediationApproval).where(RemediationApproval.tenant_id == tenant.id, RemediationApproval.plan_id == plan.id))
    ).scalars().all()
    jobs = (
        await db.execute(select(RemediationExecutionJob).where(RemediationExecutionJob.tenant_id == tenant.id, RemediationExecutionJob.plan_id == plan.id))
    ).scalars().all()
    base = _plan_response(plan).model_dump()
    return RemediationPlanDetailResponse(
        **base,
        artifacts=[_artifact_response(item) for item in artifacts],
        rollback_plan=_rollback_response(rollback) if rollback else None,
        policy_checks=[_policy_check_response(item) for item in checks],
        approvals=[await _approval_response(db, item) for item in approvals],
        execution_jobs=[_job_response(item) for item in jobs],
    )


@router.get("/plans/{plan_id}/artifacts", response_model=RemediationArtifactListResponse)
async def list_plan_artifacts(
    plan_id: uuid.UUID,
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    await _plan_or_404(db, tenant.id, plan_id)
    query = select(RemediationArtifact).where(RemediationArtifact.tenant_id == tenant.id, RemediationArtifact.plan_id == plan_id)
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(RemediationArtifact.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    return RemediationArtifactListResponse(items=[_artifact_response(item) for item in rows], total=total or 0, skip=skip, limit=limit)


@router.get("/artifacts/{artifact_id}", response_model=RemediationArtifactResponse)
async def get_artifact(
    artifact_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    return _artifact_response(await _artifact_or_404(db, tenant.id, artifact_id))


@router.post("/plans/{plan_id}/validate", response_model=ValidateRemediationPlanResponse)
async def validate_plan(
    plan_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(WRITE_ROLES)),
):
    result = await RemediationPolicyValidator(db, event_producer=event_producer).validate_plan(tenant.id, plan_id, actor_id=current_user.id)
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return ValidateRemediationPlanResponse(
        plan=_plan_response(result.plan),
        artifact=_artifact_response(result.artifact),
        policy_check=_policy_check_response(result.policy_check),
    )


@router.get("/plans/{plan_id}/policy-checks", response_model=RemediationPolicyCheckListResponse)
async def list_policy_checks(
    plan_id: uuid.UUID,
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    passed: bool | None = None,
    required_approval_level: RemediationApprovalLevel | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    await _plan_or_404(db, tenant.id, plan_id)
    query = select(RemediationPolicyCheck).where(RemediationPolicyCheck.tenant_id == tenant.id, RemediationPolicyCheck.plan_id == plan_id)
    if passed is not None:
        query = query.where(RemediationPolicyCheck.passed == passed)
    if required_approval_level is not None:
        query = query.where(RemediationPolicyCheck.required_approval_level == required_approval_level)
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(RemediationPolicyCheck.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    return RemediationPolicyCheckListResponse(items=[_policy_check_response(item) for item in rows], total=total or 0, skip=skip, limit=limit)


@router.post("/plans/{plan_id}/request-approval", response_model=RemediationApprovalResponse)
async def request_approval(
    plan_id: uuid.UUID,
    body: RequestApprovalRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(WRITE_ROLES)),
):
    approval = await RemediationApprovalService(db, event_producer=event_producer).request_approval(
        tenant.id,
        plan_id,
        requested_by=current_user.id,
        reason=body.reason,
    )
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return await _approval_response(db, approval)


@router.get("/approvals", response_model=RemediationApprovalListResponse)
async def list_approvals(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    status: RemediationApprovalStatus | None = None,
    required_approval_level: RemediationApprovalLevel | None = None,
    plan_id: uuid.UUID | None = None,
    expires_before: datetime | None = None,
    requested_by: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    query = select(RemediationApproval).where(RemediationApproval.tenant_id == tenant.id)
    if status is not None:
        query = query.where(RemediationApproval.status == status)
    if plan_id:
        query = query.where(RemediationApproval.plan_id == plan_id)
    if expires_before:
        query = query.where(RemediationApproval.expires_at < expires_before)
    if requested_by:
        query = query.where(RemediationApproval.requested_by == requested_by)
    rows = (await db.execute(query.order_by(RemediationApproval.created_at.desc()))).scalars().all()
    responses = [await _approval_response(db, item) for item in rows]
    if required_approval_level is not None:
        responses = [item for item in responses if item.required_approval_level == required_approval_level.value]
    total = len(responses)
    return RemediationApprovalListResponse(items=responses[skip : skip + limit], total=total, skip=skip, limit=limit)


@router.get("/approvals/{approval_id}", response_model=RemediationApprovalResponse)
async def get_approval(
    approval_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    return await _approval_response(db, await _approval_or_404(db, tenant.id, approval_id))


@router.post("/approvals/{approval_id}/approve", response_model=RemediationApprovalResponse)
async def approve_remediation(
    approval_id: uuid.UUID,
    body: ApproveRemediationRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(APPROVAL_ROLES)),
):
    approval = await RemediationApprovalService(db, event_producer=event_producer).approve(
        tenant.id,
        approval_id,
        approved_by=current_user.id,
        approval_reason=body.approval_reason,
        mfa_verified=body.mfa_verified,
    )
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return await _approval_response(db, approval)


@router.post("/approvals/{approval_id}/reject", response_model=RemediationApprovalResponse)
async def reject_remediation(
    approval_id: uuid.UUID,
    body: RejectRemediationRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(APPROVAL_ROLES)),
):
    approval = await RemediationApprovalService(db, event_producer=event_producer).reject(
        tenant.id,
        approval_id,
        rejected_by=current_user.id,
        rejection_reason=body.rejection_reason,
    )
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return await _approval_response(db, approval)


@router.post("/approvals/{approval_id}/revoke", response_model=RemediationApprovalResponse)
async def revoke_remediation(
    approval_id: uuid.UUID,
    body: RevokeApprovalRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin", "security_admin"])),
):
    approval = await RemediationApprovalService(db, event_producer=event_producer).revoke_approval(
        tenant.id,
        approval_id,
        revoked_by=current_user.id,
        reason=body.reason,
    )
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return await _approval_response(db, approval)


@router.get("/jobs", response_model=RemediationExecutionJobListResponse)
async def list_jobs(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    status: RemediationExecutionStatus | None = None,
    plan_id: uuid.UUID | None = None,
    approval_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    query = select(RemediationExecutionJob).where(RemediationExecutionJob.tenant_id == tenant.id)
    if status is not None:
        query = query.where(RemediationExecutionJob.status == status)
    if plan_id:
        query = query.where(RemediationExecutionJob.plan_id == plan_id)
    if approval_id:
        query = query.where(RemediationExecutionJob.approval_id == approval_id)
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(RemediationExecutionJob.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    return RemediationExecutionJobListResponse(items=[_job_response(item) for item in rows], total=total or 0, skip=skip, limit=limit)


@router.get("/jobs/{job_id}", response_model=RemediationExecutionJobResponse)
async def get_job(
    job_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    return _job_response(await _job_or_404(db, tenant.id, job_id))


@router.post("/plans/{plan_id}/artifacts/{artifact_id}/dry-run", response_model=RemediationDryRunResultResponse)
async def create_plan_artifact_dry_run(
    plan_id: uuid.UUID,
    artifact_id: uuid.UUID,
    body: CreateDryRunRequest | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(APPROVAL_ROLES)),
):
    body = body or CreateDryRunRequest()
    service = RemediationDryRunService(db, event_producer=event_producer)
    job = await service.create_dry_run_job(
        tenant.id,
        plan_id,
        artifact_id,
        approval_id=body.approval_id,
        actor_id=current_user.id,
    )
    result = await service.run_dry_run(tenant.id, job.id)
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return _dry_run_response(result)


@router.get("/dry-runs", response_model=RemediationDryRunResultListResponse)
async def list_dry_runs(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    plan_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    results = await RemediationDryRunService(db, event_producer=event_producer).list_dry_run_results(tenant.id, plan_id=plan_id)
    total = len(results)
    page = results[skip : skip + limit]
    return RemediationDryRunResultListResponse(items=[_dry_run_response(item) for item in page], total=total, skip=skip, limit=limit)


@router.get("/dry-runs/{result_id}", response_model=RemediationDryRunResultResponse)
async def get_dry_run(
    result_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    result = await RemediationDryRunService(db, event_producer=event_producer).get_dry_run_result(tenant.id, result_id)
    return _dry_run_response(result)


@router.post("/jobs/{job_id}/dry-run", response_model=RemediationDryRunResultResponse)
async def run_job_dry_run(
    job_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(APPROVAL_ROLES)),
):
    result = await RemediationDryRunService(db, event_producer=event_producer).run_dry_run(tenant.id, job_id)
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    return _dry_run_response(result)


@router.post("/plans/{plan_id}/artifacts/{artifact_id}/execute", response_model=RemediationExecutionResultResponse)
async def create_plan_artifact_execution(
    plan_id: uuid.UUID,
    artifact_id: uuid.UUID,
    body: CreateExecutionRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(APPROVAL_ROLES)),
):
    service = RemediationExecutionService(db, event_producer=event_producer)
    job = await service.create_execution_job(
        tenant.id,
        plan_id,
        artifact_id,
        body.approval_id,
        actor_id=current_user.id,
    )
    verification = await service.execute_job(tenant.id, job.id, actor_id=current_user.id)
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    refreshed_job = await service.get_execution_job(tenant.id, job.id)
    return _execution_result_response(refreshed_job, verification)


@router.post("/jobs/{job_id}/execute", response_model=RemediationExecutionResultResponse)
async def execute_job(
    job_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(APPROVAL_ROLES)),
):
    service = RemediationExecutionService(db, event_producer=event_producer)
    verification = await service.execute_job(tenant.id, job_id, actor_id=current_user.id)
    await db.commit()
    await _set_tenant_context(db, tenant.id)
    refreshed_job = await service.get_execution_job(tenant.id, job_id)
    return _execution_result_response(refreshed_job, verification)


@router.get("/verification-results", response_model=RemediationVerificationResultListResponse)
async def list_verification_results(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    plan_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    results = await RemediationExecutionService(db, event_producer=event_producer).list_verification_results(tenant.id, plan_id=plan_id)
    total = len(results)
    page = results[skip : skip + limit]
    return RemediationVerificationResultListResponse(
        items=[_verification_response(item) for item in page],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/verification-results/{result_id}", response_model=RemediationVerificationResultResponse)
async def get_verification_result(
    result_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(READ_ROLES)),
):
    result = await RemediationExecutionService(db, event_producer=event_producer).get_verification_result(tenant.id, result_id)
    return _verification_response(result)
