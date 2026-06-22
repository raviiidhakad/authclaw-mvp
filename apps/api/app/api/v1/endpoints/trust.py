from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db
from app.api.v1.endpoints.trust_common import ensure_permission, require_trust_permission, sanitizer
from app.core.events.producer import producer as default_event_producer
from app.models.compliance import ComplianceAssessment, ComplianceGap, EvidenceItem
from app.models.finding import SecurityFinding
from app.models.integration import CloudIntegration
from app.models.remediation import RemediationExecutionJob, RemediationPlan, RemediationVerificationResult
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.events import TrustCenterViewedEvent
from app.schemas.trust import TrustOverviewResponse, TrustPostureResponse
from app.services.trust_reporting import TRUST_EVENTS_TOPIC, VIEW_TRUST_DASHBOARD, sanitized_event_payload

router = APIRouter()
event_producer = default_event_producer

POSTURE_LANGUAGE = "Evidence-supported posture summary for review. This is not legal advice and does not certify compliance."


async def _emit_view(tenant_id: uuid.UUID, actor_id: uuid.UUID | None, surface: str) -> None:
    if event_producer is not None:
        await event_producer.publish(
            TRUST_EVENTS_TOPIC,
            TrustCenterViewedEvent(
                tenant_id=tenant_id,
                actor_id=actor_id,
                payload=sanitized_event_payload({"surface": surface}),
            ),
        )


def _response(tenant_id: uuid.UUID, posture: str, counts=None, status_counts=None, severity_counts=None, freshness=None) -> TrustPostureResponse:
    payload = sanitizer.sanitize_payload(
        {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc),
            "language": POSTURE_LANGUAGE,
            "posture": posture,
            "counts": counts or {},
            "status_counts": status_counts or {},
            "severity_counts": severity_counts or {},
            "freshness": freshness or {},
        }
    )
    payload.pop("sanitization_version", None)
    return TrustPostureResponse(**payload)


async def _counts_by(db: AsyncSession, stmt, field_name: str) -> dict[str, int]:
    rows = (await db.execute(stmt)).all()
    return {str(getattr(getattr(row, field_name), "value", getattr(row, field_name))): int(row.count) for row in rows}


async def _security_posture(db: AsyncSession, tenant_id: uuid.UUID) -> TrustPostureResponse:
    total = await db.scalar(
        select(func.count(SecurityFinding.id))
        .join(CloudIntegration, CloudIntegration.id == SecurityFinding.integration_id)
        .where(CloudIntegration.tenant_id == tenant_id)
    )
    severity = await _counts_by(
        db,
        select(SecurityFinding.severity.label("severity"), func.count(SecurityFinding.id).label("count"))
        .join(CloudIntegration, CloudIntegration.id == SecurityFinding.integration_id)
        .where(CloudIntegration.tenant_id == tenant_id)
        .group_by(SecurityFinding.severity),
        "severity",
    )
    status = await _counts_by(
        db,
        select(SecurityFinding.status.label("status"), func.count(SecurityFinding.id).label("count"))
        .join(CloudIntegration, CloudIntegration.id == SecurityFinding.integration_id)
        .where(CloudIntegration.tenant_id == tenant_id)
        .group_by(SecurityFinding.status),
        "status",
    )
    posture = "at risk" if severity.get("critical", 0) or severity.get("high", 0) else "evidence-supported posture"
    return _response(tenant_id, posture, counts={"findings": total or 0}, severity_counts=severity, status_counts=status)


async def _compliance_posture(db: AsyncSession, tenant_id: uuid.UUID) -> TrustPostureResponse:
    assessment_count = await db.scalar(select(func.count(ComplianceAssessment.id)).where(ComplianceAssessment.tenant_id == tenant_id))
    gap_count = await db.scalar(select(func.count(ComplianceGap.id)).where(ComplianceGap.tenant_id == tenant_id))
    evidence_count = await db.scalar(select(func.count(EvidenceItem.id)).where(EvidenceItem.tenant_id == tenant_id))
    status = await _counts_by(
        db,
        select(ComplianceAssessment.status.label("status"), func.count(ComplianceAssessment.id).label("count"))
        .where(ComplianceAssessment.tenant_id == tenant_id)
        .group_by(ComplianceAssessment.status),
        "status",
    )
    gap_severity = await _counts_by(
        db,
        select(ComplianceGap.severity.label("severity"), func.count(ComplianceGap.id).label("count"))
        .where(ComplianceGap.tenant_id == tenant_id)
        .group_by(ComplianceGap.severity),
        "severity",
    )
    stale_evidence = await db.scalar(
        select(func.count(EvidenceItem.id)).where(
            EvidenceItem.tenant_id == tenant_id,
            EvidenceItem.freshness_expires_at.is_not(None),
            EvidenceItem.freshness_expires_at < datetime.now(timezone.utc).replace(tzinfo=None),
        )
    )
    posture = "gap detected" if gap_count else "evidence-supported posture"
    return _response(
        tenant_id,
        posture,
        counts={"assessments": assessment_count or 0, "gaps": gap_count or 0, "evidence_items": evidence_count or 0},
        status_counts=status,
        severity_counts=gap_severity,
        freshness={"stale_or_expired_evidence": stale_evidence or 0},
    )


async def _remediation_posture(db: AsyncSession, tenant_id: uuid.UUID) -> TrustPostureResponse:
    plan_count = await db.scalar(select(func.count(RemediationPlan.id)).where(RemediationPlan.tenant_id == tenant_id))
    job_count = await db.scalar(select(func.count(RemediationExecutionJob.id)).where(RemediationExecutionJob.tenant_id == tenant_id))
    verified_count = await db.scalar(
        select(func.count(RemediationVerificationResult.id)).where(
            RemediationVerificationResult.tenant_id == tenant_id,
            RemediationVerificationResult.verified.is_(True),
        )
    )
    plan_status = await _counts_by(
        db,
        select(RemediationPlan.status.label("status"), func.count(RemediationPlan.id).label("count"))
        .where(RemediationPlan.tenant_id == tenant_id)
        .group_by(RemediationPlan.status),
        "status",
    )
    job_status = await _counts_by(
        db,
        select(RemediationExecutionJob.status.label("status"), func.count(RemediationExecutionJob.id).label("count"))
        .where(RemediationExecutionJob.tenant_id == tenant_id)
        .group_by(RemediationExecutionJob.status),
        "status",
    )
    posture = "needs review" if plan_status.get("approval_requested", 0) or plan_status.get("failed", 0) else "evidence-supported posture"
    return _response(
        tenant_id,
        posture,
        counts={"plans": plan_count or 0, "execution_jobs": job_count or 0, "verified_results": verified_count or 0},
        status_counts={**{f"plan_{k}": v for k, v in plan_status.items()}, **{f"job_{k}": v for k, v in job_status.items()}},
    )


async def _integration_health(db: AsyncSession, tenant_id: uuid.UUID) -> TrustPostureResponse:
    total = await db.scalar(select(func.count(CloudIntegration.id)).where(CloudIntegration.tenant_id == tenant_id))
    status = await _counts_by(
        db,
        select(CloudIntegration.status.label("status"), func.count(CloudIntegration.id).label("count"))
        .where(CloudIntegration.tenant_id == tenant_id)
        .group_by(CloudIntegration.status),
        "status",
    )
    provider = await _counts_by(
        db,
        select(CloudIntegration.provider_type.label("provider_type"), func.count(CloudIntegration.id).label("count"))
        .where(CloudIntegration.tenant_id == tenant_id)
        .group_by(CloudIntegration.provider_type),
        "provider_type",
    )
    posture = "needs review" if status.get("error", 0) else "evidence-supported posture"
    return _response(tenant_id, posture, counts={"integrations": total or 0, "providers": provider}, status_counts=status)


@router.get("/overview", response_model=TrustOverviewResponse)
async def get_trust_overview(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(VIEW_TRUST_DASHBOARD)),
):
    await ensure_permission(db, tenant.id, current_user.id, VIEW_TRUST_DASHBOARD)
    await _emit_view(tenant.id, current_user.id, "overview")
    security = await _security_posture(db, tenant.id)
    compliance = await _compliance_posture(db, tenant.id)
    remediation = await _remediation_posture(db, tenant.id)
    integrations = await _integration_health(db, tenant.id)
    payload = sanitizer.sanitize_payload(
        {
            "tenant_id": tenant.id,
            "generated_at": datetime.now(timezone.utc),
            "language": POSTURE_LANGUAGE,
            "security_posture": security.model_dump(),
            "compliance_posture": compliance.model_dump(),
            "remediation_posture": remediation.model_dump(),
            "integration_health": integrations.model_dump(),
        }
    )
    payload.pop("sanitization_version", None)
    return TrustOverviewResponse(**payload)


@router.get("/security-posture", response_model=TrustPostureResponse)
async def get_security_posture(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(VIEW_TRUST_DASHBOARD)),
):
    await ensure_permission(db, tenant.id, current_user.id, VIEW_TRUST_DASHBOARD)
    await _emit_view(tenant.id, current_user.id, "security-posture")
    return await _security_posture(db, tenant.id)


@router.get("/compliance-posture", response_model=TrustPostureResponse)
async def get_compliance_posture(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(VIEW_TRUST_DASHBOARD)),
):
    await ensure_permission(db, tenant.id, current_user.id, VIEW_TRUST_DASHBOARD)
    await _emit_view(tenant.id, current_user.id, "compliance-posture")
    return await _compliance_posture(db, tenant.id)


@router.get("/remediation-posture", response_model=TrustPostureResponse)
async def get_remediation_posture(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(VIEW_TRUST_DASHBOARD)),
):
    await ensure_permission(db, tenant.id, current_user.id, VIEW_TRUST_DASHBOARD)
    await _emit_view(tenant.id, current_user.id, "remediation-posture")
    return await _remediation_posture(db, tenant.id)


@router.get("/integration-health", response_model=TrustPostureResponse)
async def get_integration_health(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(VIEW_TRUST_DASHBOARD)),
):
    await ensure_permission(db, tenant.id, current_user.id, VIEW_TRUST_DASHBOARD)
    await _emit_view(tenant.id, current_user.id, "integration-health")
    return await _integration_health(db, tenant.id)
