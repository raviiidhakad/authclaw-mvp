from __future__ import annotations

import uuid
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db
from app.api.v1.endpoints.trust_common import (
    artifact_or_404,
    ensure_permission,
    require_trust_permission,
    set_tenant_context,
    share_link_or_404,
    share_link_response,
    sanitizer,
)
from app.core.config import settings
from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException, ForbiddenException
from app.models.compliance import ComplianceAssessment, ComplianceGap, EvidenceItem
from app.models.finding import SecurityFinding
from app.models.integration import CloudIntegration
from app.models.remediation import RemediationExecutionJob, RemediationPlan, RemediationVerificationResult
from app.models.tenant import Tenant
from app.models.trust import ExternalShareLink, ReportAccessLog, ReportRun, ReportRunStatus
from app.models.user import User
from app.schemas.events import ShareLinkCreatedEvent, ShareLinkRevokedEvent, TrustCenterViewedEvent
from app.schemas.trust import (
    ShareLinkCreateRequest,
    ShareLinkCreateResponse,
    ShareLinkListResponse,
    ShareLinkResponse,
    TrustOverviewResponse,
    TrustPostureResponse,
)
from app.services.trust_reporting import (
    CREATE_SHARE_LINK,
    REVOKE_SHARE_LINK,
    TRUST_EVENTS_TOPIC,
    VIEW_TRUST_DASHBOARD,
    hash_access_metadata,
    hash_share_token,
    sanitized_event_payload,
)

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


def _sharing_enabled_or_403() -> None:
    if not settings.ENABLE_EXTERNAL_TRUST_SHARING:
        raise ForbiddenException(detail="External trust sharing is disabled")


def _normalize_expiry(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


async def _assert_shareable_artifact(db: AsyncSession, tenant_id: uuid.UUID, artifact_id: uuid.UUID):
    artifact = await artifact_or_404(db, tenant_id, artifact_id)
    run = (await db.execute(select(ReportRun).where(ReportRun.tenant_id == tenant_id, ReportRun.id == artifact.run_id))).scalars().first()
    if run is None or run.status != ReportRunStatus.completed:
        raise BadRequestException(detail="Only completed sanitized artifacts can be shared")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if artifact.expires_at is not None and artifact.expires_at <= now:
        raise BadRequestException(detail="Expired artifacts cannot be shared")
    return artifact


@router.post("/share-links", response_model=ShareLinkCreateResponse, status_code=201)
async def create_share_link(
    body: ShareLinkCreateRequest,
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(CREATE_SHARE_LINK)),
):
    _sharing_enabled_or_403()
    await ensure_permission(db, tenant.id, current_user.id, CREATE_SHARE_LINK)
    artifact = await _assert_shareable_artifact(db, tenant.id, body.artifact_id)
    expires_at = _normalize_expiry(body.expires_at)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    max_expiry = now + timedelta(days=settings.EXTERNAL_TRUST_SHARING_MAX_EXPIRY_DAYS)
    if expires_at <= now:
        raise BadRequestException(detail="Share link expiry must be in the future")
    if expires_at > max_expiry:
        raise BadRequestException(detail="Share link expiry exceeds maximum allowed window")

    token = secrets.token_urlsafe(32)
    scope = sanitizer.sanitize_payload(
        {
            "scope_type": "artifact",
            "artifact_id": artifact.id,
            "access": "read_only",
            "content_type": "application/json",
        }
    )
    scope.pop("sanitization_version", None)
    share_link = ExternalShareLink(
        tenant_id=tenant.id,
        artifact_id=artifact.id,
        token_hash=hash_share_token(token),
        scope=scope,
        created_by=current_user.id,
        expires_at=expires_at,
        max_downloads=body.max_downloads,
    )
    db.add(share_link)
    await db.flush()
    db.add(
        ReportAccessLog(
            tenant_id=tenant.id,
            artifact_id=artifact.id,
            actor_user_id=current_user.id,
            external_share_id=share_link.id,
            action="share_created",
            ip_hash=hash_access_metadata(request.client.host if request.client else None),
            user_agent_hash=hash_access_metadata(request.headers.get("user-agent")),
        )
    )
    await db.flush()
    if event_producer is not None:
        await event_producer.publish(
            TRUST_EVENTS_TOPIC,
            ShareLinkCreatedEvent(
                tenant_id=tenant.id,
                actor_id=current_user.id,
                artifact_id=artifact.id,
                share_link_id=share_link.id,
                expires_at=share_link.expires_at,
                payload=sanitized_event_payload(
                    {
                        "artifact_id": artifact.id,
                        "share_link_id": share_link.id,
                        "scope": share_link.scope,
                        "max_downloads": share_link.max_downloads,
                    }
                ),
            ),
        )
    await db.commit()
    await set_tenant_context(db, tenant.id)
    response = share_link_response(share_link).model_dump()
    response["token"] = token
    return ShareLinkCreateResponse(**response)


@router.get("/share-links", response_model=ShareLinkListResponse)
async def list_share_links(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    artifact_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(CREATE_SHARE_LINK)),
):
    _sharing_enabled_or_403()
    await ensure_permission(db, tenant.id, current_user.id, CREATE_SHARE_LINK)
    query = select(ExternalShareLink).where(ExternalShareLink.tenant_id == tenant.id)
    if artifact_id:
        query = query.where(ExternalShareLink.artifact_id == artifact_id)
    rows = (await db.execute(query.order_by(ExternalShareLink.expires_at.desc(), ExternalShareLink.id.desc()))).scalars().all()
    page = rows[skip : skip + limit]
    return ShareLinkListResponse(items=[share_link_response(row) for row in page], total=len(rows), skip=skip, limit=limit)


@router.post("/share-links/{share_id}/revoke", response_model=ShareLinkResponse)
async def revoke_share_link(
    share_id: uuid.UUID,
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(REVOKE_SHARE_LINK)),
):
    _sharing_enabled_or_403()
    await ensure_permission(db, tenant.id, current_user.id, REVOKE_SHARE_LINK)
    share_link = await share_link_or_404(db, tenant.id, share_id)
    if share_link.revoked_at is None:
        share_link.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(
        ReportAccessLog(
            tenant_id=tenant.id,
            artifact_id=share_link.artifact_id,
            actor_user_id=current_user.id,
            external_share_id=share_link.id,
            action="share_revoked",
            ip_hash=hash_access_metadata(request.client.host if request.client else None),
            user_agent_hash=hash_access_metadata(request.headers.get("user-agent")),
        )
    )
    await db.flush()
    if event_producer is not None:
        await event_producer.publish(
            TRUST_EVENTS_TOPIC,
            ShareLinkRevokedEvent(
                tenant_id=tenant.id,
                actor_id=current_user.id,
                artifact_id=share_link.artifact_id,
                share_link_id=share_link.id,
                payload=sanitized_event_payload({"share_link_id": share_link.id, "artifact_id": share_link.artifact_id}),
            ),
        )
    await db.commit()
    await set_tenant_context(db, tenant.id)
    return share_link_response(share_link)
