from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db, require_roles
from app.core.exceptions import BadRequestException, NotFoundException
from app.core.events.producer import producer
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.events import FindingStatusChangedEvent
from app.schemas.finding import FindingListResponse, FindingResponse, FindingStatusUpdate
from app.services.api_safety import sanitize_text
from app.services.findings_context import FindingsContextBuilder, SEVERITY_ORDER

logger = logging.getLogger(__name__)
router = APIRouter()

FINDING_EVENTS_TOPIC = "authclaw.finding.events"
ALLOWED_STATUS_TRANSITIONS = {
    (FindingStatus.active, FindingStatus.suppressed),
    (FindingStatus.suppressed, FindingStatus.active),
    (FindingStatus.active, FindingStatus.resolved),
}


async def _publish_event(event) -> None:
    try:
        await producer.publish(FINDING_EVENTS_TOPIC, event)
    except Exception as exc:
        logger.warning("Failed to publish finding event %s: %s", event.event_type, exc)


async def _finding_rows_for_tenant(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    provider_type: CloudProvider | None = None,
    integration_id: uuid.UUID | None = None,
    severity: FindingSeverity | None = None,
    status: FindingStatus | None = None,
) -> list[tuple[SecurityFinding, CloudProvider]]:
    query = (
        select(SecurityFinding, CloudIntegration.provider_type)
        .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
        .where(CloudIntegration.tenant_id == tenant_id)
    )
    if provider_type is not None:
        query = query.where(CloudIntegration.provider_type == provider_type)
    if integration_id is not None:
        query = query.where(CloudIntegration.id == integration_id)
    if severity is not None:
        query = query.where(SecurityFinding.severity == severity)
    if status is not None:
        query = query.where(SecurityFinding.status == status)

    result = await db.execute(query)
    return list(result.all())


def _service_for(finding: SecurityFinding, provider_type: CloudProvider) -> str:
    builder = FindingsContextBuilder(db=None)
    return builder._infer_service(provider_type.value, finding.resource_id, finding.title)


def _finding_response(finding: SecurityFinding, provider_type: CloudProvider) -> FindingResponse:
    service = _service_for(finding, provider_type)
    return FindingResponse(
        id=finding.id,
        integration_id=finding.integration_id,
        provider_type=provider_type,
        dedup_hash=finding.dedup_hash,
        external_id=sanitize_text(finding.external_id),
        resource_id=sanitize_text(finding.resource_id),
        title=sanitize_text(finding.title),
        description=sanitize_text(finding.description) if finding.description else None,
        remediation_instructions=sanitize_text(finding.remediation_instructions)
        if finding.remediation_instructions
        else None,
        severity=finding.severity,
        status=finding.status,
        resolved_at=finding.resolved_at,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        compliance_tags=[],
        service=service,
    )


def _sort_key(row: tuple[SecurityFinding, CloudProvider]) -> tuple[int, datetime, datetime]:
    finding = row[0]
    severity_value = finding.severity.value if isinstance(finding.severity, FindingSeverity) else str(finding.severity)
    return (
        SEVERITY_ORDER.get(severity_value, 0),
        finding.updated_at or datetime.min,
        finding.created_at or datetime.min,
    )


@router.get("", response_model=FindingListResponse)
async def list_findings(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    provider_type: CloudProvider | None = None,
    integration_id: uuid.UUID | None = None,
    severity: FindingSeverity | None = None,
    status: FindingStatus | None = None,
    service: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    rows = await _finding_rows_for_tenant(
        db,
        tenant.id,
        provider_type=provider_type,
        integration_id=integration_id,
        severity=severity,
        status=status,
    )
    if service:
        normalized_service = service.strip().lower()
        rows = [
            row
            for row in rows
            if _service_for(row[0], row[1]).lower() == normalized_service
        ]

    rows = sorted(rows, key=_sort_key, reverse=True)
    total = len(rows)
    paged = rows[skip : skip + limit]
    return FindingListResponse(
        items=[_finding_response(finding, provider) for finding, provider in paged],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    finding, provider = await _get_finding_or_404(finding_id, tenant.id, db)
    return _finding_response(finding, provider)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    finding, provider = await _get_finding_or_404(finding_id, tenant.id, db)
    old_status = finding.status
    transition = (old_status, body.status)
    if transition not in ALLOWED_STATUS_TRANSITIONS:
        raise BadRequestException(
            detail=f"Finding status transition {old_status.value}->{body.status.value} is not allowed"
        )

    finding.status = body.status
    if body.status == FindingStatus.resolved:
        finding.resolved_at = datetime.now(timezone.utc)
    elif body.status == FindingStatus.active:
        finding.resolved_at = None

    await db.flush()
    await db.refresh(finding)
    await db.commit()
    await _publish_event(
        FindingStatusChangedEvent(
            tenant_id=str(tenant.id),
            finding_id=str(finding.id),
            integration_id=str(finding.integration_id),
            provider_type=provider.value,
            old_status=old_status.value,
            new_status=body.status.value,
            actor_id=str(current_user.id),
        )
    )
    return _finding_response(finding, provider)


async def _get_finding_or_404(
    finding_id: uuid.UUID,
    tenant_id: uuid.UUID,
    db: AsyncSession,
) -> tuple[SecurityFinding, CloudProvider]:
    result = await db.execute(
        select(SecurityFinding, CloudIntegration.provider_type)
        .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
        .where(
            SecurityFinding.id == finding_id,
            CloudIntegration.tenant_id == tenant_id,
        )
    )
    row = result.first()
    if not row:
        raise NotFoundException(detail="Finding not found")
    return row[0], row[1]
