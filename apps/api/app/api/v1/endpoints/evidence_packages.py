from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db
from app.api.v1.endpoints.trust_common import (
    ensure_permission,
    manifest_response,
    require_trust_permission,
    run_or_404,
    run_response,
    set_tenant_context,
)
from app.core.events.producer import producer as default_event_producer
from app.models.tenant import Tenant
from app.models.trust import ExportManifest, ReportRun, ReportRunStatus
from app.models.user import User
from app.schemas.trust import EvidencePackageCreateRequest, EvidencePackageListResponse, EvidencePackageResponse
from app.services.trust_reporting import EvidencePackageBuilder, EvidencePackageRequest, GENERATE_REPORT

router = APIRouter()
event_producer = default_event_producer


@router.post("", response_model=EvidencePackageResponse, status_code=201)
async def create_evidence_package(
    body: EvidencePackageCreateRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, current_user.id, GENERATE_REPORT)
    result = await EvidencePackageBuilder(db, event_producer=event_producer).create_evidence_package(
        tenant.id,
        EvidencePackageRequest(
            framework_id=body.framework_id,
            control_ids=body.control_ids,
            date_from=body.date_from,
            date_to=body.date_to,
            evidence_freshness_days=body.evidence_freshness_days,
            include_findings=body.include_findings,
            include_remediation=body.include_remediation,
            output_format=body.output_format,
            template_id=body.template_id,
            requested_by=current_user.id,
            retention_days=body.retention_days,
        ),
    )
    await db.commit()
    await set_tenant_context(db, tenant.id)
    manifest = result.manifest
    return EvidencePackageResponse(
        run=await run_response(db, result.report_run),
        artifact=None if result.artifact is None else (await run_response(db, result.report_run)).artifacts[0],
        manifest=manifest_response(manifest) if manifest else None,
    )


@router.get("", response_model=EvidencePackageListResponse)
async def list_evidence_packages(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    status: ReportRunStatus | None = None,
    framework_id: uuid.UUID | None = None,
    control_id: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, GENERATE_REPORT)
    query = select(ReportRun).where(ReportRun.tenant_id == tenant.id)
    if status:
        query = query.where(ReportRun.status == status)
    if date_from:
        query = query.where(ReportRun.started_at >= date_from)
    if date_to:
        query = query.where(ReportRun.started_at <= date_to)
    rows = (await db.execute(query.order_by(ReportRun.started_at.desc().nullslast(), ReportRun.id.desc()))).scalars().all()
    rows = [row for row in rows if (row.filters or {}).get("report_type") == "evidence_package"]
    if framework_id:
        rows = [row for row in rows if ((row.filters or {}).get("filters") or {}).get("framework_id") == str(framework_id)]
    if control_id:
        rows = [
            row
            for row in rows
            if str(control_id) in (((row.filters or {}).get("filters") or {}).get("control_ids") or [])
        ]
    total = len(rows)
    page = rows[skip : skip + limit]
    return EvidencePackageListResponse(items=[await run_response(db, row) for row in page], total=total, skip=skip, limit=limit)


@router.get("/{package_id}", response_model=EvidencePackageResponse)
async def get_evidence_package(
    package_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, GENERATE_REPORT)
    run = await run_or_404(db, tenant.id, package_id)
    if (run.filters or {}).get("report_type") != "evidence_package":
        from app.core.exceptions import NotFoundException

        raise NotFoundException(detail="Evidence package not found")
    response = await run_response(db, run)
    manifest = None
    if response.artifacts:
        manifest = (
            await db.execute(
                select(ExportManifest).where(
                    ExportManifest.tenant_id == tenant.id,
                    ExportManifest.artifact_id == response.artifacts[0].id,
                )
            )
        ).scalars().first()
    return EvidencePackageResponse(
        run=response,
        artifact=response.artifacts[0] if response.artifacts else None,
        manifest=manifest_response(manifest) if manifest else None,
    )
