from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db
from app.api.v1.endpoints.trust_common import (
    access_log_response,
    artifact_or_404,
    artifact_response,
    ensure_permission,
    manifest_for_artifact_or_404,
    manifest_response,
    require_trust_permission,
    run_or_404,
    run_response,
    sanitizer,
    set_tenant_context,
    template_or_404,
    template_response,
)
from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException
from app.models.tenant import Tenant
from app.models.trust import ExportManifest, ReportAccessLog, ReportArtifact, ReportRun, ReportRunStatus, ReportTemplate
from app.models.user import User
from app.schemas.events import ReportDownloadedEvent
from app.schemas.trust import (
    ExportManifestResponse,
    ReportAccessLogListResponse,
    ReportArtifactDownloadResponse,
    ReportArtifactListResponse,
    ReportArtifactMetadataResponse,
    ReportRunCreateRequest,
    ReportRunListResponse,
    ReportRunResponse,
    ReportTemplateCreate,
    ReportTemplateListResponse,
    ReportTemplateResponse,
    ReportTemplateUpdate,
)
from app.services.trust_reporting import (
    DOWNLOAD_REPORT,
    GENERATE_REPORT,
    MANAGE_REPORT_TEMPLATES,
    VIEW_REPORT_ACCESS_LOGS,
    LocalReportArtifactStore,
    ReportGenerationRequest,
    ReportGenerationService,
    TRUST_EVENTS_TOPIC,
    hash_access_metadata,
    sanitized_event_payload,
)

router = APIRouter()
event_producer = default_event_producer


@router.get("/templates", response_model=ReportTemplateListResponse)
async def list_templates(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    type: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, GENERATE_REPORT)
    query = select(ReportTemplate).where(ReportTemplate.tenant_id == tenant.id)
    if type:
        query = query.where(ReportTemplate.type == sanitizer.sanitize(type))
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(ReportTemplate.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    return ReportTemplateListResponse(items=[template_response(row) for row in rows], total=total or 0, skip=skip, limit=limit)


@router.get("/templates/{template_id}", response_model=ReportTemplateResponse)
async def get_template(
    template_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, GENERATE_REPORT)
    return template_response(await template_or_404(db, tenant.id, template_id))


@router.post("/templates", response_model=ReportTemplateResponse, status_code=201)
async def create_template(
    body: ReportTemplateCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(MANAGE_REPORT_TEMPLATES)),
):
    await ensure_permission(db, tenant.id, current_user.id, MANAGE_REPORT_TEMPLATES)
    payload = sanitizer.sanitize_payload(body.model_dump())
    payload.pop("sanitization_version", None)
    template = ReportTemplate(
        tenant_id=tenant.id,
        name=payload["name"],
        type=payload["type"],
        format=payload["format"],
        filters_schema=payload["filters_schema"],
        default_sections=payload["default_sections"],
        created_by=current_user.id,
        is_system=payload["is_system"],
    )
    db.add(template)
    await db.commit()
    await set_tenant_context(db, tenant.id)
    return template_response(template)


@router.patch("/templates/{template_id}", response_model=ReportTemplateResponse)
async def update_template(
    template_id: uuid.UUID,
    body: ReportTemplateUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(MANAGE_REPORT_TEMPLATES)),
):
    await ensure_permission(db, tenant.id, _user.id, MANAGE_REPORT_TEMPLATES)
    template = await template_or_404(db, tenant.id, template_id)
    updates = sanitizer.sanitize_payload(body.model_dump(exclude_unset=True))
    updates.pop("sanitization_version", None)
    for key, value in updates.items():
        setattr(template, key, value)
    await db.commit()
    await set_tenant_context(db, tenant.id)
    return template_response(template)


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template(
    template_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(MANAGE_REPORT_TEMPLATES)),
):
    await ensure_permission(db, tenant.id, _user.id, MANAGE_REPORT_TEMPLATES)
    template = await template_or_404(db, tenant.id, template_id)
    await db.delete(template)
    await db.commit()
    return None


@router.post("/run", response_model=ReportRunResponse, status_code=201)
async def create_report_run(
    body: ReportRunCreateRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, current_user.id, GENERATE_REPORT)
    if body.template_id:
        await template_or_404(db, tenant.id, body.template_id)
    result = await ReportGenerationService(db, event_producer=event_producer).generate_report(
        tenant.id,
        ReportGenerationRequest(
            report_type=body.report_type,
            template_id=body.template_id,
            requested_by=current_user.id,
            filters=body.filters,
            retention_days=body.retention_days,
        ),
    )
    await db.commit()
    await set_tenant_context(db, tenant.id)
    return await run_response(db, result.report_run)


@router.get("/runs", response_model=ReportRunListResponse)
async def list_report_runs(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    status: ReportRunStatus | None = None,
    template_id: uuid.UUID | None = None,
    requested_by: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    report_type: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, GENERATE_REPORT)
    query = select(ReportRun).where(ReportRun.tenant_id == tenant.id)
    if status:
        query = query.where(ReportRun.status == status)
    if template_id:
        query = query.where(ReportRun.template_id == template_id)
    if requested_by:
        query = query.where(ReportRun.requested_by == requested_by)
    if date_from:
        query = query.where(ReportRun.started_at >= date_from)
    if date_to:
        query = query.where(ReportRun.started_at <= date_to)
    rows = (await db.execute(query.order_by(ReportRun.started_at.desc().nullslast(), ReportRun.id.desc()))).scalars().all()
    if report_type:
        safe_type = sanitizer.sanitize(report_type)
        rows = [row for row in rows if (row.filters or {}).get("report_type") == safe_type]
    total = len(rows)
    page = rows[skip : skip + limit]
    return ReportRunListResponse(items=[await run_response(db, row) for row in page], total=total, skip=skip, limit=limit)


@router.get("/runs/{run_id}", response_model=ReportRunResponse)
async def get_report_run(
    run_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(GENERATE_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, GENERATE_REPORT)
    return await run_response(db, await run_or_404(db, tenant.id, run_id))


@router.get("/artifacts", response_model=ReportArtifactListResponse)
async def list_artifacts(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    run_id: uuid.UUID | None = None,
    artifact_type: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(DOWNLOAD_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, DOWNLOAD_REPORT)
    query = select(ReportArtifact).where(ReportArtifact.tenant_id == tenant.id)
    if run_id:
        query = query.where(ReportArtifact.run_id == run_id)
    if artifact_type:
        query = query.where(ReportArtifact.artifact_type == sanitizer.sanitize(artifact_type))
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(ReportArtifact.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    manifests = {}
    if rows:
        manifest_rows = (
            await db.execute(
                select(ExportManifest).where(ExportManifest.tenant_id == tenant.id, ExportManifest.artifact_id.in_([row.id for row in rows]))
            )
        ).scalars().all()
        manifests = {row.artifact_id: row for row in manifest_rows}
    return ReportArtifactListResponse(
        items=[artifact_response(row, manifests.get(row.id)) for row in rows],
        total=total or 0,
        skip=skip,
        limit=limit,
    )


@router.get("/artifacts/{artifact_id}", response_model=ReportArtifactMetadataResponse)
async def get_artifact(
    artifact_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(DOWNLOAD_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, DOWNLOAD_REPORT)
    artifact = await artifact_or_404(db, tenant.id, artifact_id)
    manifest = (
        await db.execute(select(ExportManifest).where(ExportManifest.tenant_id == tenant.id, ExportManifest.artifact_id == artifact.id))
    ).scalars().first()
    return artifact_response(artifact, manifest)


@router.get("/artifacts/{artifact_id}/manifest", response_model=ExportManifestResponse)
async def get_artifact_manifest(
    artifact_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(DOWNLOAD_REPORT)),
):
    await ensure_permission(db, tenant.id, _user.id, DOWNLOAD_REPORT)
    await artifact_or_404(db, tenant.id, artifact_id)
    return manifest_response(await manifest_for_artifact_or_404(db, tenant.id, artifact_id))


@router.get("/artifacts/{artifact_id}/download", response_model=ReportArtifactDownloadResponse)
async def download_artifact(
    artifact_id: uuid.UUID,
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_trust_permission(DOWNLOAD_REPORT)),
):
    await ensure_permission(db, tenant.id, current_user.id, DOWNLOAD_REPORT)
    artifact = await artifact_or_404(db, tenant.id, artifact_id)
    run = await run_or_404(db, tenant.id, artifact.run_id)
    if run.status != ReportRunStatus.completed:
        raise BadRequestException(detail="Report artifact is not ready for download")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if artifact.expires_at is not None and artifact.expires_at <= now:
        raise BadRequestException(detail="Report artifact has expired")
    manifest = await manifest_for_artifact_or_404(db, tenant.id, artifact.id)
    stored_payload = LocalReportArtifactStore().read_json(artifact.storage_key)
    safe_artifact = sanitizer.sanitize_payload(stored_payload)
    watermark = sanitizer.sanitize_payload(
        {
            "tenant_id": tenant.id,
            "requester_id": current_user.id,
            "artifact_id": artifact.id,
            "generated_at": artifact.created_at,
            "downloaded_at": datetime.now(timezone.utc),
            "manifest_hash": manifest.manifest_hash,
            "language": "evidence-supported posture; needs review",
        }
    )
    watermark.pop("sanitization_version", None)
    access_log = ReportAccessLog(
        tenant_id=tenant.id,
        artifact_id=artifact.id,
        actor_user_id=current_user.id,
        action="download",
        ip_hash=hash_access_metadata(request.client.host if request.client else None),
        user_agent_hash=hash_access_metadata(request.headers.get("user-agent")),
    )
    db.add(access_log)
    await db.flush()
    if event_producer is not None:
        await event_producer.publish(
            TRUST_EVENTS_TOPIC,
            ReportDownloadedEvent(
                tenant_id=tenant.id,
                actor_id=current_user.id,
                artifact_id=artifact.id,
                access_log_id=access_log.id,
                payload=sanitized_event_payload(
                    {
                        "artifact_id": artifact.id,
                        "content_hash": artifact.content_hash,
                        "manifest_hash": manifest.manifest_hash,
                        "size_bytes": artifact.size_bytes,
                        "content_type": "application/json",
                    }
                ),
            ),
        )
    await db.commit()
    await set_tenant_context(db, tenant.id)
    return ReportArtifactDownloadResponse(
        artifact_id=artifact.id,
        tenant_id=tenant.id,
        requester_id=current_user.id,
        downloaded_at=watermark["downloaded_at"],
        manifest_hash=manifest.manifest_hash,
        watermark=watermark,
        artifact=safe_artifact,
    )


@router.get("/access-logs", response_model=ReportAccessLogListResponse)
async def list_access_logs(
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    artifact_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(VIEW_REPORT_ACCESS_LOGS)),
):
    await ensure_permission(db, tenant.id, _user.id, VIEW_REPORT_ACCESS_LOGS)
    query = select(ReportAccessLog).where(ReportAccessLog.tenant_id == tenant.id)
    if artifact_id:
        query = query.where(ReportAccessLog.artifact_id == artifact_id)
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.execute(query.order_by(ReportAccessLog.created_at.desc()).offset(skip).limit(limit))).scalars().all()
    return ReportAccessLogListResponse(items=[access_log_response(row) for row in rows], total=total or 0, skip=skip, limit=limit)


@router.get("/artifacts/{artifact_id}/access-logs", response_model=ReportAccessLogListResponse)
async def list_artifact_access_logs(
    artifact_id: uuid.UUID,
    skip: int = 0,
    limit: int = Query(50, ge=1, le=200),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_trust_permission(VIEW_REPORT_ACCESS_LOGS)),
):
    await ensure_permission(db, tenant.id, _user.id, VIEW_REPORT_ACCESS_LOGS)
    await artifact_or_404(db, tenant.id, artifact_id)
    return await list_access_logs(skip=skip, limit=limit, artifact_id=artifact_id, tenant=tenant, db=db, _user=_user)


async def assert_download_permission(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    await ensure_permission(db, tenant_id, user_id, DOWNLOAD_REPORT)
