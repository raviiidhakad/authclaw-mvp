from __future__ import annotations

import uuid
from typing import Any

from fastapi import Depends
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_current_user, get_db
from app.core.exceptions import ForbiddenException, NotFoundException
from app.models.role import Role, UserRole
from app.models.tenant import Tenant
from app.models.trust import ExportManifest, ExternalShareLink, ReportAccessLog, ReportArtifact, ReportRun, ReportTemplate
from app.models.user import User
from app.schemas.trust import (
    ExportManifestResponse,
    ReportAccessLogResponse,
    ReportArtifactMetadataResponse,
    ReportRunResponse,
    ReportTemplateResponse,
    ShareLinkResponse,
)
from app.services.trust_reporting import ExportSanitizer, has_permission


sanitizer = ExportSanitizer()


async def set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


async def user_role_names(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> set[str]:
    rows = (
        await db.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.tenant_id == tenant_id, UserRole.user_id == user_id)
        )
    ).scalars().all()
    return set(rows)


async def ensure_permission(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID, action: str) -> None:
    await set_tenant_context(db, tenant_id)
    roles = await user_role_names(db, tenant_id, user_id)
    if not has_permission(roles, action):
        raise ForbiddenException(detail=f"Permission required: {action}")


def require_trust_permission(action: str):
    async def checker(
        current_user: User = Depends(get_current_user),
        tenant: Tenant = Depends(get_current_tenant),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        await ensure_permission(db, tenant.id, current_user.id, action)
        return current_user

    return checker


def template_response(template: ReportTemplate) -> ReportTemplateResponse:
    payload = sanitizer.sanitize_payload(
        {
            "id": template.id,
            "tenant_id": template.tenant_id,
            "name": template.name,
            "type": template.type,
            "format": template.format,
            "filters_schema": template.filters_schema or {},
            "default_sections": template.default_sections or [],
            "created_by": template.created_by,
            "created_at": template.created_at,
            "updated_at": template.updated_at,
            "is_system": template.is_system,
        }
    )
    payload.pop("sanitization_version", None)
    return ReportTemplateResponse(**payload)


def artifact_response(artifact: ReportArtifact, manifest: ExportManifest | None = None) -> ReportArtifactMetadataResponse:
    payload = sanitizer.sanitize_payload(
        {
            "id": artifact.id,
            "tenant_id": artifact.tenant_id,
            "run_id": artifact.run_id,
            "artifact_type": artifact.artifact_type,
            "content_hash": artifact.content_hash,
            "size_bytes": artifact.size_bytes,
            "sanitization_version": artifact.sanitization_version,
            "created_at": artifact.created_at,
            "expires_at": artifact.expires_at,
            "manifest_hash": manifest.manifest_hash if manifest else None,
        }
    )
    return ReportArtifactMetadataResponse(**payload)


def manifest_response(manifest: ExportManifest) -> ExportManifestResponse:
    payload = sanitizer.sanitize_payload(
        {
            "id": manifest.id,
            "tenant_id": manifest.tenant_id,
            "artifact_id": manifest.artifact_id,
            "manifest_json": manifest.manifest_json or {},
            "manifest_hash": manifest.manifest_hash,
            "hash_algorithm": manifest.hash_algorithm,
            "created_at": manifest.created_at,
        }
    )
    payload.pop("sanitization_version", None)
    return ExportManifestResponse(**payload)


async def run_response(db: AsyncSession, run: ReportRun) -> ReportRunResponse:
    artifacts = (
        await db.execute(select(ReportArtifact).where(ReportArtifact.tenant_id == run.tenant_id, ReportArtifact.run_id == run.id))
    ).scalars().all()
    manifests_by_artifact: dict[uuid.UUID, ExportManifest] = {}
    if artifacts:
        manifests = (
            await db.execute(
                select(ExportManifest).where(
                    ExportManifest.tenant_id == run.tenant_id,
                    ExportManifest.artifact_id.in_([item.id for item in artifacts]),
                )
            )
        ).scalars().all()
        manifests_by_artifact = {item.artifact_id: item for item in manifests}
    artifact_items = [artifact_response(item, manifests_by_artifact.get(item.id)) for item in artifacts]
    payload = sanitizer.sanitize_payload(
        {
            "id": run.id,
            "tenant_id": run.tenant_id,
            "template_id": run.template_id,
            "requested_by": run.requested_by,
            "status": getattr(run.status, "value", run.status),
            "filters": run.filters or {},
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "failed_reason": run.failed_reason,
            "expires_at": run.expires_at,
            "artifacts": [item.model_dump(mode="json") for item in artifact_items],
            "manifest_hash": artifact_items[0].manifest_hash if artifact_items else None,
        }
    )
    payload.pop("sanitization_version", None)
    return ReportRunResponse(**payload)


def access_log_response(row: ReportAccessLog) -> ReportAccessLogResponse:
    payload = sanitizer.sanitize_payload(
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "artifact_id": row.artifact_id,
            "actor_user_id": row.actor_user_id,
            "external_share_id": row.external_share_id,
            "action": row.action,
            "ip_hash": row.ip_hash,
            "user_agent_hash": row.user_agent_hash,
            "created_at": row.created_at,
        }
    )
    payload.pop("sanitization_version", None)
    return ReportAccessLogResponse(**payload)


def share_link_response(row: ExternalShareLink) -> ShareLinkResponse:
    payload = sanitizer.sanitize_payload(
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "artifact_id": row.artifact_id,
            "scope": row.scope or {},
            "created_by": row.created_by,
            "expires_at": row.expires_at,
            "revoked_at": row.revoked_at,
            "max_downloads": row.max_downloads,
        }
    )
    payload.pop("sanitization_version", None)
    return ShareLinkResponse(**payload)


async def template_or_404(db: AsyncSession, tenant_id: uuid.UUID, template_id: uuid.UUID) -> ReportTemplate:
    row = (
        await db.execute(select(ReportTemplate).where(ReportTemplate.tenant_id == tenant_id, ReportTemplate.id == template_id))
    ).scalars().first()
    if row is None:
        raise NotFoundException(detail="Report template not found")
    return row


async def run_or_404(db: AsyncSession, tenant_id: uuid.UUID, run_id: uuid.UUID) -> ReportRun:
    row = (await db.execute(select(ReportRun).where(ReportRun.tenant_id == tenant_id, ReportRun.id == run_id))).scalars().first()
    if row is None:
        raise NotFoundException(detail="Report run not found")
    return row


async def artifact_or_404(db: AsyncSession, tenant_id: uuid.UUID, artifact_id: uuid.UUID) -> ReportArtifact:
    row = (
        await db.execute(select(ReportArtifact).where(ReportArtifact.tenant_id == tenant_id, ReportArtifact.id == artifact_id))
    ).scalars().first()
    if row is None:
        raise NotFoundException(detail="Report artifact not found")
    return row


async def manifest_for_artifact_or_404(db: AsyncSession, tenant_id: uuid.UUID, artifact_id: uuid.UUID) -> ExportManifest:
    row = (
        await db.execute(
            select(ExportManifest).where(ExportManifest.tenant_id == tenant_id, ExportManifest.artifact_id == artifact_id)
        )
    ).scalars().first()
    if row is None:
        raise NotFoundException(detail="Export manifest not found")
    return row


async def share_link_or_404(db: AsyncSession, tenant_id: uuid.UUID, share_id: uuid.UUID) -> ExternalShareLink:
    row = (
        await db.execute(select(ExternalShareLink).where(ExternalShareLink.tenant_id == tenant_id, ExternalShareLink.id == share_id))
    ).scalars().first()
    if row is None:
        raise NotFoundException(detail="Share link not found")
    return row
