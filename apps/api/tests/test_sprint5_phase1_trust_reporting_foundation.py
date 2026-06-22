from __future__ import annotations

import json
import os
import secrets
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import AsyncSessionLocal
from app.models import Base
from app.models.tenant import Tenant
from app.models.trust import (
    ExportManifest,
    ExternalShareLink,
    ReportAccessLog,
    ReportArtifact,
    ReportRun,
    ReportRunStatus,
    ReportTemplate,
    TrustNotification,
)
from app.schemas.events import (
    EvidencePackageCreatedEvent,
    ReportDownloadedEvent,
    ReportRunCompletedEvent,
    ReportRunFailedEvent,
    ReportRunStartedEvent,
    ShareLinkCreatedEvent,
    ShareLinkRevokedEvent,
    TrustCenterViewedEvent,
    NotificationCreatedEvent,
)
from app.services.trust_reporting import (
    CREATE_SHARE_LINK,
    DOWNLOAD_REPORT,
    EXPIRE_REPORT_ARTIFACT,
    GENERATE_REPORT,
    MANAGE_REPORT_TEMPLATES,
    REVOKE_SHARE_LINK,
    VIEW_REPORT_ACCESS_LOGS,
    VIEW_TRUST_DASHBOARD,
    build_manifest_hash,
    expiry_from_retention,
    has_permission,
    hash_access_metadata,
    hash_share_token,
    immutable_manifest_update_guard,
    sanitized_event_payload,
    validate_artifact_metadata,
)

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "5434"))
DB_NAME = os.environ.get("DB_NAME", "authclaw")
SUPERUSER_DSN = f"postgresql://postgres:password@{DB_HOST}:{DB_PORT}/{DB_NAME}"
APP_USER_DSN = f"postgresql://authclaw_app:authclaw_app_password@{DB_HOST}:{DB_PORT}/{DB_NAME}"

TRUST_TABLES = {
    "report_templates",
    "report_runs",
    "report_artifacts",
    "export_manifests",
    "external_share_links",
    "report_access_logs",
    "trust_notifications",
}

UNSAFE_TERMS = (
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_supersecretsecretsecretsecret",
    "raw_provider_payload",
    "super-secret",
    "vault://",
)


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint5-phase1-{suffix}",
        slug=f"sprint5-phase1-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _set_tenant(db, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await _set_tenant(db, tenant_id)
        for table in (
            "trust_notifications",
            "report_access_logs",
            "external_share_links",
            "export_manifests",
            "report_artifacts",
            "report_runs",
            "report_templates",
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


async def _report_lifecycle(db, tenant_id: uuid.UUID):
    await _set_tenant(db, tenant_id)
    template = ReportTemplate(
        tenant_id=tenant_id,
        name="Executive posture summary",
        type="executive_dashboard",
        format="json",
        filters_schema={"date_range": "last_30_days"},
        default_sections=["risk_posture", "compliance_posture"],
    )
    db.add(template)
    await db.flush()
    run = ReportRun(
        tenant_id=tenant_id,
        template_id=template.id,
        status=ReportRunStatus.completed,
        filters={"framework": "soc2"},
        started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
        expires_at=expiry_from_retention(30).replace(tzinfo=None),
    )
    db.add(run)
    await db.flush()
    artifact = ReportArtifact(
        tenant_id=tenant_id,
        run_id=run.id,
        artifact_type="json",
        storage_key=f"tenant/{tenant_id}/reports/{run.id}.json",
        content_hash="a" * 64,
        size_bytes=1024,
        sanitization_version="sprint5-phase1",
        expires_at=expiry_from_retention(30).replace(tzinfo=None),
    )
    db.add(artifact)
    await db.flush()
    manifest_json = {
        "artifact_id": str(artifact.id),
        "content_hash": artifact.content_hash,
        "sections": ["risk_posture", "compliance_posture"],
    }
    manifest = ExportManifest(
        tenant_id=tenant_id,
        artifact_id=artifact.id,
        manifest_json=manifest_json,
        manifest_hash=build_manifest_hash(manifest_json),
    )
    db.add(manifest)
    share_link = ExternalShareLink(
        tenant_id=tenant_id,
        artifact_id=artifact.id,
        token_hash=hash_share_token("demo-share-token"),
        scope={"artifact_id": str(artifact.id), "read_only": True},
        expires_at=expiry_from_retention(7).replace(tzinfo=None),
        max_downloads=1,
    )
    db.add(share_link)
    await db.flush()
    access = ReportAccessLog(
        tenant_id=tenant_id,
        artifact_id=artifact.id,
        external_share_id=share_link.id,
        action="download",
        ip_hash=hash_access_metadata("127.0.0.1"),
        user_agent_hash=hash_access_metadata("AuthClawTest/1.0"),
    )
    db.add(access)
    notification = TrustNotification(
        tenant_id=tenant_id,
        type="report_completed",
        severity="info",
        title="Report completed",
        body="Your evidence-supported report is ready for review.",
        resource_type="report_run",
        resource_id=run.id,
    )
    db.add(notification)
    await db.flush()
    return template, run, artifact, manifest, share_link, access, notification


def test_sprint5_phase1_models_are_registered_in_metadata():
    assert TRUST_TABLES <= set(Base.metadata.tables)
    assert ReportRunStatus.queued.value == "queued"
    assert ReportRunStatus.expired.value == "expired"


@pytest.mark.asyncio
async def test_sprint5_phase1_tables_exist_after_migration():
    conn = await asyncpg.connect(SUPERUSER_DSN)
    try:
        rows = await conn.fetch(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = ANY($1::text[])
            """,
            list(TRUST_TABLES),
        )
        assert {row["table_name"] for row in rows} == TRUST_TABLES

        enum_values = await conn.fetch(
            """
            SELECT enumlabel
            FROM pg_enum
            JOIN pg_type ON pg_type.oid = pg_enum.enumtypid
            WHERE typname = 'report_run_status'
            ORDER BY enumsortorder
            """
        )
        assert [row["enumlabel"] for row in enum_values] == ["queued", "running", "completed", "failed", "expired"]
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_report_model_relationships_and_manifest_uniqueness():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            template, run, artifact, manifest, share_link, access, notification = await _report_lifecycle(db, tenant.id)
            await db.flush()

            loaded_run = (await db.execute(select(ReportRun).where(ReportRun.id == run.id))).scalars().one()
            assert loaded_run.template_id == template.id
            assert artifact.run_id == loaded_run.id
            assert manifest.artifact_id == artifact.id
            assert share_link.artifact_id == artifact.id
            assert access.external_share_id == share_link.id
            assert notification.resource_id == run.id
            assert loaded_run.status == ReportRunStatus.completed

            duplicate = ExportManifest(
                tenant_id=tenant.id,
                artifact_id=artifact.id,
                manifest_json={"artifact_id": str(artifact.id)},
                manifest_hash=build_manifest_hash({"artifact_id": str(artifact.id)}),
            )
            db.add(duplicate)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
        finally:
            await _cleanup(db, tenant.id)


def test_sprint5_rbac_mapping_is_stricter_than_dashboard_view():
    assert has_permission({"viewer"}, VIEW_TRUST_DASHBOARD)
    assert not has_permission({"viewer"}, GENERATE_REPORT)
    assert not has_permission({"analyst"}, DOWNLOAD_REPORT)
    assert has_permission({"auditor"}, GENERATE_REPORT)
    assert has_permission({"auditor"}, DOWNLOAD_REPORT)
    assert has_permission({"admin"}, MANAGE_REPORT_TEMPLATES)
    assert not has_permission({"admin"}, CREATE_SHARE_LINK)
    assert has_permission({"owner"}, CREATE_SHARE_LINK)
    assert has_permission({"owner"}, REVOKE_SHARE_LINK)
    assert has_permission({"owner"}, EXPIRE_REPORT_ARTIFACT)
    assert has_permission({"auditor"}, VIEW_REPORT_ACCESS_LOGS)


def test_manifest_hash_determinism_and_immutability_guard():
    manifest_a = {"sections": ["a", "b"], "artifact": {"content_hash": "a" * 64, "size": 12}}
    manifest_b = {"artifact": {"size": 12, "content_hash": "a" * 64}, "sections": ["a", "b"]}
    expected_hash = build_manifest_hash(manifest_a)

    assert expected_hash == build_manifest_hash(manifest_b)
    immutable_manifest_update_guard(expected_hash, manifest_b)
    with pytest.raises(ValueError, match="immutable"):
        immutable_manifest_update_guard(expected_hash, {"sections": ["a", "b", "c"]})


def test_share_token_and_access_metadata_store_hashes_only():
    raw_token = "raw-share-token-please-do-not-store"
    token_hash = hash_share_token(raw_token)
    assert token_hash != raw_token
    assert len(token_hash) == 64
    assert hash_share_token(raw_token) == token_hash
    assert hash_access_metadata("127.0.0.1") != "127.0.0.1"
    with pytest.raises(ValueError):
        hash_share_token("")


def test_artifact_metadata_and_events_are_sanitized():
    unsafe_metadata = {
        "storage_key": "tenant/demo/reports/report.json",
        "vault_reference_id": "vault://tenant/demo/secret",
        "raw_provider_payload": {"token": "super-secret"},
        "content_hash": "b" * 64,
        "nested": {"api_key": "AKIAIOSFODNN7EXAMPLE"},
    }
    sanitized = validate_artifact_metadata(unsafe_metadata)
    serialized = json.dumps(sanitized, sort_keys=True)
    for term in UNSAFE_TERMS:
        assert term.lower() not in serialized.lower()
    assert sanitized["content_hash"] == "b" * 64

    tenant_id = uuid.uuid4()
    run_id = uuid.uuid4()
    artifact_id = uuid.uuid4()
    payload = sanitized_event_payload(unsafe_metadata)
    events = [
        ReportRunStartedEvent(tenant_id=tenant_id, report_run_id=run_id, payload=payload),
        ReportRunCompletedEvent(tenant_id=tenant_id, report_run_id=run_id, artifact_id=artifact_id, payload=payload),
        ReportRunFailedEvent(tenant_id=tenant_id, report_run_id=run_id, reason_category="generation_error", payload=payload),
        EvidencePackageCreatedEvent(
            tenant_id=tenant_id,
            report_run_id=run_id,
            artifact_id=artifact_id,
            manifest_hash="c" * 64,
            payload=payload,
        ),
        ReportDownloadedEvent(tenant_id=tenant_id, artifact_id=artifact_id, payload=payload),
        ShareLinkCreatedEvent(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            share_link_id=uuid.uuid4(),
            expires_at=expiry_from_retention(7),
            payload=payload,
        ),
        ShareLinkRevokedEvent(tenant_id=tenant_id, artifact_id=artifact_id, share_link_id=uuid.uuid4(), payload=payload),
        TrustCenterViewedEvent(tenant_id=tenant_id, payload=payload),
        NotificationCreatedEvent(tenant_id=tenant_id, notification_id=uuid.uuid4(), payload=payload),
    ]
    serialized_events = json.dumps([event.model_dump(mode="json") for event in events], sort_keys=True)
    for term in UNSAFE_TERMS:
        assert term.lower() not in serialized_events.lower()


@pytest.mark.asyncio
async def test_trust_reporting_rls_policy_and_cross_tenant_isolation():
    su = await asyncpg.connect(SUPERUSER_DSN)
    app = await asyncpg.connect(APP_USER_DSN)
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    template_a = uuid.uuid4()
    template_b = uuid.uuid4()
    try:
        await su.execute(
            """INSERT INTO tenants (id, name, slug, plan, status, settings, created_at, updated_at)
               VALUES ($1, 'sprint5-rls-a', $2, 'free', 'active', '{}'::jsonb, now(), now()),
                      ($3, 'sprint5-rls-b', $4, 'free', 'active', '{}'::jsonb, now(), now())""",
            tenant_a,
            f"sprint5-rls-a-{tenant_a.hex[:8]}",
            tenant_b,
            f"sprint5-rls-b-{tenant_b.hex[:8]}",
        )
        for tenant_id, template_id, name in (
            (tenant_a, template_a, "tenant-a-report"),
            (tenant_b, template_b, "tenant-b-report"),
        ):
            await su.execute(
                """INSERT INTO report_templates
                   (id, tenant_id, name, type, format, filters_schema, default_sections, created_at, updated_at, is_system)
                   VALUES ($1, $2, $3, 'executive_dashboard', 'json', '{}'::jsonb, '[]'::jsonb, now(), now(), false)""",
                template_id,
                tenant_id,
                name,
            )

        policy_rows = await su.fetch(
            "SELECT tablename FROM pg_policies WHERE policyname = 'tenant_isolation' AND tablename = ANY($1::text[])",
            list(TRUST_TABLES),
        )
        assert {row["tablename"] for row in policy_rows} == TRUST_TABLES

        async with app.transaction():
            await app.execute(f"SET LOCAL app.current_tenant_id = '{tenant_a}'")
            rows = await app.fetch("SELECT id FROM report_templates WHERE id = ANY($1::uuid[])", [template_a, template_b])
            ids = {row["id"] for row in rows}
            assert template_a in ids
            assert template_b not in ids
    finally:
        await su.execute("DELETE FROM report_templates WHERE tenant_id = ANY($1::uuid[])", [tenant_a, tenant_b])
        await su.execute("DELETE FROM tenants WHERE id = ANY($1::uuid[])", [tenant_a, tenant_b])
        await su.close()
        await app.close()
