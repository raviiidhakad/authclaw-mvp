from __future__ import annotations

import inspect
import json
import uuid

import pytest
from sqlalchemy import delete, select, text

from app.api.v1.endpoints import evidence_packages as evidence_api
from app.api.v1.endpoints import reports as reports_api
from app.api.v1.endpoints import trust as trust_api
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import ForbiddenException, NotFoundException
from app.models.tenant import Tenant
from app.models.trust import ReportRun
from app.models.user import User
from app.schemas.trust import ShareLinkCreateRequest
from scripts.seed_sprint5_demo import DEMO_TENANT_SLUG, assert_safe_summary, seed_demo_dataset
from tests.test_sprint5_phase5_downloads_share_links import _request


UNSAFE_RESPONSE_TERMS = (
    "akia",
    "begin private key",
    "ghp_",
    "raw_provider_payload",
    "super-secret",
    "aws_secret_access_key",
    "vault://",
    "secret/authclaw",
    "legally compliant",
    "fully compliant",
    "certified",
    "guaranteed",
    "audit-ready",
)


def _serialized(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, default=str).lower()


async def _demo_tenant_and_user(db):
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().one()
    user = (await db.execute(select(User).where(User.tenant_id == tenant.id, User.email == "demo.admin@authclaw-demo.com"))).scalars().one()
    return tenant, user


async def _delete_demo_tenant(db) -> None:
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().first()
    if tenant is not None:
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
        await db.execute(delete(Tenant).where(Tenant.id == tenant.id))
        await db.commit()


@pytest.mark.asyncio
async def test_sprint5_demo_seed_is_idempotent_and_complete():
    async with AsyncSessionLocal() as db:
        try:
            first = await seed_demo_dataset(db)
            second = await seed_demo_dataset(db)

            assert first.as_safe_dict() == second.as_safe_dict()
            assert second.templates >= 1
            assert second.report_runs >= 2
            assert second.report_artifacts >= 2
            assert second.export_manifests >= 2
            assert second.evidence_packages >= 1
            assert second.access_logs >= 2
            assert second.notifications >= 2
            assert second.timeline_minimum_items >= 8
            assert_safe_summary(second, [])
        finally:
            await _delete_demo_tenant(db)


@pytest.mark.asyncio
async def test_sprint5_demo_api_acceptance_is_tenant_scoped_and_sanitized(monkeypatch):
    monkeypatch.setattr(trust_api, "event_producer", None)
    monkeypatch.setattr(reports_api, "event_producer", None)
    monkeypatch.setattr(evidence_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        try:
            await seed_demo_dataset(db)
            tenant, user = await _demo_tenant_and_user(db)
            other = Tenant(id=uuid.uuid4(), name="Sprint 5 Demo Isolation", slug=f"sprint5-demo-isolation-{uuid.uuid4().hex[:8]}", settings={})

            overview = await trust_api.get_trust_overview(tenant=tenant, db=db, current_user=user)
            templates = await reports_api.list_templates(skip=0, limit=50, type=None, tenant=tenant, db=db, _user=user)
            runs = await reports_api.list_report_runs(skip=0, limit=50, tenant=tenant, db=db, _user=user)
            artifacts = await reports_api.list_artifacts(skip=0, limit=50, run_id=None, artifact_type=None, tenant=tenant, db=db, _user=user)
            manifest = await reports_api.get_artifact_manifest(artifacts.items[0].id, tenant=tenant, db=db, _user=user)
            packages = await evidence_api.list_evidence_packages(skip=0, limit=50, tenant=tenant, db=db, _user=user)
            package_detail = await evidence_api.get_evidence_package(packages.items[0].id, tenant=tenant, db=db, _user=user)
            access_logs = await reports_api.list_access_logs(skip=0, limit=50, artifact_id=None, tenant=tenant, db=db, _user=user)
            notifications = await trust_api.list_notifications(
                unread_only=False,
                type=None,
                severity=None,
                resource_type=None,
                skip=0,
                limit=50,
                tenant=tenant,
                db=db,
                current_user=user,
            )
            timeline = await trust_api.list_activity_timeline(
                source=None,
                action=None,
                resource_type=None,
                resource_id=None,
                date_from=None,
                date_to=None,
                skip=0,
                limit=100,
                tenant=tenant,
                db=db,
                current_user=user,
            )

            assert overview.security_posture.posture == "at risk"
            assert templates.total >= 1
            assert runs.total >= 2
            assert artifacts.total >= 2
            assert manifest.manifest_hash
            assert packages.total >= 1
            assert package_detail.artifact is not None
            assert access_logs.total >= 2
            assert notifications.total >= 2
            assert timeline.total >= 8

            with pytest.raises((ForbiddenException, NotFoundException)):
                await reports_api.get_report_run(runs.items[0].id, tenant=other, db=db, _user=user)
            with pytest.raises((ForbiddenException, NotFoundException)):
                await reports_api.get_artifact_manifest(artifacts.items[0].id, tenant=other, db=db, _user=user)

            monkeypatch.setattr(settings, "ENABLE_EXTERNAL_TRUST_SHARING", False)
            with pytest.raises(ForbiddenException):
                await trust_api.create_share_link(
                    ShareLinkCreateRequest(artifact_id=artifacts.items[0].id, expires_at=artifacts.items[0].expires_at),
                    _request(),
                    tenant=tenant,
                    db=db,
                    current_user=user,
                )

            payload = _serialized([overview, templates, runs, artifacts, manifest, packages, package_detail, access_logs, notifications, timeline])
            assert str(other.id).lower() not in payload
            for term in UNSAFE_RESPONSE_TERMS:
                assert term not in payload
        finally:
            await db.rollback()
            await _delete_demo_tenant(db)


def test_sprint5_phase7_demo_sources_do_not_import_execution_clients():
    import scripts.seed_sprint5_demo as seed_script

    source = inspect.getsource(seed_script).lower()
    forbidden = (
        "boto3",
        "google.cloud",
        "github(",
        "subprocess",
        "terraform apply",
        "terraform destroy",
        "os.system",
        "requests.",
        "httpx.",
    )
    for token in forbidden:
        assert token not in source
