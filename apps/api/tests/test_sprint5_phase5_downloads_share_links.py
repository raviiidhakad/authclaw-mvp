from __future__ import annotations

import inspect
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.api.v1.endpoints import reports as reports_api
from app.api.v1.endpoints import trust as trust_api
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.models.trust import ExternalShareLink, ReportAccessLog, ReportRunStatus
from app.schemas.trust import ReportRunCreateRequest, ShareLinkCreateRequest
from app.services.trust_reporting import hash_share_token
from tests.test_sprint5_phase2_report_generation import _assert_safe_export, _dataset, _tenant
from tests.test_sprint5_phase3_trust_reporting_api import _cleanup_all, _registered_api_routes, _users


def _request(ip: str = "127.0.0.1", user_agent: str = "AuthClawTest/1.0"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={"user-agent": user_agent})


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


def test_sprint5_phase5_routes_registered_with_token_scoped_consumption():
    registered = _registered_api_routes()
    expected = {
        ("GET", "/reports/artifacts/{artifact_id}/download"),
        ("POST", "/trust/share-links"),
        ("GET", "/trust/share-links"),
        ("POST", "/trust/share-links/{share_id}/revoke"),
        ("GET", "/trust/shared/{token}"),
    }
    assert expected <= registered
    for _, path in registered:
        assert "/public" not in path


@pytest.mark.asyncio
async def test_authenticated_artifact_download_rbac_sanitized_watermarked_and_evented(monkeypatch):
    fake = FakeProducer()
    monkeypatch.setattr(reports_api, "event_producer", fake)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "phase5-download-" + secrets.token_hex(3))
        try:
            users = await _users(db, tenant.id)
            await _dataset(db, tenant, "phase5_download")
            run = await reports_api.create_report_run(
                ReportRunCreateRequest(report_type="trust_overview", filters={"scope": "board"}),
                tenant=tenant,
                db=db,
                current_user=users["auditor"],
            )
            artifact_id = run.artifacts[0].id

            with pytest.raises(ForbiddenException):
                await reports_api.download_artifact(artifact_id, _request(), tenant=tenant, db=db, current_user=users["viewer"])

            downloaded = await reports_api.download_artifact(
                artifact_id,
                _request(ip="203.0.113.10", user_agent="Phase5Test/1.0"),
                tenant=tenant,
                db=db,
                current_user=users["auditor"],
            )

            payload = downloaded.model_dump(mode="json")
            assert payload["content_type"] == "application/json"
            assert payload["watermark"]["requester_id"] == str(users["auditor"].id)
            assert payload["watermark"]["artifact_id"] == str(artifact_id)
            assert payload["watermark"]["manifest_hash"] == run.manifest_hash
            assert payload["watermark"]["language"] == "evidence-supported posture; needs review"
            assert payload["artifact"]["metadata"]["report_type"] == "trust_overview"
            _assert_safe_export(payload)

            logs = (
                await db.execute(
                    select(ReportAccessLog).where(
                        ReportAccessLog.tenant_id == tenant.id,
                        ReportAccessLog.artifact_id == artifact_id,
                        ReportAccessLog.action == "download",
                    )
                )
            ).scalars().all()
            assert len(logs) == 1
            serialized_logs = json.dumps([log.ip_hash for log in logs] + [log.user_agent_hash for log in logs])
            assert "203.0.113.10" not in serialized_logs
            assert "Phase5Test" not in serialized_logs
            assert len(fake.events) >= 1
            event = fake.events[-1][1]
            assert event["event_type"] == "trust.report.downloaded"
            assert event["artifact_id"] == str(artifact_id)
            _assert_safe_export(event)
        finally:
            await _cleanup_all(db, tenant.id)


@pytest.mark.asyncio
async def test_artifact_download_blocks_expired_cross_tenant_and_unfinished_runs(monkeypatch):
    monkeypatch.setattr(reports_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "phase5-download-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "phase5-download-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            users_b = await _users(db, tenant_b.id)
            await _dataset(db, tenant_a, "phase5_expired")
            run = await reports_api.create_report_run(
                ReportRunCreateRequest(report_type="trust_overview"),
                tenant=tenant_a,
                db=db,
                current_user=users_a["auditor"],
            )
            artifact = await reports_api.artifact_or_404(db, tenant_a.id, run.artifacts[0].id)
            with pytest.raises(NotFoundException):
                await reports_api.download_artifact(artifact.id, _request(), tenant=tenant_b, db=db, current_user=users_b["auditor"])

            await reports_api.set_tenant_context(db, tenant_a.id)
            artifact.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
            await db.flush()
            with pytest.raises(BadRequestException):
                await reports_api.download_artifact(artifact.id, _request(), tenant=tenant_a, db=db, current_user=users_a["auditor"])

            artifact.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
            run_row = await reports_api.run_or_404(db, tenant_a.id, run.id)
            run_row.status = ReportRunStatus.running
            await db.flush()
            with pytest.raises(BadRequestException):
                await reports_api.download_artifact(artifact.id, _request(), tenant=tenant_a, db=db, current_user=users_a["auditor"])
        finally:
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_share_link_creation_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(trust_api, "event_producer", None)
    monkeypatch.setattr(settings, "ENABLE_EXTERNAL_TRUST_SHARING", False)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "phase5-share-disabled-" + secrets.token_hex(3))
        try:
            users = await _users(db, tenant.id)
            await _dataset(db, tenant, "phase5_share_disabled")
            run = await reports_api.create_report_run(
                ReportRunCreateRequest(report_type="trust_overview"),
                tenant=tenant,
                db=db,
                current_user=users["auditor"],
            )
            with pytest.raises(ForbiddenException):
                await trust_api.create_share_link(
                    ShareLinkCreateRequest(
                        artifact_id=run.artifacts[0].id,
                        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                    ),
                    _request(),
                    tenant=tenant,
                    db=db,
                    current_user=users["owner"],
                )
        finally:
            await _cleanup_all(db, tenant.id)


@pytest.mark.asyncio
async def test_enabled_share_links_are_owner_only_hashed_expiring_revocable_and_evented(monkeypatch):
    fake = FakeProducer()
    monkeypatch.setattr(trust_api, "event_producer", fake)
    monkeypatch.setattr(settings, "ENABLE_EXTERNAL_TRUST_SHARING", True)
    monkeypatch.setattr(settings, "EXTERNAL_TRUST_SHARING_MAX_EXPIRY_DAYS", 7)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "phase5-share-enabled-" + secrets.token_hex(3))
        try:
            users = await _users(db, tenant.id)
            await _dataset(db, tenant, "phase5_share_enabled")
            run = await reports_api.create_report_run(
                ReportRunCreateRequest(report_type="trust_overview"),
                tenant=tenant,
                db=db,
                current_user=users["auditor"],
            )
            artifact_id = run.artifacts[0].id
            with pytest.raises(ForbiddenException):
                await trust_api.create_share_link(
                    ShareLinkCreateRequest(artifact_id=artifact_id, expires_at=datetime.now(timezone.utc) + timedelta(days=1)),
                    _request(),
                    tenant=tenant,
                    db=db,
                    current_user=users["admin"],
                )
            with pytest.raises(BadRequestException):
                await trust_api.create_share_link(
                    ShareLinkCreateRequest(artifact_id=artifact_id, expires_at=datetime.now(timezone.utc) + timedelta(days=30)),
                    _request(),
                    tenant=tenant,
                    db=db,
                    current_user=users["owner"],
                )

            created = await trust_api.create_share_link(
                ShareLinkCreateRequest(
                    artifact_id=artifact_id,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=2),
                    max_downloads=3,
                ),
                _request(ip="198.51.100.5"),
                tenant=tenant,
                db=db,
                current_user=users["owner"],
            )
            assert created.token
            assert created.scope["scope_type"] == "artifact"
            assert created.scope["access"] == "read_only"
            _assert_safe_export(created.model_dump(mode="json"))

            stored = (await db.execute(select(ExternalShareLink).where(ExternalShareLink.id == created.id))).scalars().one()
            assert stored.token_hash == hash_share_token(created.token)
            assert created.token not in json.dumps(stored.scope, default=str)

            listed = await trust_api.list_share_links(skip=0, limit=50, tenant=tenant, db=db, current_user=users["owner"])
            assert listed.total == 1
            assert "token" not in listed.model_dump(mode="json")["items"][0]

            revoked = await trust_api.revoke_share_link(created.id, _request(), tenant=tenant, db=db, current_user=users["owner"])
            assert revoked.revoked_at is not None
            actions = (
                await db.execute(select(ReportAccessLog.action).where(ReportAccessLog.tenant_id == tenant.id, ReportAccessLog.artifact_id == artifact_id))
            ).scalars().all()
            assert "share_created" in actions
            assert "share_revoked" in actions
            event_types = [event["event_type"] for _, event in fake.events]
            assert "trust.share_link.created" in event_types
            assert "trust.share_link.revoked" in event_types
            _assert_safe_export([event for _, event in fake.events])
        finally:
            monkeypatch.setattr(settings, "ENABLE_EXTERNAL_TRUST_SHARING", False)
            await _cleanup_all(db, tenant.id)


@pytest.mark.asyncio
async def test_shared_trust_page_token_scope_expiry_revocation_limit_and_minimization(monkeypatch):
    monkeypatch.setattr(trust_api, "event_producer", None)
    monkeypatch.setattr(settings, "ENABLE_EXTERNAL_TRUST_SHARING", True)
    monkeypatch.setattr(settings, "EXTERNAL_TRUST_SHARING_MAX_EXPIRY_DAYS", 7)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "phase5-shared-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "phase5-shared-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            await _dataset(db, tenant_a, "phase5_shared_a")
            await _dataset(db, tenant_b, "phase5_shared_b")
            run = await reports_api.create_report_run(
                ReportRunCreateRequest(report_type="trust_overview"),
                tenant=tenant_a,
                db=db,
                current_user=users_a["auditor"],
            )
            artifact_id = run.artifacts[0].id
            created = await trust_api.create_share_link(
                ShareLinkCreateRequest(
                    artifact_id=artifact_id,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=2),
                    max_downloads=1,
                ),
                _request(),
                tenant=tenant_a,
                db=db,
                current_user=users_a["owner"],
            )

            shared = await trust_api.get_shared_trust_page(created.token, _request(ip="203.0.113.20"), db=db)
            payload = shared.model_dump(mode="json")
            assert payload["organization"] == tenant_a.name
            assert payload["artifact"]["content_hash"] == run.artifacts[0].content_hash
            assert payload["security_posture"]["counts"]["findings"] == 1
            serialized = json.dumps(payload)
            assert str(tenant_a.id) not in serialized
            assert str(tenant_b.id) not in serialized
            assert tenant_b.name not in serialized
            assert "actor_user_id" not in serialized
            assert "provider_key" not in serialized.lower()
            assert "provider_config" not in serialized.lower()
            assert "api_key" not in serialized.lower()
            assert "vault" not in serialized.lower()
            assert "raw_provider_payload" not in serialized

            with pytest.raises(ForbiddenException):
                await trust_api.get_shared_trust_page(created.token, _request(), db=db)
            with pytest.raises(NotFoundException):
                await trust_api.get_shared_trust_page("not-a-valid-share-token", _request(), db=db)

            expired = await trust_api.create_share_link(
                ShareLinkCreateRequest(artifact_id=artifact_id, expires_at=datetime.now(timezone.utc) + timedelta(days=1)),
                _request(),
                tenant=tenant_a,
                db=db,
                current_user=users_a["owner"],
            )
            stored_expired = (await db.execute(select(ExternalShareLink).where(ExternalShareLink.id == expired.id))).scalars().one()
            stored_expired.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
            await db.flush()
            with pytest.raises(NotFoundException):
                await trust_api.get_shared_trust_page(expired.token, _request(), db=db)

            revoked = await trust_api.create_share_link(
                ShareLinkCreateRequest(artifact_id=artifact_id, expires_at=datetime.now(timezone.utc) + timedelta(days=1)),
                _request(),
                tenant=tenant_a,
                db=db,
                current_user=users_a["owner"],
            )
            await trust_api.revoke_share_link(revoked.id, _request(), tenant=tenant_a, db=db, current_user=users_a["owner"])
            with pytest.raises(NotFoundException):
                await trust_api.get_shared_trust_page(revoked.token, _request(), db=db)
        finally:
            monkeypatch.setattr(settings, "ENABLE_EXTERNAL_TRUST_SHARING", False)
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


def test_phase5_sources_do_not_add_cloud_or_execution_clients():
    combined = "\n".join(inspect.getsource(module) for module in (reports_api, trust_api)).lower()
    forbidden = (
        "boto3",
        "google.cloud",
        "github(",
        "subprocess",
        "terraform apply",
        "terraform destroy",
        "os.system",
        "@router.get(\"/public",
    )
    for token in forbidden:
        assert token not in combined
