from __future__ import annotations

import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import text

from app.api.v1.endpoints import trust as trust_api
from app.core.database import AsyncSessionLocal
from app.core.exceptions import ForbiddenException, NotFoundException
from app.models.trust import ReportAccessLog
from app.services import trust_activity as trust_activity_module
from app.services.trust_activity import TrustNotificationService
from app.services.trust_reporting import LocalReportArtifactStore, ReportGenerationRequest, ReportGenerationService, hash_access_metadata
from tests.test_sprint4_phase4_approval_workflow import _user
from tests.test_sprint5_phase2_report_generation import _assert_safe_export, _cleanup, _dataset, _tenant


async def _users(db, tenant_id: uuid.UUID):
    return {
        "viewer": await _user(db, tenant_id, "viewer", "phase6-viewer-" + secrets.token_hex(3)),
        "auditor": await _user(db, tenant_id, "auditor", "phase6-auditor-" + secrets.token_hex(3)),
        "blocked": await _user(db, tenant_id, "phase6_blocked", "phase6-blocked-" + secrets.token_hex(3)),
    }


async def _cleanup_all(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await db.execute(text("DELETE FROM user_roles WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM users WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()
    await _cleanup(db, *tenant_ids)


def _json(value) -> dict | list:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


@pytest.mark.asyncio
async def test_notifications_list_detail_read_state_rbac_and_tenant_isolation(monkeypatch):
    monkeypatch.setattr(trust_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "phase6-notify-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "phase6-notify-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            users_b = await _users(db, tenant_b.id)
            service = TrustNotificationService(db, event_producer=None)
            notification = await service.create_notification(
                tenant_id=tenant_a.id,
                recipient_user_id=users_a["viewer"].id,
                type="report_run_completed",
                severity="info",
                title="Report certified and guaranteed audit-ready",
                body="token=ghp_supersecretsecretsecretsecret raw_provider_payload vault://tenant/secret",
                resource_type="report_run",
                resource_id=uuid.uuid4(),
            )
            await service.create_notification(
                tenant_id=tenant_b.id,
                recipient_user_id=users_b["viewer"].id,
                type="integration_health",
                severity="warning",
                title="Other tenant notification",
                body="Other tenant only",
            )

            listed = await trust_api.list_notifications(
                unread_only=False,
                type=None,
                severity=None,
                resource_type=None,
                skip=0,
                limit=50,
                tenant=tenant_a,
                db=db,
                current_user=users_a["viewer"],
            )
            assert listed.total == 1
            assert listed.unread == 1
            assert listed.items[0].id == notification.id
            _assert_safe_export(_json(listed))

            detail = await trust_api.get_notification(notification.id, tenant=tenant_a, db=db, current_user=users_a["viewer"])
            assert detail.read_at is None
            marked = await trust_api.mark_notification_read(notification.id, tenant=tenant_a, db=db, current_user=users_a["viewer"])
            assert marked.read_at is not None
            unread = await trust_api.get_notification_unread_count(tenant=tenant_a, db=db, current_user=users_a["viewer"])
            assert unread.unread == 0

            with pytest.raises(NotFoundException):
                await trust_api.get_notification(notification.id, tenant=tenant_b, db=db, current_user=users_b["viewer"])
            with pytest.raises(ForbiddenException):
                await trust_api.list_notifications(
                    unread_only=False,
                    type=None,
                    severity=None,
                    resource_type=None,
                    skip=0,
                    limit=50,
                    tenant=tenant_a,
                    db=db,
                    current_user=users_a["blocked"],
                )
        finally:
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_activity_timeline_orders_filters_and_sanitizes_tenant_scoped_events(tmp_path, monkeypatch):
    monkeypatch.setattr(trust_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "phase6-activity-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "phase6-activity-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            users_b = await _users(db, tenant_b.id)
            await _dataset(db, tenant_a, "phase6_a")
            await _dataset(db, tenant_b, "phase6_b")

            result = await ReportGenerationService(
                db,
                artifact_store=LocalReportArtifactStore(tmp_path),
                event_producer=None,
            ).generate_report(
                tenant_a.id,
                ReportGenerationRequest(
                    report_type="trust_overview",
                    requested_by=users_a["auditor"].id,
                    filters={"scope": "phase6"},
                ),
            )
            assert result.artifact is not None
            db.add(
                ReportAccessLog(
                    tenant_id=tenant_a.id,
                    artifact_id=result.artifact.id,
                    actor_user_id=users_a["auditor"].id,
                    action="downloaded",
                    ip_hash=hash_access_metadata("192.168.1.12"),
                    user_agent_hash=hash_access_metadata("Mozilla/5.0 AuthClawTest"),
                )
            )
            await db.flush()

            timeline = await trust_api.list_activity_timeline(
                source=None,
                action=None,
                resource_type=None,
                resource_id=None,
                date_from=None,
                date_to=None,
                skip=0,
                limit=100,
                tenant=tenant_a,
                db=db,
                current_user=users_a["viewer"],
            )
            assert timeline.total >= 6
            assert timeline.items == sorted(timeline.items, key=lambda item: (item.occurred_at, item.id), reverse=True)
            sources = {item.source for item in timeline.items}
            assert {"report", "remediation", "evidence", "integration"} <= sources
            serialized = json.dumps(timeline.model_dump(mode="json"), sort_keys=True)
            assert str(tenant_b.id) not in serialized
            assert "192.168.1.12" not in serialized
            assert "Mozilla/5.0" not in serialized
            _assert_safe_export(timeline.model_dump(mode="json"))

            report_only = await trust_api.list_activity_timeline(
                source="report",
                action=None,
                resource_type="report_artifact",
                resource_id=result.artifact.id,
                date_from=None,
                date_to=None,
                skip=0,
                limit=50,
                tenant=tenant_a,
                db=db,
                current_user=users_a["auditor"],
            )
            assert report_only.total == 1
            assert report_only.items[0].action == "downloaded"

            with pytest.raises(ForbiddenException):
                await trust_api.list_activity_timeline(
                    source=None,
                    action=None,
                    resource_type=None,
                    resource_id=None,
                    date_from=None,
                    date_to=None,
                    skip=0,
                    limit=50,
                    tenant=tenant_a,
                    db=db,
                    current_user=users_a["blocked"],
                )
        finally:
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


def test_phase6_activity_service_does_not_import_execution_clients():
    source = inspect.getsource(trust_activity_module)
    forbidden = (
        "boto3",
        "google.cloud",
        "Github(",
        "subprocess",
        "terraform apply",
        "terraform destroy",
        "os.system",
    )
    for term in forbidden:
        assert term not in source
