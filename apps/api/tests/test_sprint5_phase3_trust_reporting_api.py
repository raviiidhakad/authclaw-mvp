from __future__ import annotations

import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import select, text

from app.api.v1.endpoints import evidence_packages as evidence_api
from app.api.v1.endpoints import reports as reports_api
from app.api.v1.endpoints import trust as trust_api
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import ForbiddenException, NotFoundException
from app.main import app
from app.models.trust import ReportAccessLog, ReportRunStatus
from app.schemas.trust import (
    EvidencePackageCreateRequest,
    ReportRunCreateRequest,
    ReportTemplateCreate,
    ReportTemplateUpdate,
)
from app.services.trust_reporting import hash_access_metadata
from tests.test_sprint4_phase4_approval_workflow import _user
from tests.test_sprint5_phase2_report_generation import _assert_safe_export, _cleanup, _dataset, _tenant


async def _users(db, tenant_id: uuid.UUID):
    return {
        "viewer": await _user(db, tenant_id, "viewer", "viewer-" + secrets.token_hex(3)),
        "auditor": await _user(db, tenant_id, "auditor", "auditor-" + secrets.token_hex(3)),
        "admin": await _user(db, tenant_id, "admin", "admin-" + secrets.token_hex(3)),
        "owner": await _user(db, tenant_id, "owner", "owner-" + secrets.token_hex(3)),
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


def _registered_api_routes() -> set[tuple[str, str]]:
    prefix = settings.API_PREFIX.rstrip("/")
    registered: set[tuple[str, str]] = set()
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith(prefix):
            continue
        normalized_path = path.removeprefix(prefix) or "/"
        for method in operations:
            registered.add((method.upper(), normalized_path))
    return registered


def test_sprint5_phase3_routes_registered_without_public_share_surface():
    expected = {
        ("GET", "/trust/overview"),
        ("GET", "/trust/security-posture"),
        ("GET", "/trust/compliance-posture"),
        ("GET", "/trust/remediation-posture"),
        ("GET", "/trust/integration-health"),
        ("GET", "/reports/templates"),
        ("POST", "/reports/templates"),
        ("PATCH", "/reports/templates/{template_id}"),
        ("DELETE", "/reports/templates/{template_id}"),
        ("POST", "/reports/run"),
        ("GET", "/reports/runs"),
        ("GET", "/reports/runs/{run_id}"),
        ("GET", "/reports/artifacts"),
        ("GET", "/reports/artifacts/{artifact_id}"),
        ("GET", "/reports/artifacts/{artifact_id}/manifest"),
        ("POST", "/evidence-packages"),
        ("GET", "/evidence-packages"),
        ("GET", "/evidence-packages/{package_id}"),
    }
    registered = _registered_api_routes()
    assert expected <= registered
    forbidden_fragments = ("/public", "/share/")
    for _, path in registered:
        assert not any(fragment in path for fragment in forbidden_fragments)


@pytest.mark.asyncio
async def test_trust_posture_endpoints_are_aggregate_sanitized_and_evented(monkeypatch):
    class FakeProducer:
        def __init__(self):
            self.events = []

        async def publish(self, topic, event):
            self.events.append((topic, event.model_dump(mode="json")))

    fake = FakeProducer()
    monkeypatch.setattr(trust_api, "event_producer", fake)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "api-trust-" + secrets.token_hex(3))
        try:
            users = await _users(db, tenant.id)
            await _dataset(db, tenant, "api_trust")

            overview = await trust_api.get_trust_overview(tenant=tenant, db=db, current_user=users["viewer"])
            security = await trust_api.get_security_posture(tenant=tenant, db=db, current_user=users["viewer"])
            compliance = await trust_api.get_compliance_posture(tenant=tenant, db=db, current_user=users["viewer"])
            remediation = await trust_api.get_remediation_posture(tenant=tenant, db=db, current_user=users["viewer"])
            integrations = await trust_api.get_integration_health(tenant=tenant, db=db, current_user=users["viewer"])

            assert overview.security_posture.counts["findings"] == 1
            assert security.severity_counts["high"] == 1
            assert compliance.counts["evidence_items"] == 1
            assert remediation.counts["plans"] == 1
            assert integrations.counts["integrations"] == 1
            _assert_safe_export(_json(overview))
            assert len(fake.events) == 5
            _assert_safe_export([event for _, event in fake.events])
        finally:
            await _cleanup_all(db, tenant.id)


@pytest.mark.asyncio
async def test_report_template_crud_rbac_and_tenant_isolation(monkeypatch):
    monkeypatch.setattr(reports_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "api-template-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "api-template-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            users_b = await _users(db, tenant_b.id)
            body = ReportTemplateCreate(
                name="Evidence package",
                type="evidence_package",
                filters_schema={"framework_id": "uuid", "authorization": "Bearer hidden"},
                default_sections=["evidence", {"vault_reference_id": "vault://hidden"}],
            )
            with pytest.raises(ForbiddenException):
                await reports_api.create_template(body, tenant=tenant_a, db=db, current_user=users_a["viewer"])

            created = await reports_api.create_template(body, tenant=tenant_a, db=db, current_user=users_a["admin"])
            assert created.type == "evidence_package"
            _assert_safe_export(created.model_dump(mode="json"))

            listed = await reports_api.list_templates(skip=0, limit=50, tenant=tenant_a, db=db, _user=users_a["auditor"])
            assert listed.total == 1
            fetched = await reports_api.get_template(created.id, tenant=tenant_a, db=db, _user=users_a["auditor"])
            assert fetched.id == created.id
            with pytest.raises(NotFoundException):
                await reports_api.get_template(created.id, tenant=tenant_b, db=db, _user=users_b["auditor"])

            updated = await reports_api.update_template(
                created.id,
                ReportTemplateUpdate(name="Evidence package v2", default_sections=["summary"]),
                tenant=tenant_a,
                db=db,
                _user=users_a["owner"],
            )
            assert updated.name == "Evidence package v2"
            await reports_api.delete_template(created.id, tenant=tenant_a, db=db, _user=users_a["owner"])
            assert (await reports_api.list_templates(skip=0, limit=50, tenant=tenant_a, db=db, _user=users_a["auditor"])).total == 0
        finally:
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_report_run_artifact_manifest_access_logs_and_rbac(monkeypatch):
    monkeypatch.setattr(reports_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "api-report-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "api-report-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            users_b = await _users(db, tenant_b.id)
            await _dataset(db, tenant_a, "api_report_a")

            with pytest.raises(ForbiddenException):
                await reports_api.create_report_run(
                    ReportRunCreateRequest(report_type="trust_overview"),
                    tenant=tenant_a,
                    db=db,
                    current_user=users_a["viewer"],
                )

            run = await reports_api.create_report_run(
                ReportRunCreateRequest(report_type="trust_overview", filters={"scope": "executive"}),
                tenant=tenant_a,
                db=db,
                current_user=users_a["auditor"],
            )
            assert run.status == ReportRunStatus.completed.value
            assert run.artifacts
            _assert_safe_export(run.model_dump(mode="json"))

            runs = await reports_api.list_report_runs(skip=0, limit=50, tenant=tenant_a, db=db, _user=users_a["auditor"], report_type="trust_overview")
            assert runs.total == 1
            detail = await reports_api.get_report_run(run.id, tenant=tenant_a, db=db, _user=users_a["auditor"])
            assert detail.id == run.id
            with pytest.raises(NotFoundException):
                await reports_api.get_report_run(run.id, tenant=tenant_b, db=db, _user=users_b["auditor"])

            with pytest.raises(ForbiddenException):
                await reports_api.get_artifact(run.artifacts[0].id, tenant=tenant_a, db=db, _user=users_a["viewer"])
            artifact = await reports_api.get_artifact(run.artifacts[0].id, tenant=tenant_a, db=db, _user=users_a["auditor"])
            manifest = await reports_api.get_artifact_manifest(artifact.id, tenant=tenant_a, db=db, _user=users_a["auditor"])
            assert artifact.content_hash == manifest.manifest_json["content_hash"]
            assert "storage_key" not in json.dumps(artifact.model_dump(mode="json"))
            _assert_safe_export(manifest.model_dump(mode="json"))

            access = ReportAccessLog(
                tenant_id=tenant_a.id,
                artifact_id=artifact.id,
                actor_user_id=users_a["auditor"].id,
                action="metadata_view",
                ip_hash=hash_access_metadata("127.0.0.1"),
                user_agent_hash=hash_access_metadata("AuthClawTest/1.0"),
            )
            db.add(access)
            await db.flush()
            logs = await reports_api.list_artifact_access_logs(artifact.id, skip=0, limit=50, tenant=tenant_a, db=db, _user=users_a["auditor"])
            assert logs.total == 1
            serialized_logs = json.dumps(logs.model_dump(mode="json"))
            assert "127.0.0.1" not in serialized_logs
            assert "AuthClawTest" not in serialized_logs
        finally:
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_evidence_package_create_list_detail_filters_and_cross_tenant(monkeypatch):
    monkeypatch.setattr(evidence_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "api-package-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "api-package-b-" + secrets.token_hex(3))
        try:
            users_a = await _users(db, tenant_a.id)
            users_b = await _users(db, tenant_b.id)
            data = await _dataset(db, tenant_a, "api_pkg")

            with pytest.raises(ForbiddenException):
                await evidence_api.create_evidence_package(
                    EvidencePackageCreateRequest(framework_id=data["framework"].id),
                    tenant=tenant_a,
                    db=db,
                    current_user=users_a["viewer"],
                )

            package = await evidence_api.create_evidence_package(
                EvidencePackageCreateRequest(
                    framework_id=data["framework"].id,
                    control_ids=[data["control"].id],
                    include_findings=True,
                    include_remediation=True,
                ),
                tenant=tenant_a,
                db=db,
                current_user=users_a["auditor"],
            )
            assert package.run.status == ReportRunStatus.completed.value
            assert package.artifact is not None
            assert package.manifest is not None
            _assert_safe_export(package.model_dump(mode="json"))

            listed = await evidence_api.list_evidence_packages(
                tenant=tenant_a,
                db=db,
                _user=users_a["auditor"],
                skip=0,
                limit=50,
                framework_id=data["framework"].id,
                control_id=data["control"].id,
            )
            assert listed.total == 1
            detail = await evidence_api.get_evidence_package(package.run.id, tenant=tenant_a, db=db, _user=users_a["auditor"])
            assert detail.run.id == package.run.id
            with pytest.raises(NotFoundException):
                await evidence_api.get_evidence_package(package.run.id, tenant=tenant_b, db=db, _user=users_b["auditor"])
        finally:
            await _cleanup_all(db, tenant_a.id, tenant_b.id)


def test_phase3_api_source_has_no_public_share_download_or_execution_clients():
    combined = "\n".join(
        inspect.getsource(module)
        for module in (trust_api, reports_api, evidence_api)
    ).lower()
    forbidden = (
        "boto3",
        "google.cloud",
        "github(",
        "subprocess",
        "terraform apply",
        "terraform destroy",
        "os.system",
        "@router.get(\"/download",
        "public",
    )
    for token in forbidden:
        assert token not in combined
