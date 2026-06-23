from __future__ import annotations

import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import select, text

from app.api.v1.endpoints import remediation as remediation_api
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.main import app
from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlanStatus,
)
from app.schemas.remediation import (
    ApproveRemediationRequest,
    GenerateRemediationPlanRequest,
    RejectRemediationRequest,
    RequestApprovalRequest,
    RevokeApprovalRequest,
)
from app.services.remediation_state_machine import artifact_hash, utcnow
from tests.test_sprint4_phase2_remediation_plan_generation import (
    UNSAFE_TERMS,
    _finding,
    _gap,
    _tenant,
)
from tests.test_sprint4_phase4_approval_workflow import _user


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    await db.rollback()
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        for table in (
            "remediation_audit_links",
            "remediation_verification_results",
            "remediation_execution_jobs",
            "remediation_approvals",
            "remediation_policy_checks",
            "remediation_rollback_plans",
            "remediation_artifacts",
            "remediation_plans",
            "compliance_gaps",
            "control_assessment_results",
            "compliance_assessments",
            "evidence_items",
            "finding_control_mappings",
            "user_roles",
            "users",
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(
            text(
                "DELETE FROM security_findings WHERE integration_id IN ("
                "SELECT id FROM cloud_integrations WHERE tenant_id = :tenant_id)"
            ),
            {"tenant_id": tenant_id},
        )
        await db.execute(text("DELETE FROM cloud_integrations WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


async def _seed_finding(db, tenant_id: uuid.UUID, *, title: str = "S3 bucket public access is enabled"):
    integration = CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=CloudProvider.aws,
        target_identifier=f"123456789012-{uuid.uuid4().hex[:8]}",
        display_name="aws phase5 test",
        status=IntegrationStatus.active,
        vault_reference_id=f"authclaw/tenants/{tenant_id}/integrations/{uuid.uuid4()}",
    )
    db.add(integration)
    await db.flush()
    return await _finding(
        db,
        integration.id,
        title=title,
        resource_id=f"arn:aws:s3:::phase5-{uuid.uuid4().hex[:8]}",
        severity=FindingSeverity.high,
        description=(
            "Safe normalized summary with token=super-secret-token "
            "raw_provider_payload AKIAIOSFODNN7EXAMPLE"
        ),
        remediation="Review-only guidance ghp_abcdefghijklmnopqrstuvwxyz123456.",
    )


def _serialized(response) -> str:
    return json.dumps(response.model_dump(mode="json"), sort_keys=True).lower()


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


def test_remediation_router_surface_is_registered_under_api_v1():
    expected = {
        ("GET", "/remediation/plans"),
        ("POST", "/remediation/plans/generate"),
        ("GET", "/remediation/plans/{plan_id}"),
        ("GET", "/remediation/plans/{plan_id}/artifacts"),
        ("GET", "/remediation/artifacts/{artifact_id}"),
        ("POST", "/remediation/plans/{plan_id}/validate"),
        ("GET", "/remediation/plans/{plan_id}/policy-checks"),
        ("POST", "/remediation/plans/{plan_id}/request-approval"),
        ("GET", "/remediation/approvals"),
        ("GET", "/remediation/approvals/{approval_id}"),
        ("POST", "/remediation/approvals/{approval_id}/approve"),
        ("POST", "/remediation/approvals/{approval_id}/reject"),
        ("POST", "/remediation/approvals/{approval_id}/revoke"),
        ("GET", "/remediation/jobs"),
        ("GET", "/remediation/jobs/{job_id}"),
        ("POST", "/remediation/plans/{plan_id}/artifacts/{artifact_id}/dry-run"),
        ("GET", "/remediation/dry-runs"),
        ("GET", "/remediation/dry-runs/{result_id}"),
        ("POST", "/remediation/jobs/{job_id}/dry-run"),
        ("POST", "/remediation/plans/{plan_id}/artifacts/{artifact_id}/execute"),
        ("POST", "/remediation/jobs/{job_id}/execute"),
        ("GET", "/remediation/verification-results"),
        ("GET", "/remediation/verification-results/{result_id}"),
    }
    registered = _registered_api_routes()
    assert expected <= registered
    assert set(remediation_api.READ_ROLES) >= {"viewer", "auditor"}
    assert "viewer" not in remediation_api.WRITE_ROLES
    assert "auditor" not in remediation_api.WRITE_ROLES


@pytest.mark.asyncio
async def test_generate_list_detail_and_tenant_scope(monkeypatch):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(4))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(4))
        try:
            analyst = await _user(db, tenant_a.id, "analyst", "analyst")
            finding = await _seed_finding(db, tenant_a.id)
            gap = await _gap(db, tenant_a.id)

            finding_detail = await remediation_api.generate_plan(
                GenerateRemediationPlanRequest(source_type="finding", source_id=finding.id),
                tenant=tenant_a,
                db=db,
                current_user=analyst,
            )
            gap_detail = await remediation_api.generate_plan(
                GenerateRemediationPlanRequest(source_type="gap", source_id=gap.id),
                tenant=tenant_a,
                db=db,
                current_user=analyst,
            )
            recommendation_detail = await remediation_api.generate_plan(
                GenerateRemediationPlanRequest(source_type="recommendation", source_id=gap.id),
                tenant=tenant_a,
                db=db,
                current_user=analyst,
            )

            plans = await remediation_api.list_plans(limit=50, tenant=tenant_a, db=db, _user=analyst)
            assert plans.total == 3
            assert {item.id for item in plans.items} == {
                finding_detail.id,
                gap_detail.id,
                recommendation_detail.id,
            }
            assert all(item.created_by == analyst.id for item in plans.items)

            finding_only = await remediation_api.list_plans(
                source_type="finding",
                limit=50,
                tenant=tenant_a,
                db=db,
                _user=analyst,
            )
            assert [item.id for item in finding_only.items] == [finding_detail.id]

            tenant_b_plans = await remediation_api.list_plans(limit=50, tenant=tenant_b, db=db, _user=analyst)
            assert tenant_b_plans.total == 0
            with pytest.raises(NotFoundException):
                await remediation_api.generate_plan(
                    GenerateRemediationPlanRequest(source_type="finding", source_id=finding.id),
                    tenant=tenant_b,
                    db=db,
                    current_user=analyst,
                )

            await remediation_api._set_tenant_context(db, tenant_a.id)
            detail = await remediation_api.get_plan(finding_detail.id, tenant=tenant_a, db=db, _user=analyst)
            assert detail.status == RemediationPlanStatus.plan_drafted.value
            assert len(detail.artifacts) == 1
            assert detail.rollback_plan is not None
            serialized = _serialized(detail)
            for term in UNSAFE_TERMS:
                assert term.lower() not in serialized
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_artifact_and_policy_validation_endpoints(monkeypatch):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            analyst = await _user(db, tenant.id, "analyst", "analyst")
            finding = await _seed_finding(db, tenant.id)
            detail = await remediation_api.generate_plan(
                GenerateRemediationPlanRequest(source_type="finding", source_id=finding.id),
                tenant=tenant,
                db=db,
                current_user=analyst,
            )

            artifacts = await remediation_api.list_plan_artifacts(detail.id, limit=50, tenant=tenant, db=db, _user=analyst)
            assert artifacts.total == 1
            artifact = await remediation_api.get_artifact(artifacts.items[0].id, tenant=tenant, db=db, _user=analyst)
            assert artifact.content_redacted is not None
            assert "non-executing draft only" in artifact.content_redacted.lower()

            validation = await remediation_api.validate_plan(detail.id, tenant=tenant, db=db, current_user=analyst)
            assert validation.policy_check.passed is True
            assert validation.plan.status == RemediationPlanStatus.plan_validated.value
            checks = await remediation_api.list_policy_checks(detail.id, limit=50, tenant=tenant, db=db, _user=analyst)
            assert checks.total == 1
            assert checks.items[0].policy_check_hash == validation.policy_check.policy_check_hash
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_validation_failure_blocks_approval_request(monkeypatch):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            analyst = await _user(db, tenant.id, "analyst", "analyst")
            finding = await _seed_finding(db, tenant.id)
            detail = await remediation_api.generate_plan(
                GenerateRemediationPlanRequest(source_type="finding", source_id=finding.id),
                tenant=tenant,
                db=db,
                current_user=analyst,
            )
            artifact = (
                await db.execute(select(RemediationArtifact).where(RemediationArtifact.plan_id == detail.id))
            ).scalars().one()
            artifact.content_redacted = "terraform apply -auto-approve"
            artifact.artifact_hash = artifact_hash(artifact.artifact_type, artifact.content_redacted)
            await db.flush()

            validation = await remediation_api.validate_plan(detail.id, tenant=tenant, db=db, current_user=analyst)
            assert validation.policy_check.passed is False
            assert validation.policy_check.blocking_reasons
            with pytest.raises(BadRequestException):
                await remediation_api.request_approval(
                    detail.id,
                    RequestApprovalRequest(reason="Should not pass."),
                    tenant=tenant,
                    db=db,
                    current_user=analyst,
                )
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_request_approve_reject_revoke_and_approval_filters(monkeypatch):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            operator = await _user(db, tenant.id, "operator", "operator")
            owner = await _user(db, tenant.id, "owner", "owner")
            admin = await _user(db, tenant.id, "admin", "admin")

            approved_detail = await _generate_validated_finding_plan(db, tenant, operator)
            approval = await remediation_api.request_approval(
                approved_detail.id,
                RequestApprovalRequest(reason="Request owner review."),
                tenant=tenant,
                db=db,
                current_user=operator,
            )
            assert approval.status == RemediationApprovalStatus.pending.value
            approved = await remediation_api.approve_remediation(
                approval.id,
                ApproveRemediationRequest(approval_reason="Approved after review.", mfa_verified=True),
                tenant=tenant,
                db=db,
                current_user=owner,
            )
            assert approved.status == RemediationApprovalStatus.approved.value
            assert approved.approved_by == owner.id

            rejected_detail = await _generate_validated_finding_plan(db, tenant, operator)
            rejected_approval = await remediation_api.request_approval(
                rejected_detail.id,
                RequestApprovalRequest(reason="Request rejection path."),
                tenant=tenant,
                db=db,
                current_user=operator,
            )
            rejected = await remediation_api.reject_remediation(
                rejected_approval.id,
                RejectRemediationRequest(rejection_reason="Rejected after review."),
                tenant=tenant,
                db=db,
                current_user=admin,
            )
            assert rejected.status == RemediationApprovalStatus.rejected.value

            revoked_detail = await _generate_validated_finding_plan(db, tenant, operator)
            revoked_approval = await remediation_api.request_approval(
                revoked_detail.id,
                RequestApprovalRequest(reason="Request revoke path."),
                tenant=tenant,
                db=db,
                current_user=operator,
            )
            revoked = await remediation_api.revoke_remediation(
                revoked_approval.id,
                RevokeApprovalRequest(reason="Revoked stale request."),
                tenant=tenant,
                db=db,
                current_user=admin,
            )
            assert revoked.status == RemediationApprovalStatus.revoked.value

            approvals = await remediation_api.list_approvals(limit=50, tenant=tenant, db=db, _user=operator)
            assert approvals.total == 3
            pending = await remediation_api.list_approvals(
                status=RemediationApprovalStatus.pending,
                limit=50,
                tenant=tenant,
                db=db,
                _user=operator,
            )
            assert pending.total == 0
            fetched = await remediation_api.get_approval(approval.id, tenant=tenant, db=db, _user=operator)
            assert fetched.id == approval.id
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_approval_endpoint_preserves_service_guards(monkeypatch):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            owner = await _user(db, tenant.id, "owner", "owner")
            viewer = await _user(db, tenant.id, "viewer", "viewer")

            detail = await _generate_validated_finding_plan(
                db,
                tenant,
                owner,
                title="IAM admin policy grants excessive permission",
            )
            approval = await remediation_api.request_approval(
                detail.id,
                RequestApprovalRequest(reason="Critical self-approval guard."),
                tenant=tenant,
                db=db,
                current_user=owner,
            )
            with pytest.raises(ForbiddenException):
                await remediation_api.approve_remediation(
                    approval.id,
                    ApproveRemediationRequest(approval_reason="Viewer blocked.", mfa_verified=True),
                    tenant=tenant,
                    db=db,
                    current_user=viewer,
                )
            with pytest.raises(ForbiddenException):
                await remediation_api.approve_remediation(
                    approval.id,
                    ApproveRemediationRequest(approval_reason="Self approval blocked.", mfa_verified=True),
                    tenant=tenant,
                    db=db,
                    current_user=owner,
                )

            approval_row = (
                await db.execute(select(RemediationApproval).where(RemediationApproval.id == approval.id))
            ).scalars().one()
            approval_row.expires_at = utcnow() - __import__("datetime").timedelta(minutes=1)
            await db.flush()
            with pytest.raises(BadRequestException):
                await remediation_api.approve_remediation(
                    approval.id,
                    ApproveRemediationRequest(approval_reason="Expired.", mfa_verified=True),
                    tenant=tenant,
                    db=db,
                    current_user=owner,
                )
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_jobs_read_surface(monkeypatch):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            analyst = await _user(db, tenant.id, "analyst", "analyst")
            detail = await _generate_validated_finding_plan(db, tenant, analyst)
            job = RemediationExecutionJob(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                plan_id=detail.id,
                status=RemediationExecutionStatus.disabled,
                disabled_reason="Sprint 4 Phase 5 execution endpoints are disabled.",
            )
            db.add(job)
            await db.flush()

            jobs = await remediation_api.list_jobs(limit=50, tenant=tenant, db=db, _user=analyst)
            assert jobs.total == 1
            fetched = await remediation_api.get_job(job.id, tenant=tenant, db=db, _user=analyst)
            assert fetched.status == RemediationExecutionStatus.disabled.value
            assert "disabled" in (fetched.disabled_reason or "").lower()

        finally:
            await _cleanup(db, tenant.id)


async def _generate_validated_finding_plan(db, tenant, user, *, title: str = "S3 bucket public access is enabled"):
    finding = await _seed_finding(db, tenant.id, title=title)
    detail = await remediation_api.generate_plan(
        GenerateRemediationPlanRequest(source_type="finding", source_id=finding.id),
        tenant=tenant,
        db=db,
        current_user=user,
    )
    return (await remediation_api.validate_plan(detail.id, tenant=tenant, db=db, current_user=user)).plan


def test_remediation_api_source_has_no_provider_or_execution_clients():
    source = inspect.getsource(remediation_api).lower()
    forbidden = (
        "import subprocess",
        "os.system",
        "boto3.client",
        "botocore",
        "requests.",
        "httpx.",
        "github(",
        "create_pull",
        "terraform apply",
        "terraform destroy",
        "aws s3api",
    )
    for token in forbidden:
        assert token not in source
