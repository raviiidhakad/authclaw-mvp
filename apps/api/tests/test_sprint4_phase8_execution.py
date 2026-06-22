from __future__ import annotations

import inspect
import json
import uuid

import pytest
from sqlalchemy import select

from app.api.v1.endpoints import remediation as remediation_api
from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalStatus,
    RemediationArtifactType,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlanStatus,
    RemediationRiskLevel,
)
from app.schemas.remediation import CreateExecutionRequest
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_dry_run_service import RemediationDryRunService
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_sandbox_service import RemediationSandboxService
from app.services.remediation_state_machine import artifact_hash, utcnow
from tests.test_sprint4_phase4_approval_workflow import FakeProducer, _cleanup, _tenant, _user, _validated_plan


def _serialized(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        value = {key: nested for key, nested in value.__dict__.items() if not key.startswith("_")}
    return json.dumps(value, sort_keys=True, default=str).lower()


async def _approved_dry_run_fixture(
    db,
    tenant_id,
    *,
    artifact_type: RemediationArtifactType = RemediationArtifactType.documentation_only,
    content: str = "Documentation-only controlled execution fixture. No external mutation.",
    risk_flags: dict | None = None,
    risk_level: RemediationRiskLevel = RemediationRiskLevel.low,
    sandbox_root=None,
):
    requester = await _user(db, tenant_id, "operator", f"requester-{uuid.uuid4().hex[:6]}")
    owner = await _user(db, tenant_id, "owner", f"owner-{uuid.uuid4().hex[:6]}")
    plan, artifact, _ = await _validated_plan(
        db,
        tenant_id,
        artifact_type=artifact_type,
        content=content,
        risk_flags=risk_flags or {"template_key": "documentation_only", "rollback_uncertain": False},
        risk_level=risk_level,
    )
    approval_service = RemediationApprovalService(db, event_producer=None)
    approval = await approval_service.request_approval(tenant_id, plan.id, requested_by=requester.id)
    approval = await approval_service.approve(
        tenant_id,
        approval.id,
        owner.id,
        "Approved for controlled execution.",
        mfa_verified=risk_level in {RemediationRiskLevel.high, RemediationRiskLevel.critical},
    )
    dry_service = RemediationDryRunService(
        db,
        event_producer=None,
        sandbox_service=RemediationSandboxService(root_dir=sandbox_root),
    )
    dry_job = await dry_service.create_dry_run_job(tenant_id, plan.id, artifact.id, approval_id=approval.id)
    dry_run = await dry_service.run_dry_run(tenant_id, dry_job.id)
    return plan, artifact, approval, dry_run


@pytest.mark.asyncio
async def test_safe_documentation_only_execution_succeeds_and_verifies(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(db, tenant.id, sandbox_root=tmp_path)
            producer = FakeProducer()
            service = RemediationExecutionService(
                db,
                event_producer=producer,
                sandbox_service=RemediationSandboxService(root_dir=tmp_path),
            )
            job = await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
            verification = await service.execute_job(tenant.id, job.id)

            assert job.status == RemediationExecutionStatus.succeeded
            assert verification is not None and verification.verified is True
            assert verification.job_id == job.id
            assert plan.status == RemediationPlanStatus.verified
            refreshed_approval = (await db.execute(select(RemediationApproval).where(RemediationApproval.id == approval.id))).scalars().one()
            assert refreshed_approval.status == RemediationApprovalStatus.used
            assert "external mutation" in verification.verification_summary.lower()
            event_types = [event["event_type"] for _, event in producer.events]
            assert "remediation.execution.queued" in event_types
            assert "remediation.execution.started" in event_types
            assert "remediation.execution.succeeded" in event_types
            assert "remediation.verified" in event_types
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_simulated_execution_succeeds_for_high_risk_without_provider_calls(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(
                db,
                tenant.id,
                risk_level=RemediationRiskLevel.high,
                risk_flags={"template_key": "simulation", "execution_adapter": "simulated_provider", "rollback_uncertain": False},
                sandbox_root=tmp_path,
            )
            service = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job = await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
            verification = await service.execute_job(tenant.id, job.id)

            assert job.status == RemediationExecutionStatus.succeeded
            assert verification.verified is True
            assert "simulated provider" in verification.verification_summary.lower()
            assert "no external provider" in verification.verification_summary.lower()
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_simulated_failure_marks_rollback_required_without_rollback_execution(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(
                db,
                tenant.id,
                risk_level=RemediationRiskLevel.high,
                risk_flags={
                    "template_key": "simulation",
                    "execution_adapter": "simulated_provider",
                    "simulate_execution_failure": True,
                    "rollback_uncertain": False,
                },
                sandbox_root=tmp_path,
            )
            producer = FakeProducer()
            service = RemediationExecutionService(db, event_producer=producer, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job = await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
            verification = await service.execute_job(tenant.id, job.id)

            assert job.status == RemediationExecutionStatus.rollback_required
            assert verification.verified is False
            assert plan.status == RemediationPlanStatus.rollback_required
            assert "remediation.rollback.required" in [event["event_type"] for _, event in producer.events]
            assert "simulated" in verification.verification_summary.lower()
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_static_validation_and_local_noop_adapters_require_passed_dry_run(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(
                db,
                tenant.id,
                risk_flags={"template_key": "static", "execution_adapter": "static_validation", "rollback_uncertain": False},
                sandbox_root=tmp_path,
            )
            service = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job = await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
            verification = await service.execute_job(tenant.id, job.id)
            assert verification.verified is True
            assert "static dry-run validation" in verification.verification_summary.lower()

            tenant_2 = await _tenant(db, "phase8-noop")
            plan_2, artifact_2, approval_2, _ = await _approved_dry_run_fixture(
                db,
                tenant_2.id,
                risk_flags={"template_key": "noop", "execution_adapter": "local_noop", "rollback_uncertain": False},
                sandbox_root=tmp_path,
            )
            service_2 = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job_2 = await service_2.create_execution_job(tenant_2.id, plan_2.id, artifact_2.id, approval_2.id)
            verification_2 = await service_2.execute_job(tenant_2.id, job_2.id)
            assert verification_2.verified is True
            assert "local no-op" in verification_2.verification_summary.lower()
        finally:
            await _cleanup(db, tenant.id, locals().get("tenant_2", tenant).id)


@pytest.mark.asyncio
async def test_execution_blocked_without_approval_or_without_required_dry_run(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, _ = await _validated_plan(db, tenant.id)
            service = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            with pytest.raises(NotFoundException):
                await service.create_execution_job(tenant.id, plan.id, artifact.id, uuid.uuid4())

            requester = await _user(db, tenant.id, "operator", "requester-no-dryrun")
            owner = await _user(db, tenant.id, "owner", "owner-no-dryrun")
            approval_service = RemediationApprovalService(db, event_producer=None)
            approval = await approval_service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            approval = await approval_service.approve(tenant.id, approval.id, owner.id, "Approved.", mfa_verified=False)
            with pytest.raises(BadRequestException) as missing_dry_run:
                await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
            assert "Passed dry-run" in missing_dry_run.value.detail
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_execution_blocks_expired_mismatched_and_reused_approvals(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(db, tenant.id, sandbox_root=tmp_path)
            service = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))

            approval.expires_at = utcnow() - __import__("datetime").timedelta(minutes=1)
            await db.flush()
            with pytest.raises(BadRequestException) as expired:
                await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
            assert "expired" in expired.value.detail.lower()

            tenant_2 = await _tenant(db, "phase8-mismatch")
            plan_2, artifact_2, approval_2, _ = await _approved_dry_run_fixture(db, tenant_2.id, sandbox_root=tmp_path)
            artifact_2.content_redacted = "Changed after approval without matching hash."
            artifact_2.artifact_hash = artifact_hash(artifact_2.artifact_type, artifact_2.content_redacted)
            await db.flush()
            with pytest.raises(BadRequestException) as artifact_mismatch:
                await RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path)).create_execution_job(
                    tenant_2.id, plan_2.id, artifact_2.id, approval_2.id
                )
            assert "artifact hash" in artifact_mismatch.value.detail

            tenant_3 = await _tenant(db, "phase8-policy")
            plan_3, artifact_3, approval_3, _ = await _approved_dry_run_fixture(db, tenant_3.id, sandbox_root=tmp_path)
            approval_3.policy_check_hash = uuid.uuid4().hex
            await db.flush()
            with pytest.raises(BadRequestException) as policy_mismatch:
                await RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path)).create_execution_job(
                    tenant_3.id, plan_3.id, artifact_3.id, approval_3.id
                )
            assert "policy check" in policy_mismatch.value.detail

            tenant_4 = await _tenant(db, "phase8-reuse")
            plan_4, artifact_4, approval_4, _ = await _approved_dry_run_fixture(db, tenant_4.id, sandbox_root=tmp_path)
            service_4 = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job_4 = await service_4.create_execution_job(tenant_4.id, plan_4.id, artifact_4.id, approval_4.id)
            await service_4.execute_job(tenant_4.id, job_4.id)
            refreshed = (await db.execute(select(RemediationApproval).where(RemediationApproval.id == approval_4.id))).scalars().one()
            assert refreshed.status == RemediationApprovalStatus.used
            with pytest.raises(BadRequestException):
                await service_4.create_execution_job(tenant_4.id, plan_4.id, artifact_4.id, approval_4.id)
        finally:
            await _cleanup(
                db,
                tenant.id,
                locals().get("tenant_2", tenant).id,
                locals().get("tenant_3", tenant).id,
                locals().get("tenant_4", tenant).id,
            )


@pytest.mark.asyncio
async def test_execution_blocks_real_mutation_and_shell_artifacts(tmp_path):
    cases = [
        "terraform apply -auto-approve",
        "aws iam create-role --role-name admin",
        "diff --git a/a b/a\ngh pr create",
        "#!/bin/bash\naws s3 rm s3://bucket --recursive",
    ]
    async with AsyncSessionLocal() as db:
        tenant_ids = []
        try:
            for index, unsafe_content in enumerate(cases):
                tenant = await _tenant(db, f"phase8-block-{index}")
                tenant_ids.append(tenant.id)
                plan, artifact, approval, _ = await _approved_dry_run_fixture(db, tenant.id, sandbox_root=tmp_path)
                artifact.content_redacted = unsafe_content
                await db.flush()
                service = RemediationExecutionService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
                with pytest.raises(BadRequestException):
                    await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)
        finally:
            await _cleanup(db, *tenant_ids)


@pytest.mark.asyncio
async def test_execution_tenant_isolation_and_events_are_sanitized(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "phase8-a")
        tenant_b = await _tenant(db, "phase8-b")
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(
                db,
                tenant_a.id,
                content="Documentation-only fixture token=super-secret-value.",
                sandbox_root=tmp_path,
            )
            producer = FakeProducer()
            service = RemediationExecutionService(db, event_producer=producer, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job = await service.create_execution_job(tenant_a.id, plan.id, artifact.id, approval.id)
            verification = await service.execute_job(tenant_a.id, job.id)
            with pytest.raises(NotFoundException):
                await service.get_execution_job(tenant_b.id, job.id)
            assert "super-secret-value" not in _serialized(producer.events)
            assert "super-secret-value" not in _serialized(verification)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_api_execute_allows_safe_class_and_reads_verification(monkeypatch, tmp_path):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    monkeypatch.setattr(
        remediation_api,
        "RemediationExecutionService",
        lambda db, event_producer=None: RemediationExecutionService(
            db,
            event_producer=event_producer,
            sandbox_service=RemediationSandboxService(root_dir=tmp_path),
        ),
    )
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            analyst = await _user(db, tenant.id, "analyst", "phase8-api")
            plan, artifact, approval, _ = await _approved_dry_run_fixture(db, tenant.id, sandbox_root=tmp_path)
            response = await remediation_api.create_plan_artifact_execution(
                plan.id,
                artifact.id,
                CreateExecutionRequest(approval_id=approval.id),
                tenant=tenant,
                db=db,
                current_user=analyst,
            )
            assert response.job.status == RemediationExecutionStatus.succeeded.value
            assert response.verification_result is not None
            listed = await remediation_api.list_verification_results(limit=50, tenant=tenant, db=db, _user=analyst)
            assert listed.total == 1
            fetched = await remediation_api.get_verification_result(response.verification_result.id, tenant=tenant, db=db, _user=analyst)
            assert fetched.id == response.verification_result.id
        finally:
            await _cleanup(db, tenant.id)


def test_phase8_source_does_not_introduce_real_execution_clients_or_shell_execution():
    source = inspect.getsource(RemediationExecutionService).lower()
    forbidden = [
        "import subprocess",
        "subprocess.run",
        "boto3",
        "botocore",
        "google.cloud",
        "github import",
        "requests.",
        "httpx.",
        "git push origin",
        "vault_credentials",
    ]
    for term in forbidden:
        assert term not in source
