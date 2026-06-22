from __future__ import annotations

import inspect
import json
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.api.v1.endpoints import remediation as remediation_api
from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.remediation import (
    RemediationApprovalStatus,
    RemediationArtifactType,
    RemediationDryRunStatus,
    RemediationExecutionStatus,
    RemediationRiskLevel,
)
from app.schemas.remediation import CreateDryRunRequest
from app.services import remediation_sandbox_service
from app.services.remediation_dry_run_service import RemediationDryRunService
from app.services.remediation_sandbox_service import RemediationSandboxService
from app.services.remediation_state_machine import artifact_hash
from tests.test_sprint4_phase4_approval_workflow import (
    FakeProducer,
    _cleanup,
    _critical_validated_plan,
    _tenant,
    _user,
    _validated_plan,
)


def _artifact(artifact_type: RemediationArtifactType, content: str):
    return SimpleNamespace(artifact_type=artifact_type, content_redacted=content)


def _codes(items):
    return {item["code"] for item in items}


def _serialized(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        value = {key: nested for key, nested in value.__dict__.items() if not key.startswith("_")}
    return json.dumps(value, sort_keys=True, default=str).lower()


def test_sandbox_workspace_is_controlled_cleaned_and_blocks_path_traversal(tmp_path):
    service = RemediationSandboxService(root_dir=tmp_path)
    outcome = service.validate_artifact(
        _artifact(RemediationArtifactType.documentation_only, "Review-only documentation. No execution.")
    )

    assert outcome.status == RemediationDryRunStatus.succeeded
    assert not (tmp_path / outcome.sandbox_id).exists()
    service.create_workspace("dryrun-path-test")
    with pytest.raises(ValueError):
        service.workspace_file_path("dryrun-path-test", "../escape.txt")
    service.cleanup_workspace(tmp_path / "dryrun-path-test")


def test_sandbox_rejects_oversized_binary_and_shell_wrappers(tmp_path):
    service = RemediationSandboxService(root_dir=tmp_path, max_artifact_bytes=8)
    oversized = service.validate_artifact(_artifact(RemediationArtifactType.documentation_only, "x" * 32))
    assert oversized.status == RemediationDryRunStatus.rejected
    assert "artifact_too_large" in _codes(oversized.blocking_reasons)

    binary = RemediationSandboxService(root_dir=tmp_path).validate_artifact(
        _artifact(RemediationArtifactType.documentation_only, "safe\x00unsafe")
    )
    assert "binary_artifact" in _codes(binary.blocking_reasons)

    shell = RemediationSandboxService(root_dir=tmp_path).validate_artifact(
        _artifact(RemediationArtifactType.documentation_only, "#!/bin/bash\naws s3 rm s3://bucket --recursive")
    )
    assert "shell_wrapper" in _codes(shell.blocking_reasons)


def test_terraform_static_validator_blocks_apply_destroy_and_provisioners(monkeypatch, tmp_path):
    monkeypatch.setattr(remediation_sandbox_service.shutil, "which", lambda _: None)
    service = RemediationSandboxService(root_dir=tmp_path)
    unsafe = service.validate_artifact(
        _artifact(
            RemediationArtifactType.terraform_plan_draft,
            'resource "x" "y" { provisioner "local-exec" { command = "terraform apply" } }\nterraform destroy',
        )
    )
    assert unsafe.status == RemediationDryRunStatus.rejected
    assert {"terraform_apply", "terraform_destroy", "terraform_local_exec", "terraform_provisioner"} <= _codes(
        unsafe.blocking_reasons
    )

    safe = service.validate_artifact(
        _artifact(RemediationArtifactType.terraform_plan_draft, 'resource "aws_s3_bucket_public_access_block" "safe" {}')
    )
    assert safe.status == RemediationDryRunStatus.succeeded
    assert "terraform_validate_unavailable" in _codes(safe.warnings)


def test_static_validators_block_aws_github_and_iam_mutations(tmp_path):
    service = RemediationSandboxService(root_dir=tmp_path)
    aws = service.validate_artifact(_artifact(RemediationArtifactType.aws_cli_command_draft, "aws iam create-role --role-name admin"))
    assert aws.status == RemediationDryRunStatus.rejected
    assert "aws_mutating_command" in _codes(aws.blocking_reasons)

    github = service.validate_artifact(
        _artifact(RemediationArtifactType.github_pr_patch_draft, "diff --git a/a b/a\n+change\ngh pr create")
    )
    assert github.status == RemediationDryRunStatus.rejected
    assert "github_mutation" in _codes(github.blocking_reasons)

    iam = service.validate_artifact(
        _artifact(
            RemediationArtifactType.iam_policy_diff,
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
        )
    )
    assert iam.status == RemediationDryRunStatus.rejected
    assert "iam_wildcard_detected" in _codes(iam.blocking_reasons)

    doc = service.validate_artifact(_artifact(RemediationArtifactType.documentation_only, "Human review note only."))
    assert doc.status == RemediationDryRunStatus.succeeded


@pytest.mark.asyncio
async def test_dry_run_static_passes_without_approval_for_low_risk_and_events_are_sanitized(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, _ = await _validated_plan(
                db,
                tenant.id,
                content="Documentation-only draft. token=super-secret-value. No execution.",
                risk_level=RemediationRiskLevel.low,
            )
            producer = FakeProducer()
            service = RemediationDryRunService(
                db,
                event_producer=producer,
                sandbox_service=RemediationSandboxService(root_dir=tmp_path),
            )
            job = await service.create_dry_run_job(tenant.id, plan.id, artifact.id)
            result = await service.run_dry_run(tenant.id, job.id)

            assert result.status == RemediationDryRunStatus.succeeded
            assert job.status == RemediationExecutionStatus.dry_run_succeeded
            assert job.dry_run_result_id == result.id
            event_types = [event["event_type"] for _, event in producer.events]
            assert event_types == [
                "remediation.dry_run.queued",
                "remediation.dry_run.started",
                "remediation.dry_run.completed",
            ]
            assert "super-secret-value" not in _serialized(producer.events)
            assert "super-secret-value" not in _serialized(result)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_high_risk_dry_run_requires_approval_and_does_not_consume_it(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator", "requester")
            owner = await _user(db, tenant.id, "owner", "owner")
            plan, artifact, _ = await _critical_validated_plan(db, tenant.id)
            service = RemediationDryRunService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            with pytest.raises(BadRequestException):
                await service.create_dry_run_job(tenant.id, plan.id, artifact.id)

            approval_service = service.approval_service
            approval = await approval_service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            approval = await approval_service.approve(tenant.id, approval.id, owner.id, "Approved for dry-run.", mfa_verified=True)
            job = await service.create_dry_run_job(tenant.id, plan.id, artifact.id, approval_id=approval.id)
            result = await service.run_dry_run(tenant.id, job.id)

            assert result.status == RemediationDryRunStatus.succeeded
            refreshed = (await db.execute(select(type(approval)).where(type(approval).id == approval.id))).scalars().one()
            assert refreshed.status == RemediationApprovalStatus.approved
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_approval_hash_mismatch_blocks_required_dry_run(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            requester = await _user(db, tenant.id, "operator", "requester")
            owner = await _user(db, tenant.id, "owner", "owner")
            plan, artifact, _ = await _critical_validated_plan(db, tenant.id)
            service = RemediationDryRunService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            approval = await service.approval_service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            approval = await service.approval_service.approve(tenant.id, approval.id, owner.id, "Approved.", mfa_verified=True)

            artifact.content_redacted = "IAM diff draft changed after approval."
            artifact.artifact_hash = artifact_hash(artifact.artifact_type, artifact.content_redacted)
            await db.flush()

            with pytest.raises(BadRequestException):
                await service.create_dry_run_job(tenant.id, plan.id, artifact.id, approval_id=approval.id)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_dry_run_result_tenant_isolation(tmp_path):
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "phase7-a")
        tenant_b = await _tenant(db, "phase7-b")
        try:
            plan, artifact, _ = await _validated_plan(db, tenant_a.id)
            service = RemediationDryRunService(db, event_producer=None, sandbox_service=RemediationSandboxService(root_dir=tmp_path))
            job = await service.create_dry_run_job(tenant_a.id, plan.id, artifact.id)
            result = await service.run_dry_run(tenant_a.id, job.id)

            with pytest.raises(NotFoundException):
                await service.get_dry_run_result(tenant_b.id, result.id)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_api_dry_run_works_safely(monkeypatch, tmp_path):
    monkeypatch.setattr(remediation_api, "event_producer", None)
    monkeypatch.setattr(
        remediation_api,
        "RemediationDryRunService",
        lambda db, event_producer=None: RemediationDryRunService(
            db,
            event_producer=event_producer,
            sandbox_service=RemediationSandboxService(root_dir=tmp_path),
        ),
    )
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            analyst = await _user(db, tenant.id, "analyst", "analyst")
            plan, artifact, _ = await _validated_plan(db, tenant.id)
            response = await remediation_api.create_plan_artifact_dry_run(
                plan.id,
                artifact.id,
                CreateDryRunRequest(),
                tenant=tenant,
                db=db,
                current_user=analyst,
            )
            assert response.status == RemediationDryRunStatus.succeeded.value
            listed = await remediation_api.list_dry_runs(limit=50, tenant=tenant, db=db, _user=analyst)
            assert listed.total == 1
            fetched = await remediation_api.get_dry_run(response.id, tenant=tenant, db=db, _user=analyst)
            assert fetched.id == response.id

        finally:
            await _cleanup(db, tenant.id)


def test_phase7_source_does_not_introduce_execution_or_provider_clients():
    sandbox_source = inspect.getsource(RemediationSandboxService)
    dry_run_source = inspect.getsource(RemediationDryRunService)
    combined = f"{sandbox_source}\n{dry_run_source}".lower()
    forbidden = ["import subprocess", "subprocess.run", "boto3", "botocore", "requests.", "httpx.", "git push origin"]
    for term in forbidden:
        assert term not in combined
