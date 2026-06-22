from __future__ import annotations

import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import func, select, text

from app.core.database import AsyncSessionLocal
from app.core.exceptions import NotFoundException
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalLevel,
    RemediationArtifact,
    RemediationArtifactType,
    RemediationExecutionJob,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
)
from app.models.tenant import Tenant
from app.services.remediation_policy_validator import RemediationPolicyValidator
from app.services.remediation_state_machine import (
    RemediationPlanService,
    RemediationStateError,
    RemediationStateMachine,
    artifact_hash,
)


RAW_SECRET = "ghp_abcdefghijklmnopqrstuvwxyz123456"


class FakeProducer:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint4-phase3-{suffix}",
        slug=f"sprint4-phase3-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _draft(
    db,
    tenant_id: uuid.UUID,
    *,
    artifact_type: RemediationArtifactType = RemediationArtifactType.documentation_only,
    content: str = "Documentation-only draft. Human review only. No execution.",
    risk_flags: dict | None = None,
    rollback: bool = True,
    risk_level: RemediationRiskLevel = RemediationRiskLevel.medium,
):
    service = RemediationPlanService(db, event_producer=None)
    plan = await service.create_draft_plan_shell(
        tenant_id=tenant_id,
        summary="Sprint 4 Phase 3 validation fixture.",
        expected_impact="Validation-only test plan. No execution.",
        risk_level=risk_level,
    )
    artifact = await service.attach_artifact_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=artifact_type,
        content=content,
        diff_summary="Validation fixture diff summary.",
        risk_flags=risk_flags or {"template_key": "manual_documentation_review", "rollback_uncertain": False},
    )
    rollback_plan = None
    if rollback:
        rollback_plan = await service.attach_rollback_placeholder(
            tenant_id=tenant_id,
            plan_id=plan.id,
            rollback_steps="Restore the previous reviewed configuration if a future approved change is made.",
            risk_level=risk_level,
        )
    return plan, artifact, rollback_plan


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
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
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


@pytest.mark.asyncio
async def test_safe_documentation_plan_passes_and_transitions_to_validated():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            producer = FakeProducer()
            plan, artifact, _ = await _draft(db, tenant.id)
            result = await RemediationPolicyValidator(db, event_producer=producer).validate_plan(tenant.id, plan.id)

            assert result.policy_check.passed is True
            assert result.policy_check.artifact_id == artifact.id
            assert result.policy_check.required_approval_level == RemediationApprovalLevel.admin
            assert result.plan.status == RemediationPlanStatus.plan_validated
            assert await db.scalar(select(func.count(RemediationApproval.id)).where(RemediationApproval.plan_id == plan.id)) == 0
            assert await db.scalar(select(func.count(RemediationExecutionJob.id)).where(RemediationExecutionJob.plan_id == plan.id)) == 0
            event_types = [event["event_type"] for _, event in producer.events]
            assert "remediation.plan.validated" in event_types
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "artifact_type", "risk_flags", "warning_code", "approval_level"),
    [
        (
            "# Terraform draft only; do not apply.\nresource \"aws_s3_bucket_public_access_block\" \"x\" { block_public_acls = true restrict_public_buckets = true }",
            RemediationArtifactType.terraform_plan_draft,
            {"template_key": "aws_s3_public_access_block", "rollback_uncertain": True},
            "public_access_change",
            RemediationApprovalLevel.owner,
        ),
        (
            "resource \"aws_cloudtrail\" \"trail\" { enable_logging = true is_multi_region_trail = true }",
            RemediationArtifactType.terraform_plan_draft,
            {"template_key": "aws_cloudtrail_enable_logging", "rollback_uncertain": False},
            "logging_configuration_change",
            RemediationApprovalLevel.owner,
        ),
        (
            "Settings draft only. Branch protection required review and status checks enabled.",
            RemediationArtifactType.github_pr_patch_draft,
            {"template_key": "github_branch_protection_draft", "rollback_uncertain": False},
            "github_branch_protection_change",
            RemediationApprovalLevel.owner,
        ),
    ],
)
async def test_safe_infra_drafts_pass_with_warnings_and_elevated_approval(
    content,
    artifact_type,
    risk_flags,
    warning_code,
    approval_level,
):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, _, _ = await _draft(
                db,
                tenant.id,
                artifact_type=artifact_type,
                content=content,
                risk_flags=risk_flags,
                risk_level=RemediationRiskLevel.high,
            )
            result = await RemediationPolicyValidator(db, event_producer=None).validate_plan(tenant.id, plan.id)

            assert result.policy_check.passed is True
            assert result.policy_check.required_approval_level == approval_level
            warning_codes = {warning["code"] for warning in result.policy_check.warnings}
            assert warning_code in warning_codes
            assert result.plan.status == RemediationPlanStatus.plan_validated
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "expected_code"),
    [
        ('{"Statement":[{"Action":"*","Resource":"*","Effect":"Allow"}]}', "iam_wildcard"),
        ("Attach AdministratorAccess to the reviewed role.", "privilege_escalation"),
        ("terraform apply -auto-approve", "terraform_apply"),
        ("#!/bin/bash\naws s3 ls", "shell_wrapper"),
        ("export AWS_SECRET_ACCESS_KEY=example", "credential_export"),
        ("terraform destroy -auto-approve", "terraform_destroy"),
        ("token=" + RAW_SECRET, "secret_like_content"),
        ("resource \"aws_s3_bucket_acl\" \"x\" { acl = \"public-read\" }", "public_access_enablement"),
    ],
)
async def test_dangerous_artifacts_are_blocked_and_do_not_transition(content, expected_code):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, _ = await _draft(
                db,
                tenant.id,
                artifact_type=RemediationArtifactType.iam_policy_diff,
                content="Initial safe placeholder.",
                risk_flags={"template_key": "aws_iam_least_privilege_review", "rollback_uncertain": False},
                risk_level=RemediationRiskLevel.critical,
            )
            artifact.content_redacted = content
            artifact.artifact_hash = artifact_hash(artifact.artifact_type, artifact.content_redacted)
            await db.flush()

            result = await RemediationPolicyValidator(db, event_producer=None).validate_artifact(tenant.id, artifact.id)

            assert result.policy_check.passed is False
            assert result.policy_check.required_approval_level == RemediationApprovalLevel.security_admin
            assert expected_code in {reason["code"] for reason in result.policy_check.blocking_reasons}
            assert result.plan.status == RemediationPlanStatus.plan_drafted
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_missing_rollback_and_artifact_hash_mismatch_block_validation():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            missing_rollback_plan, _, _ = await _draft(db, tenant.id, rollback=False)
            missing_result = await RemediationPolicyValidator(db, event_producer=None).validate_plan(
                tenant.id,
                missing_rollback_plan.id,
            )
            assert missing_result.policy_check.passed is False
            assert "missing_rollback_plan" in {reason["code"] for reason in missing_result.policy_check.blocking_reasons}
            assert missing_result.plan.status == RemediationPlanStatus.plan_drafted

            plan, artifact, _ = await _draft(db, tenant.id)
            artifact.artifact_hash = "0" * 64
            await db.flush()
            mismatch_result = await RemediationPolicyValidator(db, event_producer=None).validate_artifact(tenant.id, artifact.id)
            assert mismatch_result.policy_check.passed is False
            assert "artifact_hash_mismatch" in {reason["code"] for reason in mismatch_result.policy_check.blocking_reasons}
            assert mismatch_result.plan.status == RemediationPlanStatus.plan_drafted
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_policy_check_hash_is_deterministic_and_latest_lookup_is_tenant_scoped():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, _, _ = await _draft(db, tenant.id)
            validator = RemediationPolicyValidator(db, event_producer=None)
            first = await validator.validate_plan(tenant.id, plan.id)
            second = await validator.validate_plan(tenant.id, plan.id)
            latest = await validator.get_latest_policy_check(tenant.id, plan.id)

            assert first.policy_check.policy_check_hash == second.policy_check.policy_check_hash
            assert first.policy_check.id == second.policy_check.id
            assert latest is not None
            assert latest.policy_check_hash == first.policy_check.policy_check_hash
            assert await db.scalar(select(func.count(RemediationPolicyCheck.id)).where(RemediationPolicyCheck.plan_id == plan.id)) == 1
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_failed_validation_cannot_request_approval_and_events_are_sanitized():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            producer = FakeProducer()
            plan, artifact, _ = await _draft(db, tenant.id)
            artifact.content_redacted = "token=" + RAW_SECRET
            artifact.artifact_hash = artifact_hash(artifact.artifact_type, artifact.content_redacted)
            await db.flush()

            result = await RemediationPolicyValidator(db, event_producer=producer).validate_plan(tenant.id, plan.id)
            assert result.policy_check.passed is False
            with pytest.raises(RemediationStateError):
                await RemediationStateMachine(db, event_producer=None).transition_plan(
                    tenant.id,
                    plan.id,
                    RemediationPlanStatus.approval_requested,
                    context={
                        "artifact_hash": artifact.artifact_hash,
                        "policy_check_hash": result.policy_check.policy_check_hash,
                    },
                )

            serialized_events = json.dumps([event for _, event in producer.events], sort_keys=True).lower()
            assert RAW_SECRET.lower() not in serialized_events
            assert "content_redacted" not in serialized_events
            assert "raw_provider_payload" not in serialized_events
            assert "remediation.policy_check.failed" in serialized_events
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_validate_artifact_enforces_tenant_isolation():
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(4))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(4))
        try:
            _, artifact, _ = await _draft(db, tenant_a.id)
            with pytest.raises(NotFoundException):
                await RemediationPolicyValidator(db, event_producer=None).validate_artifact(tenant_b.id, artifact.id)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


def test_policy_validator_has_no_execution_or_provider_clients():
    source = inspect.getsource(RemediationPolicyValidator).lower()
    forbidden = (
        "import subprocess",
        "os.system",
        "boto3.client",
        "botocore",
        "requests.",
        "httpx.",
        "github(",
        "create_pull",
        "hvac",
        "vault",
    )
    for token in forbidden:
        assert token not in source
