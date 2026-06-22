from __future__ import annotations

import hashlib
import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import func, select, text

from app.core.database import AsyncSessionLocal
from app.core.exceptions import NotFoundException
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceAssessmentStatus,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    ComplianceGapSeverity,
    ComplianceGapType,
    ComplianceScoreBand,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.remediation import (
    RemediationApproval,
    RemediationArtifactType,
    RemediationExecutionJob,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
)
from app.models.tenant import Tenant
from app.services.compliance_seed_loader import seed_compliance_catalog
from app.services.remediation_plan_generator import NON_EXECUTING_NOTICE, RemediationPlanGenerator
from app.services.remediation_state_machine import artifact_hash


UNSAFE_TERMS = (
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz123456",
    "raw_provider_payload",
    "super-secret-token",
    "terraform apply",
    "aws s3api",
    "gh pr create",
)


class FakeProducer:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint4-phase2-{suffix}",
        slug=f"sprint4-phase2-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _integration(db, tenant_id: uuid.UUID, provider: CloudProvider) -> CloudIntegration:
    target = {
        CloudProvider.aws: "123456789012",
        CloudProvider.github: f"authclaw-test/repo-{uuid.uuid4().hex[:8]}",
        CloudProvider.gcp: f"authclaw-demo-{uuid.uuid4().hex[:8]}",
    }[provider]
    integration = CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=provider,
        target_identifier=target,
        display_name=f"{provider.value} phase2 test",
        status=IntegrationStatus.active,
        vault_reference_id=f"authclaw/tenants/{tenant_id}/integrations/{uuid.uuid4()}",
    )
    db.add(integration)
    await db.flush()
    return integration


async def _finding(
    db,
    integration_id: uuid.UUID,
    *,
    title: str,
    resource_id: str,
    severity: FindingSeverity = FindingSeverity.high,
    description: str = "Normalized provider finding summary.",
    remediation: str = "Review safe summarized remediation guidance.",
) -> SecurityFinding:
    dedup_input = f"{integration_id}:{title}:{resource_id}:{uuid.uuid4()}".encode("utf-8")
    finding = SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration_id,
        dedup_hash=hashlib.sha256(dedup_input).hexdigest(),
        external_id=f"finding-{uuid.uuid4()}",
        resource_id=resource_id,
        title=title,
        description=description,
        remediation_instructions=remediation,
        severity=severity,
        status=FindingStatus.active,
        resolved_at=None,
    )
    db.add(finding)
    await db.flush()
    return finding


async def _gap(db, tenant_id: uuid.UUID) -> ComplianceGap:
    await seed_compliance_catalog(db)
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
        {"tenant_id": str(tenant_id)},
    )
    framework = (
        await db.execute(select(ComplianceFramework).where(ComplianceFramework.key == "soc2"))
    ).scalars().first()
    assert framework is not None
    control = (
        await db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == framework.id))
    ).scalars().first()
    assert control is not None
    assessment = ComplianceAssessment(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        framework_id=framework.id,
        status=ComplianceAssessmentStatus.completed,
        score=42,
        score_band=ComplianceScoreBand.at_risk,
        inputs_hash=hashlib.sha256(f"{tenant_id}:{framework.id}".encode("utf-8")).hexdigest(),
        explanation="Synthetic assessment for Sprint 4 Phase 2 plan generation tests.",
    )
    db.add(assessment)
    await db.flush()
    gap = ComplianceGap(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        assessment_id=assessment.id,
        control_id=control.id,
        gap_type=ComplianceGapType.critical_open_risk,
        severity=ComplianceGapSeverity.critical,
        reason="Critical open risk needs reviewed remediation; not legal advice.",
        evidence_status="active",
        metadata_={"test": "sprint4_phase2"},
    )
    db.add(gap)
    await db.flush()
    return gap


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
            "compliance_gaps",
            "control_assessment_results",
            "compliance_assessments",
            "evidence_items",
            "finding_control_mappings",
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


async def _assert_generated(
    db,
    tenant_id: uuid.UUID,
    result,
    *,
    risk_level: RemediationRiskLevel,
    artifact_type: RemediationArtifactType,
    template_key: str,
) -> None:
    plan = result.plan
    artifact = result.artifacts[0]
    rollback = result.rollback_plan
    assert plan.tenant_id == tenant_id
    assert plan.status == RemediationPlanStatus.plan_drafted
    assert plan.risk_level == risk_level
    assert artifact.artifact_type == artifact_type
    assert artifact.risk_flags["template_key"] == template_key
    assert artifact.risk_flags["non_executing"] is True
    assert artifact.risk_flags["requires_future_policy_validation"] is True
    assert artifact.risk_flags["requires_future_human_approval"] is True
    assert artifact.content_redacted.startswith(NON_EXECUTING_NOTICE)
    assert artifact.artifact_hash == artifact_hash(artifact.artifact_type, artifact.content_redacted)
    assert rollback.plan_id == plan.id
    assert rollback.risk_level == risk_level

    assert await db.scalar(select(func.count(RemediationPolicyCheck.id)).where(RemediationPolicyCheck.plan_id == plan.id)) == 0
    assert await db.scalar(select(func.count(RemediationApproval.id)).where(RemediationApproval.plan_id == plan.id)) == 0
    assert await db.scalar(select(func.count(RemediationExecutionJob.id)).where(RemediationExecutionJob.plan_id == plan.id)) == 0

    serialized = json.dumps(
        {
            "summary": plan.summary,
            "impact": plan.expected_impact,
            "content": artifact.content_redacted,
            "diff": artifact.diff_summary,
            "flags": artifact.risk_flags,
            "rollback": rollback.rollback_steps,
        },
        sort_keys=True,
    ).lower()
    for term in UNSAFE_TERMS:
        assert term.lower() not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "provider",
        "title",
        "resource_id",
        "severity",
        "expected_risk",
        "expected_type",
        "template_key",
    ),
    [
        (
            CloudProvider.aws,
            "S3 bucket public access is enabled",
            "arn:aws:s3:::phase2-public-bucket",
            FindingSeverity.high,
            RemediationRiskLevel.high,
            RemediationArtifactType.terraform_plan_draft,
            "aws_s3_public_access_block",
        ),
        (
            CloudProvider.aws,
            "CloudTrail disabled for account logging",
            "arn:aws:cloudtrail:us-east-1:123456789012:trail/demo",
            FindingSeverity.medium,
            RemediationRiskLevel.medium,
            RemediationArtifactType.terraform_plan_draft,
            "aws_cloudtrail_enable_logging",
        ),
        (
            CloudProvider.aws,
            "IAM admin policy grants excessive permission",
            "arn:aws:iam::123456789012:role/phase2-admin",
            FindingSeverity.high,
            RemediationRiskLevel.critical,
            RemediationArtifactType.iam_policy_diff,
            "aws_iam_least_privilege_review",
        ),
        (
            CloudProvider.github,
            "Secret token leak detected",
            "authclaw-test/repo",
            FindingSeverity.high,
            RemediationRiskLevel.high,
            RemediationArtifactType.documentation_only,
            "github_secret_rotation_recommendation",
        ),
        (
            CloudProvider.github,
            "Branch protection missing required review",
            "authclaw-test/repo:main",
            FindingSeverity.medium,
            RemediationRiskLevel.medium,
            RemediationArtifactType.github_pr_patch_draft,
            "github_branch_protection_draft",
        ),
        (
            CloudProvider.gcp,
            "Storage bucket public allUsers binding",
            "//storage.googleapis.com/phase2-public-bucket",
            FindingSeverity.high,
            RemediationRiskLevel.high,
            RemediationArtifactType.terraform_plan_draft,
            "gcp_storage_public_access_review",
        ),
    ],
)
async def test_provider_findings_generate_deterministic_non_executing_plans(
    provider,
    title,
    resource_id,
    severity,
    expected_risk,
    expected_type,
    template_key,
):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, provider)
            finding = await _finding(
                db,
                integration.id,
                title=title,
                resource_id=resource_id,
                severity=severity,
                description=(
                    "Safe normalized description with token=super-secret-token "
                    "raw_provider_payload AKIAIOSFODNN7EXAMPLE"
                ),
                remediation="Review-only guidance ghp_abcdefghijklmnopqrstuvwxyz123456.",
            )
            producer = FakeProducer()
            generator = RemediationPlanGenerator(db, event_producer=producer)

            preview = await generator.preview_plan_inputs(tenant.id, "finding", finding.id)
            result = await generator.generate_from_finding(tenant.id, finding.id)

            assert preview["template_key"] == template_key
            await _assert_generated(
                db,
                tenant.id,
                result,
                risk_level=expected_risk,
                artifact_type=expected_type,
                template_key=template_key,
            )
            event_types = [event["event_type"] for _, event in producer.events]
            assert "remediation.plan.generated" in event_types
            assert "remediation.artifact.drafted" in event_types
            assert "remediation.rollback_plan.created" in event_types
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_compliance_gap_and_recommendation_generate_documentation_plan():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        tenant_id = tenant.id
        try:
            gap = await _gap(db, tenant_id)
            generator = RemediationPlanGenerator(db, event_producer=None)

            gap_result = await generator.generate_from_gap(tenant_id, gap.id)
            await _assert_generated(
                db,
                tenant_id,
                gap_result,
                risk_level=RemediationRiskLevel.critical,
                artifact_type=RemediationArtifactType.documentation_only,
                template_key="compliance_gap_critical_open_risk",
            )
            assert gap_result.plan.gap_id == gap.id
            assert gap_result.plan.recommendation_id is None

            recommendation_result = await generator.generate_from_recommendation(tenant_id, gap.id)
            await _assert_generated(
                db,
                tenant_id,
                recommendation_result,
                risk_level=RemediationRiskLevel.critical,
                artifact_type=RemediationArtifactType.documentation_only,
                template_key="compliance_gap_critical_open_risk",
            )
            assert recommendation_result.plan.gap_id == gap.id
            assert recommendation_result.plan.recommendation_id == gap.id
        finally:
            await db.rollback()
            await _cleanup(db, tenant_id)


@pytest.mark.asyncio
async def test_unknown_finding_falls_back_to_manual_review_and_tenant_isolation_is_enforced():
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(4))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(4))
        try:
            integration = await _integration(db, tenant_a.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="Unsupported provider finding shape",
                resource_id="arn:aws:unknown:::phase2",
                severity=FindingSeverity.low,
            )
            generator = RemediationPlanGenerator(db, event_producer=None)

            result = await generator.generate_from_finding(tenant_a.id, finding.id)
            await _assert_generated(
                db,
                tenant_a.id,
                result,
                risk_level=RemediationRiskLevel.low,
                artifact_type=RemediationArtifactType.documentation_only,
                template_key="unknown_finding_manual_review",
            )
            assert result.artifacts[0].risk_flags["rollback_uncertain"] is True

            with pytest.raises(NotFoundException):
                await generator.generate_from_finding(tenant_b.id, finding.id)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


def test_plan_generator_has_no_cloud_scm_or_execution_clients():
    source = inspect.getsource(RemediationPlanGenerator).lower()
    forbidden = (
        "boto3.client",
        "botocore",
        "subprocess",
        "requests.post",
        "requests.patch",
        "httpx.",
        "github(",
        "create_pull",
        "terraform apply",
        "terraform plan",
        "aws s3api",
        "gcloud ",
    )
    for token in forbidden:
        assert token not in source
