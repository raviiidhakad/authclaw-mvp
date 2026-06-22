from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceAssessmentStatus,
    ComplianceControl,
    ComplianceFramework,
    ComplianceFrameworkKey,
    ComplianceGap,
    ComplianceGapSeverity,
    ComplianceGapType,
    ComplianceScoreBand,
    ControlAssessmentResult,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.remediation import (
    RemediationArtifactType,
    RemediationDryRunResult,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationRiskLevel,
    RemediationVerificationResult,
)
from app.models.role import Role, UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.services.compliance_seed_loader import seed_compliance_catalog
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_dry_run_service import RemediationDryRunService
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_policy_validator import RemediationPolicyValidator
from app.services.remediation_sandbox_service import RemediationSandboxService
from app.services.remediation_state_machine import RemediationPlanService


DEMO_TENANT_SLUG = "authclaw-sprint4-demo"
DEMO_TENANT_NAME = "AuthClaw Sprint 4 Demo"
DEMO_ADMIN_EMAIL = "sprint4.demo.admin@authclaw-demo.com"
DEMO_OPERATOR_EMAIL = "sprint4.demo.operator@authclaw-demo.com"
DEMO_USER_PASSWORD = "demo-only-password"
DEMO_NAMESPACE = uuid.UUID("c15ec3e6-28a5-4888-98fa-cd9a6de93a47")


@dataclass(frozen=True)
class Sprint4DemoSummary:
    tenant_id: uuid.UUID
    admin_email: str
    operator_email: str
    plans: int
    artifacts: int
    rollback_plans: int
    policy_checks: int
    approvals: int
    dry_run_results: int
    execution_jobs: int
    verification_results: int
    succeeded_jobs: int
    verified_results: int
    blocked_jobs: int
    blocked_plan_id: uuid.UUID

    def as_safe_dict(self) -> dict[str, object]:
        return {
            "tenant_id": str(self.tenant_id),
            "admin_email": self.admin_email,
            "operator_email": self.operator_email,
            "plans": self.plans,
            "artifacts": self.artifacts,
            "rollback_plans": self.rollback_plans,
            "policy_checks": self.policy_checks,
            "approvals": self.approvals,
            "dry_run_results": self.dry_run_results,
            "execution_jobs": self.execution_jobs,
            "verification_results": self.verification_results,
            "succeeded_jobs": self.succeeded_jobs,
            "verified_results": self.verified_results,
            "blocked_jobs": self.blocked_jobs,
            "blocked_plan_id": str(self.blocked_plan_id),
        }


class NullProducer:
    async def publish(self, _topic, _event) -> None:
        return None


async def seed_demo_dataset(db: AsyncSession) -> Sprint4DemoSummary:
    await seed_compliance_catalog(db)
    tenant = await _ensure_tenant(db)
    await _reset_demo_tenant_data(db, tenant.id)
    admin = await _ensure_user(db, tenant.id, DEMO_ADMIN_EMAIL, "Demo", "Admin", "owner")
    operator = await _ensure_user(db, tenant.id, DEMO_OPERATOR_EMAIL, "Demo", "Operator", "operator")
    integration = await _ensure_integration(db, tenant.id)
    findings = await _ensure_findings(db, integration)
    gap = await _ensure_compliance_gap(db, tenant.id, findings[1])

    plan_service = RemediationPlanService(db, event_producer=NullProducer())
    validator = RemediationPolicyValidator(db, event_producer=NullProducer())
    approvals = RemediationApprovalService(db, event_producer=NullProducer())
    sandbox = RemediationSandboxService()
    dry_runs = RemediationDryRunService(db, event_producer=NullProducer(), sandbox_service=sandbox)
    execution = RemediationExecutionService(db, event_producer=NullProducer(), sandbox_service=sandbox)

    await _seed_documentation_flow(
        tenant.id,
        operator.id,
        admin.id,
        findings[0].id,
        plan_service,
        validator,
        approvals,
        dry_runs,
        execution,
    )
    await _seed_simulated_provider_flow(
        tenant.id,
        operator.id,
        admin.id,
        findings[1].id,
        gap.id,
        plan_service,
        validator,
        approvals,
        dry_runs,
        execution,
    )
    blocked_plan = await _seed_blocked_mutation_flow(
        tenant.id,
        operator.id,
        findings[2].id,
        plan_service,
        validator,
        execution,
    )

    await db.commit()
    summary = await _summary(db, tenant.id, blocked_plan.id)
    assert_safe_summary(summary, [])
    return summary


async def _seed_documentation_flow(
    tenant_id: uuid.UUID,
    requester_id: uuid.UUID,
    approver_id: uuid.UUID,
    finding_id: uuid.UUID,
    plan_service: RemediationPlanService,
    validator: RemediationPolicyValidator,
    approvals: RemediationApprovalService,
    dry_runs: RemediationDryRunService,
    execution: RemediationExecutionService,
) -> None:
    plan = await plan_service.create_draft_plan_shell(
        tenant_id=tenant_id,
        finding_id=finding_id,
        actor_id=requester_id,
        summary="Sprint 4 demo: documentation-only remediation record",
        expected_impact=(
            "Records an evidence-supported documentation update for audit review. "
            "No provider, shell, Terraform, or GitHub action is executed."
        ),
        risk_level=RemediationRiskLevel.low,
    )
    artifact = await plan_service.attach_artifact_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=RemediationArtifactType.documentation_only,
        content=(
            "Documentation-only remediation artifact.\n"
            "- Record the reviewed control owner decision.\n"
            "- Link the source finding and evidence summary.\n"
            "- Note that this is not legal advice and not a compliance guarantee.\n"
            "- No external mutation is attempted."
        ),
        diff_summary="Create a review note for a synthetic access-control finding.",
        risk_flags={"template_key": "documentation_only", "execution_adapter": "documentation_only", "rollback_uncertain": False},
    )
    await plan_service.attach_rollback_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        rollback_steps="Archive the review note and reopen the linked finding for human review.",
        risk_level=RemediationRiskLevel.low,
    )
    await validator.validate_plan(tenant_id, plan.id, actor_id=requester_id)
    approval = await approvals.request_approval(tenant_id, plan.id, requested_by=requester_id, reason="Sprint 4 documentation-only demo approval.")
    approval = await approvals.approve(tenant_id, approval.id, approver_id, "Approved safe documentation-only demo flow.", mfa_verified=False)
    dry_job = await dry_runs.create_dry_run_job(tenant_id, plan.id, artifact.id, approval_id=approval.id, actor_id=requester_id)
    await dry_runs.run_dry_run(tenant_id, dry_job.id)
    job = await execution.create_execution_job(tenant_id, plan.id, artifact.id, approval.id, actor_id=requester_id)
    await execution.execute_job(tenant_id, job.id)


async def _seed_simulated_provider_flow(
    tenant_id: uuid.UUID,
    requester_id: uuid.UUID,
    approver_id: uuid.UUID,
    finding_id: uuid.UUID,
    gap_id: uuid.UUID,
    plan_service: RemediationPlanService,
    validator: RemediationPolicyValidator,
    approvals: RemediationApprovalService,
    dry_runs: RemediationDryRunService,
    execution: RemediationExecutionService,
) -> None:
    plan = await plan_service.create_draft_plan_shell(
        tenant_id=tenant_id,
        finding_id=finding_id,
        gap_id=gap_id,
        actor_id=requester_id,
        summary="Sprint 4 demo: simulated provider remediation",
        expected_impact=(
            "Shows the provider-related remediation lifecycle using the simulated adapter only. "
            "No external provider call, credential retrieval, or resource mutation occurs."
        ),
        risk_level=RemediationRiskLevel.high,
    )
    artifact = await plan_service.attach_artifact_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=RemediationArtifactType.documentation_only,
        content=(
            "Documentation-only simulated provider remediation artifact.\n"
            "- Simulate expected CloudTrail logging remediation outcome.\n"
            "- Confirm dry-run and verification rows are recorded.\n"
            "- No AWS API call, CLI command, infrastructure tool action, repository write, or provider mutation is attempted."
        ),
        diff_summary="Simulate provider remediation visibility for a synthetic CloudTrail finding.",
        risk_flags={"template_key": "simulation", "execution_adapter": "simulated_provider", "rollback_uncertain": False},
    )
    await plan_service.attach_rollback_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        rollback_steps="Mark the simulated provider remediation as inconclusive and return the finding to needs-review.",
        risk_level=RemediationRiskLevel.high,
    )
    await validator.validate_plan(tenant_id, plan.id, actor_id=requester_id)
    approval = await approvals.request_approval(tenant_id, plan.id, requested_by=requester_id, reason="Sprint 4 simulated provider demo approval.")
    approval = await approvals.approve(tenant_id, approval.id, approver_id, "Approved simulated provider demo after review.", mfa_verified=True)
    dry_job = await dry_runs.create_dry_run_job(tenant_id, plan.id, artifact.id, approval_id=approval.id, actor_id=requester_id)
    await dry_runs.run_dry_run(tenant_id, dry_job.id)
    job = await execution.create_execution_job(tenant_id, plan.id, artifact.id, approval.id, actor_id=requester_id)
    await execution.execute_job(tenant_id, job.id)


async def _seed_blocked_mutation_flow(
    tenant_id: uuid.UUID,
    requester_id: uuid.UUID,
    finding_id: uuid.UUID,
    plan_service: RemediationPlanService,
    validator: RemediationPolicyValidator,
    execution: RemediationExecutionService,
) -> RemediationPlan:
    plan = await plan_service.create_draft_plan_shell(
        tenant_id=tenant_id,
        finding_id=finding_id,
        actor_id=requester_id,
        summary="Sprint 4 demo: blocked high-risk mutation artifact",
        expected_impact=(
            "Demonstrates that real mutation-shaped remediation remains blocked. "
            "The artifact is retained only as a redacted review object and cannot execute."
        ),
        risk_level=RemediationRiskLevel.critical,
    )
    await plan_service.attach_artifact_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=RemediationArtifactType.terraform_plan_draft,
        content=(
            "# BLOCKED DEMO ARTIFACT - do not execute\n"
            "terraform apply -auto-approve\n"
            "aws iam create-role --role-name authclaw-demo-admin\n"
        ),
        diff_summary="Blocked destructive mutation shape for Sprint 4 acceptance.",
        risk_flags={"template_key": "blocked_real_mutation", "execution_adapter": "real_provider", "rollback_uncertain": True},
    )
    await plan_service.attach_rollback_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        rollback_steps="No rollback execution is available because the mutation is blocked before execution.",
        risk_level=RemediationRiskLevel.critical,
    )
    validation = await validator.validate_plan(tenant_id, plan.id, actor_id=requester_id)
    if validation.policy_check.passed:
        raise RuntimeError("Blocked mutation demo unexpectedly passed policy validation")
    await execution.block_execution(
        tenant_id,
        plan.id,
        "Blocked mutation demo: Terraform apply, AWS mutation, provider credentials, and shell execution are not allowed.",
    )
    return plan


async def _ensure_tenant(db: AsyncSession) -> Tenant:
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().first()
    if tenant is None:
        tenant = Tenant(
            id=uuid.uuid5(DEMO_NAMESPACE, "tenant"),
            name=DEMO_TENANT_NAME,
            slug=DEMO_TENANT_SLUG,
            settings={"demo_dataset": "sprint4_phase9", "fake_data_only": True, "external_calls": False},
        )
        db.add(tenant)
        await db.flush()
    else:
        tenant.name = DEMO_TENANT_NAME
        tenant.settings = {"demo_dataset": "sprint4_phase9", "fake_data_only": True, "external_calls": False}
    return tenant


async def _ensure_user(db: AsyncSession, tenant_id: uuid.UUID, email: str, first_name: str, last_name: str, role_name: str) -> User:
    role = await _ensure_role(db, role_name)
    user = (await db.execute(select(User).where(User.tenant_id == tenant_id, User.email == email))).scalars().first()
    if user is None:
        user = User(
            id=uuid.uuid5(DEMO_NAMESPACE, f"user:{email}"),
            tenant_id=tenant_id,
            email=email,
            password_hash=get_password_hash(DEMO_USER_PASSWORD),
            first_name=first_name,
            last_name=last_name,
            is_active=True,
            mfa_enabled=True,
            mfa_secret="demo-mfa-not-a-real-secret",
        )
        db.add(user)
        await db.flush()
    else:
        user.password_hash = get_password_hash(DEMO_USER_PASSWORD)
        user.is_active = True
        user.mfa_enabled = True
        user.mfa_secret = "demo-mfa-not-a-real-secret"

    existing = (
        await db.execute(
            select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id, UserRole.tenant_id == tenant_id)
        )
    ).scalars().first()
    if existing is None:
        db.add(UserRole(id=uuid.uuid5(DEMO_NAMESPACE, f"user-role:{email}:{role_name}"), user_id=user.id, role_id=role.id, tenant_id=tenant_id))
    await db.flush()
    return user


async def _ensure_role(db: AsyncSession, name: str) -> Role:
    role = (await db.execute(select(Role).where(Role.name == name))).scalars().first()
    if role is None:
        role = Role(id=uuid.uuid5(DEMO_NAMESPACE, f"role:{name}"), name=name, description=f"Sprint 4 demo {name} role", is_system=True)
        db.add(role)
        await db.flush()
    return role


async def _ensure_integration(db: AsyncSession, tenant_id: uuid.UUID) -> CloudIntegration:
    integration = CloudIntegration(
        id=uuid.uuid5(DEMO_NAMESPACE, "integration:aws:111122223333"),
        tenant_id=tenant_id,
        provider_type=CloudProvider.aws,
        target_identifier="111122223333",
        display_name="AWS Sprint 4 fake demo account",
        status=IntegrationStatus.active,
        vault_reference_id=f"demo/authclaw/tenants/{tenant_id}/integrations/aws-sprint4-fake",
        last_sync_finding_count=3,
    )
    db.add(integration)
    await db.flush()
    return integration


async def _ensure_findings(db: AsyncSession, integration: CloudIntegration) -> list[SecurityFinding]:
    specs = [
        (
            "sprint4-doc-only-review",
            "arn:aws:s3:::sprint4-demo-docs",
            "Documentation evidence needs owner review",
            "Synthetic finding for a documentation-only remediation lifecycle.",
            FindingSeverity.low,
        ),
        (
            "sprint4-cloudtrail-simulated",
            "arn:aws:cloudtrail:us-east-1:111122223333:trail/sprint4-demo",
            "CloudTrail logging simulation needed",
            "Synthetic finding used to prove simulated provider execution without external calls.",
            FindingSeverity.high,
        ),
        (
            "sprint4-blocked-mutation",
            "arn:aws:iam::111122223333:role/sprint4-demo-admin",
            "Privileged IAM mutation is blocked",
            "Synthetic finding used to prove destructive mutation artifacts cannot execute.",
            FindingSeverity.critical,
        ),
    ]
    findings: list[SecurityFinding] = []
    for external_id, resource_id, title, description, severity in specs:
        finding = SecurityFinding(
            id=uuid.uuid5(DEMO_NAMESPACE, f"finding:{external_id}"),
            integration_id=integration.id,
            dedup_hash=hashlib.sha256(f"{integration.id}:{external_id}:{resource_id}".encode("utf-8")).hexdigest(),
            external_id=external_id,
            resource_id=resource_id,
            title=title,
            description=f"{description} Fake data only; no raw provider payload is stored.",
            remediation_instructions="Use the Sprint 4 demo remediation lifecycle. No automatic destructive action is allowed.",
            severity=severity,
            status=FindingStatus.active,
            resolved_at=None,
        )
        db.add(finding)
        findings.append(finding)
    await db.flush()
    return findings


async def _ensure_compliance_gap(db: AsyncSession, tenant_id: uuid.UUID, finding: SecurityFinding) -> ComplianceGap:
    framework = (
        await db.execute(select(ComplianceFramework).where(ComplianceFramework.key == ComplianceFrameworkKey.soc2).order_by(ComplianceFramework.version.desc()))
    ).scalars().first()
    if framework is None:
        raise RuntimeError("SOC 2 framework is required for Sprint 4 demo seeding")
    control = (
        await db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == framework.id).order_by(ComplianceControl.sort_order.asc()))
    ).scalars().first()
    if control is None:
        raise RuntimeError("SOC 2 control is required for Sprint 4 demo seeding")

    assessment = ComplianceAssessment(
        id=uuid.uuid5(DEMO_NAMESPACE, "assessment:sprint4"),
        tenant_id=tenant_id,
        framework_id=framework.id,
        status=ComplianceAssessmentStatus.completed,
        score=72.0,
        score_band=ComplianceScoreBand.at_risk,
        inputs_hash=hashlib.sha256(f"{tenant_id}:sprint4-demo".encode("utf-8")).hexdigest(),
        explanation="Evidence-supported demo posture needs review. This is not legal advice or a compliance guarantee.",
    )
    db.add(assessment)
    await db.flush()
    db.add(
        ControlAssessmentResult(
            id=uuid.uuid5(DEMO_NAMESPACE, "control-result:sprint4"),
            tenant_id=tenant_id,
            assessment_id=assessment.id,
            control_id=control.id,
            score=72.0,
            score_band=ComplianceScoreBand.at_risk,
            evidence_count=1,
            gap_count=1,
            explanation="Synthetic CloudTrail evidence gap needs review before remediation planning.",
            metadata_={"demo_dataset": "sprint4_phase9"},
        )
    )
    gap = ComplianceGap(
        id=uuid.uuid5(DEMO_NAMESPACE, "gap:sprint4-cloudtrail"),
        tenant_id=tenant_id,
        assessment_id=assessment.id,
        control_id=control.id,
        evidence_id=None,
        mapping_id=None,
        finding_id=finding.id,
        gap_type=ComplianceGapType.unresolved_finding,
        severity=ComplianceGapSeverity.high,
        reason="CloudTrail logging evidence needs simulated provider remediation review.",
        evidence_status="needs_review",
        metadata_={"demo_dataset": "sprint4_phase9", "recommendation_id": str(uuid.uuid5(DEMO_NAMESPACE, "recommendation:sprint4-cloudtrail"))},
    )
    db.add(gap)
    await db.flush()
    return gap


async def _reset_demo_tenant_data(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await _set_tenant_context(db, tenant_id)
    for table in (
        "remediation_audit_links",
        "remediation_verification_results",
        "remediation_dry_run_results",
        "remediation_execution_jobs",
        "remediation_approvals",
        "remediation_policy_checks",
        "remediation_rollback_plans",
        "remediation_artifacts",
        "remediation_plans",
        "compliance_gaps",
        "control_assessment_results",
        "compliance_assessments",
        "user_roles",
        "users",
    ):
        await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
    await db.execute(
        delete(SecurityFinding).where(
            SecurityFinding.integration_id.in_(
                select(CloudIntegration.id).where(CloudIntegration.tenant_id == tenant_id)
            )
        )
    )
    await db.execute(delete(CloudIntegration).where(CloudIntegration.tenant_id == tenant_id))
    await db.flush()


async def _summary(db: AsyncSession, tenant_id: uuid.UUID, blocked_plan_id: uuid.UUID) -> Sprint4DemoSummary:
    await _set_tenant_context(db, tenant_id)
    return Sprint4DemoSummary(
        tenant_id=tenant_id,
        admin_email=DEMO_ADMIN_EMAIL,
        operator_email=DEMO_OPERATOR_EMAIL,
        plans=await _count(db, RemediationPlan, tenant_id),
        artifacts=await _table_count(db, "remediation_artifacts", tenant_id),
        rollback_plans=await _table_count(db, "remediation_rollback_plans", tenant_id),
        policy_checks=await _table_count(db, "remediation_policy_checks", tenant_id),
        approvals=await _table_count(db, "remediation_approvals", tenant_id),
        dry_run_results=await _count(db, RemediationDryRunResult, tenant_id),
        execution_jobs=await _count(db, RemediationExecutionJob, tenant_id),
        verification_results=await _count(db, RemediationVerificationResult, tenant_id),
        succeeded_jobs=int(
            await db.scalar(
                select(func.count(RemediationExecutionJob.id)).where(
                    RemediationExecutionJob.tenant_id == tenant_id,
                    RemediationExecutionJob.status == RemediationExecutionStatus.succeeded,
                )
            )
            or 0
        ),
        verified_results=int(
            await db.scalar(
                select(func.count(RemediationVerificationResult.id)).where(
                    RemediationVerificationResult.tenant_id == tenant_id,
                    RemediationVerificationResult.verified.is_(True),
                )
            )
            or 0
        ),
        blocked_jobs=int(
            await db.scalar(
                select(func.count(RemediationExecutionJob.id)).where(
                    RemediationExecutionJob.tenant_id == tenant_id,
                    RemediationExecutionJob.status == RemediationExecutionStatus.disabled,
                )
            )
            or 0
        ),
        blocked_plan_id=blocked_plan_id,
    )


async def _count(db: AsyncSession, model, tenant_id: uuid.UUID) -> int:
    return int(await db.scalar(select(func.count(model.id)).where(model.tenant_id == tenant_id)) or 0)


async def _table_count(db: AsyncSession, table: str, tenant_id: uuid.UUID) -> int:
    return int(await db.scalar(text(f"SELECT count(id) FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id}) or 0)


async def _set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


def assert_safe_summary(summary: Sprint4DemoSummary, serialized_payloads: Iterable[object]) -> None:
    unsafe_terms = (
        "AKIA",
        "BEGIN PRIVATE KEY",
        "ghp_",
        "raw_provider_payload",
        "super-secret",
        "aws_secret_access_key",
        "you are compliant",
        "legally compliant",
    )
    haystack = json.dumps([summary.as_safe_dict(), *serialized_payloads], default=str).lower()
    for term in unsafe_terms:
        assert term.lower() not in haystack


async def main() -> None:
    async with AsyncSessionLocal() as db:
        summary = await seed_demo_dataset(db)
    print("Seeded Sprint 4 demo dataset:")
    print(json.dumps(summary.as_safe_dict(), indent=2, sort_keys=True))
    print("Demo login:")
    print(f"  email={DEMO_ADMIN_EMAIL}")
    print(f"  password={DEMO_USER_PASSWORD}")


if __name__ == "__main__":
    asyncio.run(main())
