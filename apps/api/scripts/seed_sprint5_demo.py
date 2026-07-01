from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import AsyncSessionLocal
from app.core.rate_limit.tenant_limiter import LimitDecision
from app.core.security import get_password_hash
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceAssessmentStatus,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    ComplianceGapSeverity,
    ComplianceGapType,
    ComplianceScoreBand,
    ControlAssessmentResult,
    EvidenceItem,
    EvidenceSourceType,
    EvidenceStatus,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationArtifactStatus,
    RemediationArtifactType,
    RemediationDryRunResult,
    RemediationDryRunStatus,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationRiskLevel,
    RemediationVerificationResult,
    RemediationVerificationStatus,
)
from app.models.role import Role, UserRole
from app.models.tenant import Tenant
from app.models.trust import ReportAccessLog, ReportRun, ReportTemplate, TrustNotification
from app.models.user import User
from app.services.trust_activity import TrustNotificationService
from app.services.trust_reporting import (
    EvidencePackageBuilder,
    EvidencePackageRequest,
    ReportGenerationRequest,
    ReportGenerationService,
    hash_access_metadata,
)


DEMO_TENANT_SLUG = "authclaw-sprint5-demo"
DEMO_TENANT_NAME = "AuthClaw Sprint 5 Demo"
DEMO_ADMIN_EMAIL = "demo.admin@authclaw-demo.com"
DEMO_USER_PASSWORD = "demo-only-password"
DEMO_NAMESPACE = uuid.UUID("7149f427-656b-45f3-89f1-95a9df0c9462")


class _DemoReportLimiter:
    async def check_report_generation(self, _db: AsyncSession, _tenant_id: uuid.UUID) -> LimitDecision:
        return LimitDecision(allowed=True, scope="report_generation", plan="demo_seed")


@dataclass(frozen=True)
class Sprint5DemoSummary:
    tenant_id: uuid.UUID
    admin_email: str
    templates: int
    report_runs: int
    report_artifacts: int
    export_manifests: int
    evidence_packages: int
    access_logs: int
    notifications: int
    timeline_minimum_items: int

    def as_safe_dict(self) -> dict[str, object]:
        return {
            "tenant_id": str(self.tenant_id),
            "admin_email": self.admin_email,
            "templates": self.templates,
            "report_runs": self.report_runs,
            "report_artifacts": self.report_artifacts,
            "export_manifests": self.export_manifests,
            "evidence_packages": self.evidence_packages,
            "access_logs": self.access_logs,
            "notifications": self.notifications,
            "timeline_minimum_items": self.timeline_minimum_items,
        }


async def seed_demo_dataset(db: AsyncSession) -> Sprint5DemoSummary:
    tenant = await _ensure_tenant(db)
    await _reset_demo_tenant_data(db, tenant.id)
    admin = await _ensure_user(db, tenant.id)
    framework, control = await _ensure_framework_and_control(db)
    integration = await _seed_integration(db, tenant.id)
    finding = await _seed_finding(db, integration)
    evidence = await _seed_compliance(db, tenant.id, framework.id, control.id, integration.id, finding.id)
    await _seed_remediation(db, tenant.id, admin.id, integration.id, finding.id, evidence.id)
    template = await _seed_template(db, tenant.id, admin.id)
    demo_report_limiter = _DemoReportLimiter()

    report_result = await ReportGenerationService(db, event_producer=None, rate_limiter=demo_report_limiter).generate_report(
        tenant.id,
        ReportGenerationRequest(
            report_type="trust_overview",
            template_id=template.id,
            requested_by=admin.id,
            filters={"scope": "sprint5-demo", "audience": "internal-review"},
            retention_days=30,
        ),
    )
    package_result = await EvidencePackageBuilder(db, event_producer=None, rate_limiter=demo_report_limiter).create_evidence_package(
        tenant.id,
        EvidencePackageRequest(
            framework_id=framework.id,
            control_ids=[control.id],
            include_findings=True,
            include_remediation=True,
            requested_by=admin.id,
            retention_days=30,
        ),
    )
    await _seed_access_logs(db, tenant.id, admin.id, [item for item in (report_result.artifact, package_result.artifact) if item is not None])
    await _seed_notifications(db, tenant.id, admin.id, report_result.report_run.id)
    await db.commit()

    summary = await _summary(db, tenant.id)
    assert_safe_summary(summary, [])
    return summary


async def _ensure_tenant(db: AsyncSession) -> Tenant:
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().first()
    if tenant is None:
        tenant = Tenant(
            id=uuid.uuid5(DEMO_NAMESPACE, "tenant"),
            name=DEMO_TENANT_NAME,
            slug=DEMO_TENANT_SLUG,
            settings={"demo_dataset": "sprint5_phase7", "fake_data_only": True, "external_calls": False},
        )
        db.add(tenant)
        await db.flush()
    else:
        tenant.name = DEMO_TENANT_NAME
        tenant.settings = {"demo_dataset": "sprint5_phase7", "fake_data_only": True, "external_calls": False}
    await _set_tenant_context(db, tenant.id)
    return tenant


async def _ensure_user(db: AsyncSession, tenant_id: uuid.UUID) -> User:
    role = await _ensure_role(db, "owner")
    user = (await db.execute(select(User).where(User.tenant_id == tenant_id, User.email == DEMO_ADMIN_EMAIL))).scalars().first()
    if user is None:
        user = User(
            id=uuid.uuid5(DEMO_NAMESPACE, "user:demo-admin"),
            tenant_id=tenant_id,
            email=DEMO_ADMIN_EMAIL,
            password_hash=get_password_hash(DEMO_USER_PASSWORD),
            first_name="Demo",
            last_name="Admin",
            is_active=True,
            mfa_enabled=False,
            mfa_secret=None,
        )
        db.add(user)
        await db.flush()
    else:
        user.password_hash = get_password_hash(DEMO_USER_PASSWORD)
        user.is_active = True
        user.mfa_enabled = False
        user.mfa_secret = None
    existing = (
        await db.execute(select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id, UserRole.tenant_id == tenant_id))
    ).scalars().first()
    if existing is None:
        db.add(UserRole(id=uuid.uuid5(DEMO_NAMESPACE, "user-role:demo-admin:owner"), user_id=user.id, role_id=role.id, tenant_id=tenant_id))
    await db.flush()
    return user


async def _ensure_role(db: AsyncSession, name: str) -> Role:
    role = (await db.execute(select(Role).where(Role.name == name))).scalars().first()
    if role is None:
        role = Role(id=uuid.uuid5(DEMO_NAMESPACE, f"role:{name}"), name=name, description=f"Sprint 5 demo {name} role", is_system=True)
        db.add(role)
        await db.flush()
    return role


async def _ensure_framework_and_control(db: AsyncSession) -> tuple[ComplianceFramework, ComplianceControl]:
    framework = (
        await db.execute(select(ComplianceFramework).where(ComplianceFramework.key == "sprint5_demo", ComplianceFramework.version == "2026.1"))
    ).scalars().first()
    if framework is None:
        framework = ComplianceFramework(
            id=uuid.uuid5(DEMO_NAMESPACE, "framework:sprint5-demo"),
            key="sprint5_demo",
            version="2026.1",
            name="Sprint 5 Internal Trust Framework",
            description="Internal summarized framework for evidence-supported trust reporting demonstrations.",
            source_url=None,
            license_note="Internal demo summary only; no licensed framework text copied.",
            metadata_={"demo_dataset": "sprint5_phase7"},
        )
        db.add(framework)
        await db.flush()
    control = (
        await db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == framework.id, ComplianceControl.control_code == "TRUST-1"))
    ).scalars().first()
    if control is None:
        control = ComplianceControl(
            id=uuid.uuid5(DEMO_NAMESPACE, "control:trust-1"),
            framework_id=framework.id,
            control_code="TRUST-1",
            title="Evidence freshness and access review",
            summary="Mapped controls should maintain current evidence and owner review.",
            domain="trust_reporting",
            category="evidence",
            severity_weight=2,
            requires_review=True,
            sort_order=1,
            metadata_={"demo_dataset": "sprint5_phase7"},
        )
        db.add(control)
        await db.flush()
    return framework, control


async def _seed_integration(db: AsyncSession, tenant_id: uuid.UUID) -> CloudIntegration:
    integration = CloudIntegration(
        id=uuid.uuid5(DEMO_NAMESPACE, "integration:aws-demo"),
        tenant_id=tenant_id,
        provider_type=CloudProvider.aws,
        target_identifier="000000000000",
        display_name="AWS fake trust demo account",
        status=IntegrationStatus.active,
        vault_reference_id="disabled-demo-credential-reference",
        last_sync_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2),
        last_sync_finding_count=1,
        error_message=None,
    )
    db.add(integration)
    await db.flush()
    return integration


async def _seed_finding(db: AsyncSession, integration: CloudIntegration) -> SecurityFinding:
    finding = SecurityFinding(
        id=uuid.uuid5(DEMO_NAMESPACE, "finding:evidence-freshness"),
        integration_id=integration.id,
        dedup_hash=hashlib.sha256(f"{integration.id}:sprint5-demo-finding".encode("utf-8")).hexdigest(),
        external_id="sprint5-demo-evidence-freshness",
        resource_id="arn:aws:s3:::authclaw-sprint5-fake-evidence",
        title="Evidence freshness needs review",
        description="Synthetic finding used only for trust/reporting demo posture.",
        remediation_instructions="Review evidence owner and update mapped control evidence. No external mutation is required.",
        severity=FindingSeverity.high,
        status=FindingStatus.active,
    )
    db.add(finding)
    await db.flush()
    return finding


async def _seed_compliance(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    framework_id: uuid.UUID,
    control_id: uuid.UUID,
    integration_id: uuid.UUID,
    finding_id: uuid.UUID,
) -> EvidenceItem:
    evidence = EvidenceItem(
        id=uuid.uuid5(DEMO_NAMESPACE, "evidence:freshness"),
        tenant_id=tenant_id,
        control_id=control_id,
        finding_id=finding_id,
        integration_id=integration_id,
        source_type=EvidenceSourceType.finding_mapping,
        status=EvidenceStatus.active,
        safe_summary="Evidence-supported posture for mapped access review needs review.",
        proof_hash=hashlib.sha256(b"sprint5-demo-proof").hexdigest(),
        freshness_expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=21),
        metadata_={"demo_dataset": "sprint5_phase7", "source": "synthetic"},
    )
    assessment = ComplianceAssessment(
        id=uuid.uuid5(DEMO_NAMESPACE, "assessment:sprint5-demo"),
        tenant_id=tenant_id,
        framework_id=framework_id,
        status=ComplianceAssessmentStatus.completed,
        score=78,
        score_band=ComplianceScoreBand.mostly_supported,
        inputs_hash=hashlib.sha256(f"{tenant_id}:sprint5-demo-assessment".encode("utf-8")).hexdigest(),
        explanation="Evidence-supported posture with one mapped control gap that needs review. Not legal advice.",
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add_all([evidence, assessment])
    await db.flush()
    db.add(
        ControlAssessmentResult(
            id=uuid.uuid5(DEMO_NAMESPACE, "control-result:sprint5-demo"),
            tenant_id=tenant_id,
            assessment_id=assessment.id,
            control_id=control_id,
            score=78,
            score_band=ComplianceScoreBand.mostly_supported,
            evidence_count=1,
            gap_count=1,
            explanation="Mapped controls show evidence-supported posture with follow-up review.",
            metadata_={"demo_dataset": "sprint5_phase7"},
        )
    )
    db.add(
        ComplianceGap(
            id=uuid.uuid5(DEMO_NAMESPACE, "gap:sprint5-demo"),
            tenant_id=tenant_id,
            assessment_id=assessment.id,
            control_id=control_id,
            evidence_id=evidence.id,
            finding_id=finding_id,
            gap_type=ComplianceGapType.needs_review,
            severity=ComplianceGapSeverity.medium,
            reason="Gap detected: evidence freshness threshold needs review.",
            evidence_status=EvidenceStatus.active.value,
            metadata_={"demo_dataset": "sprint5_phase7"},
        )
    )
    await db.flush()
    return evidence


async def _seed_remediation(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    admin_id: uuid.UUID,
    integration_id: uuid.UUID,
    finding_id: uuid.UUID,
    evidence_id: uuid.UUID,
) -> None:
    plan = RemediationPlan(
        id=uuid.uuid5(DEMO_NAMESPACE, "remediation-plan:sprint5-demo"),
        tenant_id=tenant_id,
        finding_id=finding_id,
        integration_id=integration_id,
        provider="aws",
        resource_ref="arn:aws:s3:::authclaw-sprint5-fake-evidence",
        risk_level=RemediationRiskLevel.medium,
        status=RemediationPlanStatus.verified,
        summary="Documentation-only remediation status summary for trust reporting.",
        expected_impact="Records review status only. No cloud, GitHub, Terraform, or shell mutation.",
        created_by=admin_id,
    )
    artifact = RemediationArtifact(
        id=uuid.uuid5(DEMO_NAMESPACE, "remediation-artifact:sprint5-demo"),
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=RemediationArtifactType.documentation_only,
        content_redacted="Documentation-only review note for evidence freshness.",
        diff_summary="Synthetic trust reporting remediation summary.",
        artifact_hash=hashlib.sha256(b"sprint5-demo-remediation-artifact").hexdigest(),
        risk_flags={"demo_dataset": "sprint5_phase7", "execution": "disabled"},
        status=RemediationArtifactStatus.active,
    )
    approval = RemediationApproval(
        id=uuid.uuid5(DEMO_NAMESPACE, "remediation-approval:sprint5-demo"),
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_hash=artifact.artifact_hash,
        policy_check_hash=hashlib.sha256(b"sprint5-demo-policy-check").hexdigest(),
        requested_by=admin_id,
        approved_by=admin_id,
        status=RemediationApprovalStatus.used,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=7),
        resolved_at=datetime.now(timezone.utc).replace(tzinfo=None),
        mfa_verified=True,
        nonce=f"sprint5-demo-{plan.id}",
        approval_reason="Approved fake documentation-only trust reporting demo.",
    )
    job = RemediationExecutionJob(
        id=uuid.uuid5(DEMO_NAMESPACE, "remediation-job:sprint5-demo"),
        tenant_id=tenant_id,
        plan_id=plan.id,
        approval_id=approval.id,
        sandbox_id="sprint5-demo-static-sandbox",
        status=RemediationExecutionStatus.succeeded,
        started_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=20),
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=19),
        disabled_reason=None,
    )
    dry_run = RemediationDryRunResult(
        id=uuid.uuid5(DEMO_NAMESPACE, "remediation-dry-run:sprint5-demo"),
        tenant_id=tenant_id,
        job_id=job.id,
        plan_id=plan.id,
        artifact_id=artifact.id,
        approval_id=approval.id,
        sandbox_id="sprint5-demo-static-sandbox",
        dry_run_type=RemediationArtifactType.documentation_only.value,
        status=RemediationDryRunStatus.succeeded,
        output_summary="Static documentation dry-run completed. No external mutation.",
        warnings=[],
        blocking_reasons=[],
        started_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=21),
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=20),
    )
    job.dry_run_result_id = dry_run.id
    verification = RemediationVerificationResult(
        id=uuid.uuid5(DEMO_NAMESPACE, "remediation-verification:sprint5-demo"),
        tenant_id=tenant_id,
        plan_id=plan.id,
        job_id=job.id,
        evidence_id=evidence_id,
        verified=True,
        status=RemediationVerificationStatus.verified,
        finding_status_before=FindingStatus.active.value,
        finding_status_after=FindingStatus.active.value,
        verification_summary="Verified via AuthClaw demo records only; no provider state was changed.",
    )
    db.add_all([plan, artifact, approval, job, dry_run, verification])
    await db.flush()


async def _seed_template(db: AsyncSession, tenant_id: uuid.UUID, admin_id: uuid.UUID) -> ReportTemplate:
    template = ReportTemplate(
        id=uuid.uuid5(DEMO_NAMESPACE, "report-template:quarterly-posture"),
        tenant_id=tenant_id,
        name="Sprint 5 demo posture package",
        type="trust_overview",
        format="json",
        filters_schema={"scope": "string", "audience": "string"},
        default_sections=["summary", "posture", "evidence", "remediation"],
        created_by=admin_id,
        is_system=False,
    )
    db.add(template)
    await db.flush()
    return template


async def _seed_access_logs(db: AsyncSession, tenant_id: uuid.UUID, admin_id: uuid.UUID, artifacts: list[object]) -> None:
    for index, artifact in enumerate(artifacts):
        db.add(
            ReportAccessLog(
                id=uuid.uuid5(DEMO_NAMESPACE, f"access-log:{index}"),
                tenant_id=tenant_id,
                artifact_id=artifact.id,
                actor_user_id=admin_id,
                action="download" if index == 0 else "metadata_view",
                ip_hash=hash_access_metadata(f"203.0.113.{10 + index}"),
                user_agent_hash=hash_access_metadata(f"AuthClawSprint5Demo/{index}"),
            )
        )
    await db.flush()


async def _seed_notifications(db: AsyncSession, tenant_id: uuid.UUID, admin_id: uuid.UUID, report_run_id: uuid.UUID) -> None:
    service = TrustNotificationService(db, event_producer=None)
    await service.create_notification(
        tenant_id=tenant_id,
        recipient_user_id=admin_id,
        type="report_run_completed",
        severity="info",
        title="Sprint 5 report run completed",
        body="Evidence-supported posture package is ready for internal review.",
        resource_type="report_run",
        resource_id=report_run_id,
    )
    await service.create_notification(
        tenant_id=tenant_id,
        recipient_user_id=admin_id,
        type="evidence_freshness",
        severity="warning",
        title="Evidence freshness needs review",
        body="Mapped control evidence should be reviewed before external audit reliance.",
        resource_type="evidence_item",
        resource_id=uuid.uuid5(DEMO_NAMESPACE, "evidence:freshness"),
    )


async def _reset_demo_tenant_data(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await _set_tenant_context(db, tenant_id)
    for table in (
        "report_access_logs",
        "external_share_links",
        "export_manifests",
        "report_artifacts",
        "report_runs",
        "report_templates",
        "trust_notifications",
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
        "evidence_items",
        "finding_control_mappings",
        "user_roles",
        "users",
    ):
        await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
    await db.execute(
        delete(SecurityFinding).where(SecurityFinding.integration_id.in_(select(CloudIntegration.id).where(CloudIntegration.tenant_id == tenant_id)))
    )
    await db.execute(delete(CloudIntegration).where(CloudIntegration.tenant_id == tenant_id))
    await db.flush()


async def _summary(db: AsyncSession, tenant_id: uuid.UUID) -> Sprint5DemoSummary:
    await _set_tenant_context(db, tenant_id)
    report_runs = await _table_count(db, "report_runs", tenant_id)
    runs = (await db.execute(select(ReportRun).where(ReportRun.tenant_id == tenant_id))).scalars().all()
    return Sprint5DemoSummary(
        tenant_id=tenant_id,
        admin_email=DEMO_ADMIN_EMAIL,
        templates=await _table_count(db, "report_templates", tenant_id),
        report_runs=report_runs,
        report_artifacts=await _table_count(db, "report_artifacts", tenant_id),
        export_manifests=await _table_count(db, "export_manifests", tenant_id),
        evidence_packages=sum(1 for row in runs if (row.filters or {}).get("report_type") == "evidence_package"),
        access_logs=await _table_count(db, "report_access_logs", tenant_id),
        notifications=await _table_count(db, "trust_notifications", tenant_id),
        timeline_minimum_items=report_runs
        + await _table_count(db, "report_access_logs", tenant_id)
        + await _table_count(db, "remediation_approvals", tenant_id)
        + await _table_count(db, "remediation_execution_jobs", tenant_id)
        + await _table_count(db, "remediation_verification_results", tenant_id)
        + await _table_count(db, "evidence_items", tenant_id)
        + await _table_count(db, "cloud_integrations", tenant_id),
    )


async def _table_count(db: AsyncSession, table: str, tenant_id: uuid.UUID) -> int:
    return int(await db.scalar(text(f"SELECT count(id) FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id}) or 0)


async def _set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


def assert_safe_summary(summary: Sprint5DemoSummary, serialized_payloads: Iterable[object]) -> None:
    unsafe_terms = (
        "AKIA",
        "BEGIN PRIVATE KEY",
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
    haystack = json.dumps([summary.as_safe_dict(), *serialized_payloads], default=str).lower()
    for term in unsafe_terms:
        assert term.lower() not in haystack


async def main() -> None:
    async with AsyncSessionLocal() as db:
        summary = await seed_demo_dataset(db)
    print("Seeded Sprint 5 demo dataset:")
    print(json.dumps(summary.as_safe_dict(), indent=2, sort_keys=True))
    print("Demo login:")
    print(f"  email={DEMO_ADMIN_EMAIL}")
    print(f"  password={DEMO_USER_PASSWORD}")


if __name__ == "__main__":
    asyncio.run(main())
