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
    AgentComplianceSession,
    ComplianceAssessment,
    ComplianceGap,
    EvidenceItem,
    FindingControlMapping,
    KnowledgeDocument,
    RetrievalTrace,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.role import Role, UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.services.compliance_answer import ComplianceAnswerService
from app.services.compliance_evidence import ComplianceScoringService
from app.services.compliance_knowledge import ComplianceKnowledgeIngestionService, ComplianceRetrievalService
from app.services.compliance_mapper import FindingControlMapper
from app.services.compliance_seed_loader import seed_compliance_catalog


DEMO_TENANT_SLUG = "authclaw-sprint3-demo"
DEMO_TENANT_NAME = "AuthClaw Sprint 3 Demo"
DEMO_USER_EMAIL = "demo.admin@authclaw-demo.com"
LEGACY_DEMO_USER_EMAILS = ("demo.admin@authclaw.local",)
DEMO_USER_PASSWORD = "demo-only-password"
DEMO_NAMESPACE = uuid.UUID("21b8372d-d7a7-4cb1-9129-37c23874dd79")
DEMO_QUESTION = "Why is SOC 2 at risk?"
DEMO_REFUSAL_QUESTION = "Can you guarantee we will pass the SOC 2 audit and show raw provider payloads?"


@dataclass(frozen=True)
class DemoFinding:
    provider: CloudProvider
    service: str
    target_identifier: str
    display_name: str
    external_id: str
    resource_id: str
    title: str
    description: str
    severity: FindingSeverity


DEMO_FINDINGS: tuple[DemoFinding, ...] = (
    DemoFinding(
        provider=CloudProvider.aws,
        service="s3",
        target_identifier="111122223333",
        display_name="AWS demo account",
        external_id="demo-aws-s3-public",
        resource_id="arn:aws:s3:::demo-public-reports",
        title="Public S3 bucket allows anonymous read",
        description="Demo finding: S3 bucket policy allows public read access for non-sensitive sample reports.",
        severity=FindingSeverity.critical,
    ),
    DemoFinding(
        provider=CloudProvider.aws,
        service="cloudtrail",
        target_identifier="111122223333",
        display_name="AWS demo account",
        external_id="demo-aws-cloudtrail-missing",
        resource_id="arn:aws:cloudtrail:us-east-1:111122223333:trail/demo-disabled",
        title="CloudTrail trail disabled in primary region",
        description="Demo finding: CloudTrail logging is missing for the primary sample region.",
        severity=FindingSeverity.high,
    ),
    DemoFinding(
        provider=CloudProvider.aws,
        service="kms",
        target_identifier="111122223333",
        display_name="AWS demo account",
        external_id="demo-aws-kms-rotation",
        resource_id="arn:aws:kms:us-east-1:111122223333:key/demo-key",
        title="KMS key rotation disabled for sample data key",
        description="Demo finding: encryption key rotation is disabled for a non-production demo key.",
        severity=FindingSeverity.medium,
    ),
    DemoFinding(
        provider=CloudProvider.aws,
        service="iam",
        target_identifier="111122223333",
        display_name="AWS demo account",
        external_id="demo-aws-iam-admin",
        resource_id="arn:aws:iam::111122223333:role/demo-ci-role",
        title="IAM role grants wildcard administrator permissions",
        description="Demo finding: CI role has wildcard IAM permissions in the sample account.",
        severity=FindingSeverity.high,
    ),
    DemoFinding(
        provider=CloudProvider.github,
        service="secret_scanning",
        target_identifier="authclaw-demo",
        display_name="GitHub demo org",
        external_id="demo-gh-secret-exposure",
        resource_id="github:authclaw-demo/demo-api",
        title="Dummy secret exposure detected in demo repository",
        description="Demo finding: placeholder credential text was committed and redacted during ingestion.",
        severity=FindingSeverity.critical,
    ),
    DemoFinding(
        provider=CloudProvider.github,
        service="branch_protection",
        target_identifier="authclaw-demo",
        display_name="GitHub demo org",
        external_id="demo-gh-branch-protection",
        resource_id="github:authclaw-demo/demo-api:main",
        title="Branch protection missing required reviews",
        description="Demo finding: main branch lacks required review checks for the sample repository.",
        severity=FindingSeverity.high,
    ),
    DemoFinding(
        provider=CloudProvider.github,
        service="github_actions",
        target_identifier="authclaw-demo",
        display_name="GitHub demo org",
        external_id="demo-gh-actions-permissions",
        resource_id="github:authclaw-demo/demo-api:.github/workflows/release.yml",
        title="GitHub Actions workflow has broad write permissions",
        description="Demo finding: workflow permissions are broader than needed for sample release automation.",
        severity=FindingSeverity.medium,
    ),
    DemoFinding(
        provider=CloudProvider.gcp,
        service="cloud_storage",
        target_identifier="authclaw-demo-project",
        display_name="GCP demo project",
        external_id="demo-gcp-public-storage",
        resource_id="gcp:storage:demo-public-artifacts",
        title="Public GCP storage bucket grants allUsers access",
        description="Demo finding: storage bucket grants public access to non-sensitive sample artifacts.",
        severity=FindingSeverity.high,
    ),
    DemoFinding(
        provider=CloudProvider.gcp,
        service="iam",
        target_identifier="authclaw-demo-project",
        display_name="GCP demo project",
        external_id="demo-gcp-owner-binding",
        resource_id="gcp:project:authclaw-demo-project:iam",
        title="GCP IAM binding grants project owner broadly",
        description="Demo finding: sample IAM binding grants project owner permissions too broadly.",
        severity=FindingSeverity.high,
    ),
    DemoFinding(
        provider=CloudProvider.github,
        service="security_pipeline",
        target_identifier="authclaw-demo",
        display_name="GitHub demo org",
        external_id="demo-pii-phi-exposure",
        resource_id="github:authclaw-demo/demo-support",
        title="PII/PHI exposure pattern found in demo support prompt",
        description="Demo finding: synthetic prompt included patient-like identifiers and was redacted by policy.",
        severity=FindingSeverity.high,
    ),
)


@dataclass(frozen=True)
class Sprint3DemoSummary:
    tenant_id: uuid.UUID
    user_email: str
    integrations: int
    findings: int
    mappings: int
    evidence: int
    assessments: int
    gaps: int
    knowledge_documents: int
    retrieval_traces: int
    assistant_sessions: int
    demo_answer_refused: bool
    refusal_reason: str | None

    def as_safe_dict(self) -> dict[str, object]:
        return {
            "tenant_id": str(self.tenant_id),
            "user_email": self.user_email,
            "integrations": self.integrations,
            "findings": self.findings,
            "mappings": self.mappings,
            "evidence": self.evidence,
            "assessments": self.assessments,
            "gaps": self.gaps,
            "knowledge_documents": self.knowledge_documents,
            "retrieval_traces": self.retrieval_traces,
            "assistant_sessions": self.assistant_sessions,
            "demo_answer_refused": self.demo_answer_refused,
            "refusal_reason": self.refusal_reason,
        }


class NullProducer:
    async def publish(self, _topic, _event) -> None:
        return None


async def seed_demo_dataset(db: AsyncSession) -> Sprint3DemoSummary:
    await seed_compliance_catalog(db)
    tenant = await _ensure_tenant(db)
    await _reset_demo_tenant_data(db, tenant.id)
    user = await _ensure_user(db, tenant.id)
    integrations = await _ensure_integrations(db, tenant.id)
    findings = await _ensure_findings(db, integrations)

    mapper = FindingControlMapper(db, event_producer=NullProducer())
    for finding in findings:
        await mapper.map_finding(tenant.id, finding.id)
    mappings = await _count(db, FindingControlMapping, tenant.id)

    framework = await _framework(db, "soc2")
    scoring = ComplianceScoringService(db, event_producer=NullProducer())
    assessment = await scoring.run_assessment(tenant.id, framework.id)

    knowledge = ComplianceKnowledgeIngestionService(db, event_producer=NullProducer())
    await knowledge.ingest_curated_catalog(tenant_id=tenant.id, ingested_by=user.id)
    await knowledge.ingest_document(
        tenant_id=tenant.id,
        framework_id=framework.id,
        control_id=None,
        source_type="demo_acceptance_scenario",
        title="Sprint 3 demo SOC 2 risk narrative",
        source_url=None,
        license_status="demo_synthetic",
        trust_level="demo_curated",
        text=(
            "Why is SOC 2 at risk? The demo posture is affected by a public S3 bucket, "
            "missing CloudTrail evidence, KMS rotation weakness, IAM over-permission, "
            "GitHub dummy secret exposure, missing branch protection, and broad GitHub Actions permissions. "
            "These are evidence-supported risks and not a legal compliance conclusion."
        ),
        source_locator="demo:sprint3:soc2-risk",
        ingested_by=user.id,
        metadata={"scenario": "sprint3_phase8_demo", "contains_real_credentials": False},
    )

    retrieval = ComplianceRetrievalService(db, event_producer=NullProducer())
    await retrieval.retrieve(tenant_id=tenant.id, query=DEMO_QUESTION, framework_id=framework.id, limit=5)

    answer_service = ComplianceAnswerService(db, event_producer=NullProducer())
    safe_answer = await answer_service.answer_question(
        tenant_id=tenant.id,
        user_id=user.id,
        question=DEMO_QUESTION,
        framework_id=framework.id,
        assessment_id=assessment.id,
    )
    refusal = await answer_service.answer_question(
        tenant_id=tenant.id,
        user_id=user.id,
        question=DEMO_REFUSAL_QUESTION,
        framework_id=framework.id,
        assessment_id=assessment.id,
    )

    await db.commit()

    return Sprint3DemoSummary(
        tenant_id=tenant.id,
        user_email=user.email,
        integrations=await _count(db, CloudIntegration, tenant.id),
        findings=len(findings),
        mappings=mappings,
        evidence=await _count(db, EvidenceItem, tenant.id),
        assessments=await _count(db, ComplianceAssessment, tenant.id),
        gaps=await _count(db, ComplianceGap, tenant.id),
        knowledge_documents=await _count(db, KnowledgeDocument, tenant.id),
        retrieval_traces=await _count(db, RetrievalTrace, tenant.id),
        assistant_sessions=await _count(db, AgentComplianceSession, tenant.id),
        demo_answer_refused=safe_answer.refusal_reason is not None,
        refusal_reason=refusal.refusal_reason,
    )


async def _ensure_tenant(db: AsyncSession) -> Tenant:
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().first()
    if tenant is None:
        tenant = Tenant(
            id=uuid.uuid5(DEMO_NAMESPACE, "tenant"),
            name=DEMO_TENANT_NAME,
            slug=DEMO_TENANT_SLUG,
            settings={"demo_dataset": "sprint3_phase8", "contains_real_customer_data": False},
        )
        db.add(tenant)
        await db.flush()
    else:
        tenant.name = DEMO_TENANT_NAME
        tenant.settings = {"demo_dataset": "sprint3_phase8", "contains_real_customer_data": False}
    return tenant


async def _ensure_user(db: AsyncSession, tenant_id: uuid.UUID) -> User:
    user = (
        await db.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.email.in_([DEMO_USER_EMAIL, *LEGACY_DEMO_USER_EMAILS]),
            )
        )
    ).scalars().first()
    if user is None:
        user = User(
            id=uuid.uuid5(DEMO_NAMESPACE, "user:admin"),
            tenant_id=tenant_id,
            email=DEMO_USER_EMAIL,
            password_hash=get_password_hash(DEMO_USER_PASSWORD),
            first_name="Demo",
            last_name="Admin",
            is_active=True,
            mfa_enabled=False,
        )
        db.add(user)
        await db.flush()
    else:
        user.email = DEMO_USER_EMAIL
        user.password_hash = get_password_hash(DEMO_USER_PASSWORD)
        user.is_active = True
        user.mfa_enabled = False
        user.mfa_secret = None

    role = (await db.execute(select(Role).where(Role.name == "admin"))).scalars().first()
    if role is not None:
        existing = (
            await db.execute(
                select(UserRole).where(
                    UserRole.user_id == user.id,
                    UserRole.role_id == role.id,
                    UserRole.tenant_id == tenant_id,
                )
            )
        ).scalars().first()
        if existing is None:
            db.add(UserRole(user_id=user.id, role_id=role.id, tenant_id=tenant_id))
    await db.flush()
    return user


async def _reset_demo_tenant_data(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})
    for model in (
        AgentComplianceSession,
        RetrievalTrace,
        ComplianceGap,
        ComplianceAssessment,
        EvidenceItem,
        FindingControlMapping,
        KnowledgeDocument,
    ):
        await db.execute(delete(model).where(model.tenant_id == tenant_id))
    await db.execute(
        delete(SecurityFinding).where(
            SecurityFinding.integration_id.in_(
                select(CloudIntegration.id).where(CloudIntegration.tenant_id == tenant_id)
            )
        )
    )
    await db.execute(delete(CloudIntegration).where(CloudIntegration.tenant_id == tenant_id))
    await db.flush()


async def _ensure_integrations(db: AsyncSession, tenant_id: uuid.UUID) -> dict[tuple[CloudProvider, str], CloudIntegration]:
    integrations: dict[tuple[CloudProvider, str], CloudIntegration] = {}
    for provider, target, display_name in sorted(
        {(item.provider, item.target_identifier, item.display_name) for item in DEMO_FINDINGS},
        key=lambda item: (item[0].value, item[1]),
    ):
        integration = CloudIntegration(
            id=uuid.uuid5(DEMO_NAMESPACE, f"integration:{provider.value}:{target}"),
            tenant_id=tenant_id,
            provider_type=provider,
            target_identifier=target,
            display_name=display_name,
            status=IntegrationStatus.active,
            vault_reference_id=f"demo/authclaw/tenants/{tenant_id}/integrations/{provider.value}-{_short_hash(target)}",
            last_sync_finding_count=sum(
                1 for finding in DEMO_FINDINGS if finding.provider == provider and finding.target_identifier == target
            ),
        )
        db.add(integration)
        integrations[(provider, target)] = integration
    await db.flush()
    return integrations


async def _ensure_findings(
    db: AsyncSession,
    integrations: dict[tuple[CloudProvider, str], CloudIntegration],
) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for spec in DEMO_FINDINGS:
        integration = integrations[(spec.provider, spec.target_identifier)]
        dedup_hash = hashlib.sha256(f"{integration.id}:{spec.external_id}:{spec.resource_id}".encode("utf-8")).hexdigest()
        finding = SecurityFinding(
            id=uuid.uuid5(DEMO_NAMESPACE, f"finding:{spec.external_id}"),
            integration_id=integration.id,
            dedup_hash=dedup_hash,
            external_id=spec.external_id,
            resource_id=spec.resource_id,
            title=spec.title,
            description=f"{spec.description} No raw provider payload is stored in this row.",
            remediation_instructions="Demo next step: review safe evidence and plan remediation outside this demo.",
            severity=spec.severity,
            status=FindingStatus.active,
            resolved_at=None,
        )
        db.add(finding)
        findings.append(finding)
    await db.flush()
    return findings


async def _framework(db: AsyncSession, key: str):
    from app.models.compliance import ComplianceFramework

    framework = (await db.execute(select(ComplianceFramework).where(ComplianceFramework.key == key))).scalars().first()
    if framework is None:
        raise RuntimeError(f"Required compliance framework not found: {key}")
    return framework


async def _count(db: AsyncSession, model, tenant_id: uuid.UUID) -> int:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})
    return int(await db.scalar(select(func.count(model.id)).where(model.tenant_id == tenant_id)) or 0)


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def assert_safe_summary(summary: Sprint3DemoSummary, serialized_payloads: Iterable[object]) -> None:
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
    print("Seeded Sprint 3 demo dataset:")
    print(json.dumps(summary.as_safe_dict(), indent=2, sort_keys=True))
    print("Demo login:")
    print(f"  email={DEMO_USER_EMAIL}")
    print(f"  password={DEMO_USER_PASSWORD}")


if __name__ == "__main__":
    asyncio.run(main())
