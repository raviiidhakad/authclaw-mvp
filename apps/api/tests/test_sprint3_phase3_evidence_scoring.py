from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, text

from app.api.v1.endpoints import compliance as compliance_api
from app.core.database import AsyncSessionLocal
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceFramework,
    ComplianceGap,
    ComplianceGapType,
    ComplianceScore,
    EvidenceItem,
    EvidenceSourceType,
    EvidenceStatus,
    FindingControlMapping,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.tenant import Tenant
from app.schemas.compliance import ComplianceAssessmentRunRequest
from app.services.compliance_evidence import ComplianceEvidenceEngine, ComplianceScoringService
from app.services.compliance_mapper import FindingControlMapper
from app.services.compliance_seed_loader import seed_compliance_catalog


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint3-score-{suffix}",
        slug=f"sprint3-score-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _integration(db, tenant_id: uuid.UUID, provider: CloudProvider = CloudProvider.aws):
    integration = CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=provider,
        target_identifier=f"target-{uuid.uuid4()}",
        display_name=f"{provider.value} test",
        status=IntegrationStatus.active,
        vault_reference_id=f"authclaw/tenants/{tenant_id}/integrations/{uuid.uuid4()}",
    )
    db.add(integration)
    await db.flush()
    return integration


async def _finding(
    db,
    integration_id: uuid.UUID,
    title: str = "S3 bucket allows public access",
    resource_id: str = "arn:aws:s3:::public-test-bucket",
    description: str = "Public bucket policy detected",
    severity: FindingSeverity = FindingSeverity.high,
    status: FindingStatus = FindingStatus.active,
) -> SecurityFinding:
    finding = SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration_id,
        dedup_hash=(uuid.uuid4().hex + uuid.uuid4().hex)[:64],
        external_id=f"finding-{uuid.uuid4()}",
        resource_id=resource_id,
        title=title,
        description=description,
        remediation_instructions="Review normalized finding and remediate safely.",
        severity=severity,
        status=status,
        resolved_at=datetime.utcnow() if status == FindingStatus.resolved else None,
    )
    db.add(finding)
    await db.flush()
    return finding


async def _framework(db, key: str = "soc2") -> ComplianceFramework:
    framework = (
        await db.execute(select(ComplianceFramework).where(ComplianceFramework.key == key))
    ).scalars().first()
    assert framework is not None
    return framework


async def _mapped_public_bucket(db, tenant_id: uuid.UUID, status=FindingStatus.active, severity=FindingSeverity.high):
    integration = await _integration(db, tenant_id, CloudProvider.aws)
    finding = await _finding(db, integration.id, status=status, severity=severity)
    mappings = await FindingControlMapper(db, event_producer=None).map_finding(tenant_id, finding.id)
    return finding, mappings


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        await db.execute(text("DELETE FROM compliance_gaps WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM control_assessment_results WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM compliance_assessments WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM evidence_items WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM finding_control_mappings WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
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


def test_phase3_models_preserve_existing_compliance_score():
    assert ComplianceScore.__tablename__ == "compliance_scores"
    assert EvidenceItem.__tablename__ == "evidence_items"
    assert ComplianceAssessment.__tablename__ == "compliance_assessments"
    assert ComplianceGap.__tablename__ == "compliance_gaps"


@pytest.mark.asyncio
async def test_evidence_creation_is_idempotent_safe_and_tenant_scoped():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(3))
        try:
            finding, mappings = await _mapped_public_bucket(db, tenant_a.id)
            producer = FakeProducer()
            engine = ComplianceEvidenceEngine(db, event_producer=producer)

            first = await engine.refresh_evidence_for_mapping(tenant_a.id, mappings[0].id)
            second = await engine.refresh_evidence_for_mapping(tenant_a.id, mappings[0].id)
            evidence_count = await db.scalar(
                select(func.count(EvidenceItem.id)).where(
                    EvidenceItem.tenant_id == tenant_a.id,
                    EvidenceItem.mapping_id == mappings[0].id,
                )
            )

            assert first.id == second.id
            assert evidence_count == 1
            assert first.proof_hash and len(first.proof_hash) == 64
            assert "public-test-bucket" not in first.safe_summary
            assert await engine.get_evidence_for_control(tenant_b.id, mappings[0].control_id) == []
            serialized_events = str([event for _, event in producer.events]).lower()
            assert finding.resource_id.lower() not in serialized_events
            assert "vault_reference_id" not in serialized_events
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("finding_status", "evidence_status"),
    [
        (FindingStatus.resolved, EvidenceStatus.resolved),
        (FindingStatus.suppressed, EvidenceStatus.suppressed),
    ],
)
async def test_resolved_and_suppressed_findings_update_evidence_status(finding_status, evidence_status):
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            _, mappings = await _mapped_public_bucket(db, tenant.id, status=finding_status)
            evidence = await ComplianceEvidenceEngine(db, event_producer=None).refresh_evidence_for_mapping(
                tenant.id,
                mappings[0].id,
            )

            assert evidence.status == evidence_status
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_evidence_expiration_marks_stale_items_expired():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            _, mappings = await _mapped_public_bucket(db, tenant.id)
            engine = ComplianceEvidenceEngine(db, event_producer=None)
            evidence = await engine.refresh_evidence_for_mapping(tenant.id, mappings[0].id)
            evidence.freshness_expires_at = datetime.utcnow() - timedelta(days=1)
            await db.flush()

            expired = await engine.expire_stale_evidence(tenant.id)

            assert expired
            assert expired[0].status == EvidenceStatus.expired
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_assessment_scoring_detects_gaps_and_caps_critical_open_risk():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.github)
            finding = await _finding(
                db,
                integration.id,
                title="GitHub secret scanning alert exposed credential",
                resource_id="acme/repo/security/secret-scanning/1",
                description="Credential exposure detected",
                severity=FindingSeverity.critical,
            )
            await FindingControlMapper(db, event_producer=None).map_finding(tenant.id, finding.id)
            framework = await _framework(db, "soc2")

            assessment = await ComplianceScoringService(db, event_producer=None).run_assessment(
                tenant.id,
                framework.id,
            )
            gaps = (
                await db.execute(
                    select(ComplianceGap).where(ComplianceGap.assessment_id == assessment.id)
                )
            ).scalars().all()

            assert assessment.score <= 49
            assert assessment.score_band.value == "high_risk"
            assert any(gap.gap_type == ComplianceGapType.critical_open_risk for gap in gaps)
            assert "legal compliance" in assessment.explanation
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_low_confidence_and_stale_evidence_reduce_posture():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="Critical unknown cloud security exposure",
                resource_id="arn:aws:unknown:::resource",
                description="No specific deterministic rule should match this text",
                severity=FindingSeverity.critical,
            )
            mappings = await FindingControlMapper(db, event_producer=None).map_finding(tenant.id, finding.id)
            await ComplianceEvidenceEngine(db, event_producer=None).refresh_evidence_for_mapping(
                tenant.id,
                mappings[0].id,
            )
            stale_evidence = EvidenceItem(
                tenant_id=tenant.id,
                control_id=mappings[0].control_id,
                source_type=EvidenceSourceType.system,
                status=EvidenceStatus.stale,
                safe_summary="System-generated evidence has exceeded its freshness window.",
                freshness_expires_at=datetime.utcnow() - timedelta(days=1),
                metadata_={"source": "phase3-test"},
            )
            db.add(stale_evidence)
            await db.flush()
            framework = await _framework(db, "gdpr")

            assessment = await ComplianceScoringService(db, event_producer=None).run_assessment(
                tenant.id,
                framework.id,
            )
            gaps = (
                await db.execute(
                    select(ComplianceGap).where(ComplianceGap.assessment_id == assessment.id)
                )
            ).scalars().all()
            gap_types = {gap.gap_type for gap in gaps}

            assert ComplianceGapType.low_confidence_mapping in gap_types
            assert ComplianceGapType.needs_review in gap_types
            assert ComplianceGapType.stale_evidence in gap_types
            assert assessment.score < 75
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_assessment_evidence_and_gap_apis_are_safe(monkeypatch):
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            await _mapped_public_bucket(db, tenant.id)
            monkeypatch.setattr(
                compliance_api,
                "ComplianceScoringService",
                lambda session: ComplianceScoringService(session, event_producer=None),
            )

            run = await compliance_api.run_assessment(
                ComplianceAssessmentRunRequest(framework="soc2"),
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            assessments = await compliance_api.list_assessments(
                skip=0,
                limit=10,
                framework="soc2",
                status=None,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            detail = await compliance_api.get_assessment(
                run.id,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            evidence = await compliance_api.list_evidence(
                skip=0,
                limit=20,
                framework="soc2",
                control_id=None,
                status=None,
                freshness="fresh",
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            gaps = await compliance_api.list_gaps(
                skip=0,
                limit=20,
                framework="soc2",
                control_id=None,
                severity=None,
                gap_type=None,
                evidence_status=None,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )

            serialized = str(
                [
                    run.model_dump(mode="json"),
                    detail.model_dump(mode="json"),
                    evidence.model_dump(mode="json"),
                    gaps.model_dump(mode="json"),
                ]
            ).lower()
            assert assessments.items
            assert detail.control_results
            assert evidence.items
            assert gaps.items
            assert "public-test-bucket" not in serialized
            assert "vault_reference_id" not in serialized
            assert "aws_secret_access_key" not in serialized
        finally:
            await _cleanup(db, tenant.id)
