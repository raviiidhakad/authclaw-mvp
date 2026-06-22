from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text

from app.api.v1.endpoints import compliance as compliance_api
from app.core.database import AsyncSessionLocal
from app.core.exceptions import NotFoundException
from app.models.compliance import (
    AgentComplianceSession,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    EvidenceItem,
    FindingControlMapping,
    MappingReviewStatus,
    RetrievalTrace,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.tenant import Tenant
from app.schemas.compliance import ComplianceAskRequest, ComplianceAssessmentRunRequest, MappingReviewRequest
from app.services.compliance_answer import ComplianceAnswerService
from app.services.compliance_knowledge import ComplianceKnowledgeIngestionService
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
        name=f"sprint3-phase6-{suffix}",
        slug=f"sprint3-phase6-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _integration(db, tenant_id: uuid.UUID) -> CloudIntegration:
    integration = CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=CloudProvider.aws,
        target_identifier=f"target-{uuid.uuid4()}",
        display_name="aws phase6 test",
        status=IntegrationStatus.active,
        vault_reference_id=f"authclaw/tenants/{tenant_id}/integrations/{uuid.uuid4()}",
    )
    db.add(integration)
    await db.flush()
    return integration


async def _finding(db, integration_id: uuid.UUID) -> SecurityFinding:
    finding = SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration_id,
        dedup_hash=(uuid.uuid4().hex + uuid.uuid4().hex)[:64],
        external_id=f"finding-{uuid.uuid4()}",
        resource_id="arn:aws:s3:::phase6-public-bucket",
        title="S3 bucket allows public access token=super-secret-token",
        description="Public bucket policy raw_provider_payload token=super-secret-token",
        remediation_instructions="Review normalized finding only.",
        severity=FindingSeverity.high,
        status=FindingStatus.active,
        resolved_at=None,
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


async def _setup_assessed_tenant(db):
    await seed_compliance_catalog(db)
    tenant = await _tenant(db)
    integration = await _integration(db, tenant.id)
    finding = await _finding(db, integration.id)
    mappings = await FindingControlMapper(db, event_producer=None).map_finding(tenant.id, finding.id)
    framework = await _framework(db, "soc2")
    assessment = await compliance_api.run_assessment(
        ComplianceAssessmentRunRequest(framework_id=framework.id),
        tenant=SimpleNamespace(id=tenant.id),
        _=SimpleNamespace(id=uuid.uuid4()),
        db=db,
    )
    return tenant, framework, finding, mappings, assessment


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        await db.execute(text("DELETE FROM agent_compliance_sessions WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM retrieval_traces WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM compliance_gaps WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM control_assessment_results WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM compliance_assessments WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM evidence_items WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM finding_control_mappings WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM knowledge_chunks WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM knowledge_documents WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
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


def test_phase6_required_route_surface_has_no_duplicates():
    expected = {
        ("GET", "/frameworks"),
        ("GET", "/frameworks/{framework_id}"),
        ("GET", "/frameworks/{framework_id}/controls"),
        ("GET", "/controls/{control_id}"),
        ("GET", "/mappings"),
        ("GET", "/findings/{finding_id}/mappings"),
        ("GET", "/controls/{control_id}/mappings"),
        ("PATCH", "/mappings/{mapping_id}/review"),
        ("POST", "/assessments/run"),
        ("GET", "/assessments"),
        ("GET", "/assessments/{assessment_id}"),
        ("GET", "/assessments/{assessment_id}/controls"),
        ("GET", "/evidence"),
        ("GET", "/evidence/{evidence_id}"),
        ("GET", "/gaps"),
        ("GET", "/gaps/{gap_id}"),
        ("GET", "/recommendations"),
        ("GET", "/knowledge"),
        ("GET", "/knowledge/{document_id}"),
        ("POST", "/knowledge/ingest"),
        ("POST", "/retrieval/query"),
        ("POST", "/ask"),
        ("GET", "/ask/sessions"),
        ("GET", "/ask/sessions/{session_id}"),
    }
    actual = {
        (method, route.path)
        for route in compliance_api.router.routes
        for method in getattr(route, "methods", set())
        if method in {"GET", "POST", "PATCH"}
    }

    missing = expected - actual
    duplicates = [
        item for item in expected if sum(1 for route in compliance_api.router.routes if item[1] == route.path and item[0] in route.methods) > 1
    ]
    assert not missing
    assert not duplicates


@pytest.mark.asyncio
async def test_mapping_review_filters_and_sanitized_event(monkeypatch):
    async with AsyncSessionLocal() as db:
        tenant, _, finding, mappings, _ = await _setup_assessed_tenant(db)
        producer = FakeProducer()
        monkeypatch.setattr(compliance_api, "producer", producer)
        try:
            reviewed = await compliance_api.review_mapping(
                mappings[0].id,
                MappingReviewRequest(
                    review_status="overridden",
                    override_reason="Auditor selected a narrower control relationship.",
                ),
                tenant=SimpleNamespace(id=tenant.id),
                current_user=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            listed = await compliance_api.list_mappings(
                skip=0,
                limit=10,
                framework=None,
                framework_id=None,
                finding_id=finding.id,
                control_id=reviewed.control_id,
                review_status=MappingReviewStatus.overridden,
                mapping_source=None,
                min_confidence=0,
                max_confidence=1,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )

            assert reviewed.review_status == "overridden"
            assert listed.total == 1
            serialized = str(producer.events).lower()
            assert "super-secret-token" not in serialized
            assert "raw_provider_payload" not in serialized

            with pytest.raises(HTTPException) as exc:
                await compliance_api.list_mappings(
                    skip=0,
                    limit=10,
                    framework=None,
                    framework_id=None,
                    finding_id=None,
                    control_id=None,
                    review_status=None,
                    mapping_source=None,
                    min_confidence=0.9,
                    max_confidence=0.1,
                    tenant=SimpleNamespace(id=tenant.id),
                    _=SimpleNamespace(id=uuid.uuid4()),
                    db=db,
                )
            assert exc.value.status_code == 400
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_phase6_detail_recommendation_and_cross_tenant_contracts():
    async with AsyncSessionLocal() as db:
        tenant_a, framework, _, _, assessment = await _setup_assessed_tenant(db)
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(3))
        try:
            evidence = (
                await db.execute(select(EvidenceItem).where(EvidenceItem.tenant_id == tenant_a.id))
            ).scalars().first()
            gap = (
                await db.execute(select(ComplianceGap).where(ComplianceGap.tenant_id == tenant_a.id))
            ).scalars().first()
            assert evidence is not None
            assert gap is not None

            controls = await compliance_api.list_assessment_controls(
                assessment.id,
                skip=0,
                limit=50,
                tenant=SimpleNamespace(id=tenant_a.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            evidence_detail = await compliance_api.get_evidence(
                evidence.id,
                tenant=SimpleNamespace(id=tenant_a.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            gap_detail = await compliance_api.get_gap(
                gap.id,
                tenant=SimpleNamespace(id=tenant_a.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            recommendations = await compliance_api.list_recommendations(
                skip=0,
                limit=50,
                framework=None,
                framework_id=framework.id,
                control_id=None,
                severity=None,
                tenant=SimpleNamespace(id=tenant_a.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )

            assert controls
            assert evidence_detail.id == evidence.id
            assert gap_detail.id == gap.id
            assert recommendations.total >= 1
            assert recommendations.status == "derived_from_existing_gaps"
            assert "super-secret-token" not in str(evidence_detail.model_dump(mode="json")).lower()

            with pytest.raises(NotFoundException):
                await compliance_api.get_evidence(
                    evidence.id,
                    tenant=SimpleNamespace(id=tenant_b.id),
                    _=SimpleNamespace(id=uuid.uuid4()),
                    db=db,
                )
            with pytest.raises(NotFoundException):
                await compliance_api.get_gap(
                    gap.id,
                    tenant=SimpleNamespace(id=tenant_b.id),
                    _=SimpleNamespace(id=uuid.uuid4()),
                    db=db,
                )
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_ask_session_list_and_detail_are_safe_and_filterable(monkeypatch):
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        await ComplianceKnowledgeIngestionService(db, event_producer=None).ingest_curated_catalog()
        tenant = await _tenant(db)
        framework = await _framework(db, "soc2")
        try:
            monkeypatch.setattr(
                compliance_api,
                "ComplianceAnswerService",
                lambda session: ComplianceAnswerService(session, event_producer=None),
            )
            answer = await compliance_api.ask_compliance_question(
                ComplianceAskRequest(
                    question="What SOC2 access control evidence should we review?",
                    framework_id=framework.id,
                ),
                tenant=SimpleNamespace(id=tenant.id),
                current_user=SimpleNamespace(id=None),
                db=db,
            )
            sessions = await compliance_api.list_ask_sessions(
                skip=0,
                limit=10,
                framework_id=framework.id,
                control_id=None,
                refused=False,
                min_confidence=0,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            detail = await compliance_api.get_ask_session(
                answer.session_id,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )

            assert sessions.total >= 1
            assert detail.id == answer.session_id
            assert detail.question_hash
            assert "what soc2 access control evidence" not in str(detail.model_dump(mode="json")).lower()
            assert detail.refused is False
        finally:
            await _cleanup(db, tenant.id)
