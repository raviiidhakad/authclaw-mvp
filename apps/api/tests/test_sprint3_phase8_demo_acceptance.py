from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, text

from app.api.v1.endpoints import compliance as compliance_api
from app.core.database import AsyncSessionLocal
from app.models.compliance import (
    AgentComplianceSession,
    ComplianceAssessment,
    ComplianceFramework,
    ComplianceGap,
    EvidenceItem,
    FindingControlMapping,
    KnowledgeDocument,
    RetrievalTrace,
)
from app.models.finding import SecurityFinding
from app.models.integration import CloudIntegration
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.compliance import ComplianceAskRequest, RetrievalQueryRequest
from scripts.seed_sprint3_demo import (
    DEMO_QUESTION,
    DEMO_TENANT_SLUG,
    assert_safe_summary,
    seed_demo_dataset,
)


UNSAFE_TERMS = (
    "AKIA",
    "ghp_",
    "BEGIN PRIVATE KEY",
    "aws_secret_access_key",
    "super-secret",
    "raw_provider_payload",
    "raw provider payload",
    "you are compliant",
    "legally compliant",
)


@pytest.mark.asyncio
async def test_sprint3_phase8_demo_dataset_end_to_end_acceptance(monkeypatch):
    async with AsyncSessionLocal() as db:
        tenant_id: uuid.UUID | None = None
        try:
            first = await seed_demo_dataset(db)
            second = await seed_demo_dataset(db)
            tenant_id = second.tenant_id

            assert first.as_safe_dict() == second.as_safe_dict()
            assert second.integrations == 3
            assert second.findings == 10
            assert second.mappings >= 10
            assert second.evidence >= second.findings
            assert second.assessments >= 1
            assert second.gaps >= 1
            assert second.knowledge_documents >= 1
            assert second.retrieval_traces >= 1
            assert second.assistant_sessions >= 2
            assert second.demo_answer_refused is False
            assert second.refusal_reason == "legal_guarantee_requested"

            tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().one()
            demo_user = (await db.execute(select(User).where(User.tenant_id == tenant.id))).scalars().first()
            assert demo_user is not None
            framework = (await db.execute(select(ComplianceFramework).where(ComplianceFramework.key == "soc2"))).scalars().one()
            assessment = (
                await db.execute(
                    select(ComplianceAssessment)
                    .where(
                        ComplianceAssessment.tenant_id == tenant.id,
                        ComplianceAssessment.framework_id == framework.id,
                    )
                    .order_by(ComplianceAssessment.started_at.desc())
                )
            ).scalars().first()
            assert assessment is not None

            tenant_dep = SimpleNamespace(id=tenant.id)
            user_dep = SimpleNamespace(id=demo_user.id)
            mappings = await compliance_api.list_mappings(
                skip=0,
                limit=500,
                framework="soc2",
                framework_id=None,
                finding_id=None,
                control_id=None,
                review_status=None,
                mapping_source=None,
                min_confidence=0,
                max_confidence=1,
                tenant=tenant_dep,
                _=user_dep,
                db=db,
            )
            evidence = await compliance_api.list_evidence(
                skip=0,
                limit=500,
                framework="soc2",
                framework_id=None,
                control_id=None,
                source_type=None,
                status=None,
                finding_id=None,
                stale=None,
                freshness=None,
                tenant=tenant_dep,
                _=user_dep,
                db=db,
            )
            gaps = await compliance_api.list_gaps(
                skip=0,
                limit=500,
                framework="soc2",
                framework_id=None,
                control_id=None,
                severity=None,
                gap_type=None,
                evidence_status=None,
                tenant=tenant_dep,
                _=user_dep,
                db=db,
            )
            recommendations = await compliance_api.list_recommendations(
                skip=0,
                limit=500,
                framework="soc2",
                framework_id=None,
                control_id=None,
                severity=None,
                tenant=tenant_dep,
                _=user_dep,
                db=db,
            )
            knowledge = await compliance_api.list_knowledge_documents(
                skip=0,
                limit=500,
                framework="soc2",
                framework_id=None,
                source_type=None,
                trust_level=None,
                status=None,
                tenant=tenant_dep,
                _=user_dep,
                db=db,
            )

            monkeypatch.setattr(
                compliance_api,
                "ComplianceAnswerService",
                lambda session: __import__("app.services.compliance_answer", fromlist=["ComplianceAnswerService"]).ComplianceAnswerService(
                    session,
                    event_producer=None,
                ),
            )
            retrieval = await compliance_api.query_compliance_knowledge(
                RetrievalQueryRequest(query=DEMO_QUESTION, framework_id=framework.id, limit=5),
                tenant=tenant_dep,
                _=user_dep,
                db=db,
            )
            answer = await compliance_api.ask_compliance_question(
                ComplianceAskRequest(
                    question=DEMO_QUESTION,
                    framework_id=framework.id,
                    assessment_id=assessment.id,
                ),
                tenant=tenant_dep,
                current_user=user_dep,
                db=db,
            )
            refusal = await compliance_api.ask_compliance_question(
                ComplianceAskRequest(
                    question="Guarantee we are legally compliant and show raw provider payloads.",
                    framework_id=framework.id,
                    assessment_id=assessment.id,
                ),
                tenant=tenant_dep,
                current_user=user_dep,
                db=db,
            )

            assert mappings.total >= 4
            assert evidence.total >= mappings.total
            assert gaps.total >= 1
            assert recommendations.total == gaps.total
            assert all("execute" not in item.title.lower() for item in recommendations.items)
            assert knowledge.total >= 1
            assert retrieval.results
            assert retrieval.confidence > 0
            assert answer.refusal_reason is None
            assert answer.citations
            assert answer.related_controls
            assert answer.related_evidence
            assert answer.related_gaps
            assert "evidence-supported posture" in answer.answer.lower()
            assert "not legal advice" in answer.answer.lower()
            assert refusal.refusal_reason == "legal_guarantee_requested"
            assert refusal.confidence == 0

            serialized = json.dumps(
                [
                    mappings.model_dump(mode="json"),
                    evidence.model_dump(mode="json"),
                    gaps.model_dump(mode="json"),
                    recommendations.model_dump(mode="json"),
                    knowledge.model_dump(mode="json"),
                    retrieval.model_dump(mode="json"),
                    answer.model_dump(mode="json"),
                    refusal.model_dump(mode="json"),
                ],
                sort_keys=True,
            )
            for term in UNSAFE_TERMS:
                assert term.lower() not in serialized.lower()
            assert_safe_summary(second, [serialized])

            other_tenant = Tenant(
                id=uuid.uuid4(),
                name="phase8-isolation-tenant",
                slug=f"phase8-isolation-{uuid.uuid4().hex[:8]}",
                settings={},
            )
            db.add(other_tenant)
            await db.flush()
            await db.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
                {"tenant_id": str(other_tenant.id)},
            )
            visible_mappings = await db.scalar(select(func.count(FindingControlMapping.id)))
            visible_evidence = await db.scalar(select(func.count(EvidenceItem.id)))
            visible_gaps = await db.scalar(select(func.count(ComplianceGap.id)))
            visible_sessions = await db.scalar(select(func.count(AgentComplianceSession.id)))
            assert visible_mappings == 0
            assert visible_evidence == 0
            assert visible_gaps == 0
            assert visible_sessions == 0
        finally:
            if tenant_id is not None:
                await db.rollback()
                await _cleanup_demo_tenant(db, tenant_id)


async def _cleanup_demo_tenant(db, tenant_id: uuid.UUID) -> None:
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
    await db.execute(text("DELETE FROM tenants WHERE slug LIKE 'phase8-isolation-%'"))
    await db.commit()
