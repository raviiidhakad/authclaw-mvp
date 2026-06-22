from __future__ import annotations

import hashlib
import inspect
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import desc, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import NotFoundException
from app.models.compliance import (
    AgentComplianceSession,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    EvidenceItem,
    FindingControlMapping,
)
from app.models.finding import SecurityFinding
from app.models.integration import CloudIntegration
from app.schemas.events import ComplianceQuestionAskedEvent
from app.services.compliance_knowledge import (
    ComplianceRetrievalService,
    RetrievalResult,
    SECRET_PATTERNS,
)

logger = logging.getLogger(__name__)

COMPLIANCE_QUESTION_EVENTS_TOPIC = "authclaw.compliance.question.events"
MIN_RETRIEVAL_CONFIDENCE = 0.03

LEGAL_GUARANTEE_PATTERNS = (
    re.compile(r"(?i)\b(guarantee|certify|certification|legally compliant|legal advice)\b"),
    re.compile(r"(?i)\b(pass|clear)\s+(an?\s+)?audit\b"),
)
SECRET_REQUEST_PATTERNS = (
    re.compile(r"(?i)\b(raw provider payloads?|raw payloads?|vault references?|vault secrets?)\b"),
    re.compile(r"(?i)\b(show|expose|dump|print|reveal).*\b(secret|token|password|credential|api key|private key)\b"),
)
REMEDIATION_EXECUTION_PATTERNS = (
    re.compile(r"(?i)\b(apply|execute|run|deploy)\b.*\b(terraform|script|cli|command|remediation)\b"),
    re.compile(r"(?i)\bfix this for me\b"),
)
COMPLIANCE_SCOPE_TERMS = {
    "audit",
    "compliance",
    "control",
    "evidence",
    "framework",
    "gap",
    "gdpr",
    "hipaa",
    "iso",
    "policy",
    "posture",
    "privacy",
    "risk",
    "soc2",
    "security",
}


@dataclass(frozen=True)
class ComplianceAnswerResult:
    session: AgentComplianceSession
    answer: str
    confidence: float
    citations: list[dict[str, Any]]
    related_controls: list[dict[str, Any]]
    related_evidence: list[dict[str, Any]]
    related_gaps: list[dict[str, Any]]
    recommended_next_steps: list[str]
    refusal_reason: str | None = None
    retrieval_trace_id: uuid.UUID | None = None


@dataclass
class TenantComplianceContext:
    assessment: ComplianceAssessment | None = None
    controls: list[ComplianceControl] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    gaps: list[ComplianceGap] = field(default_factory=list)
    mappings: list[FindingControlMapping] = field(default_factory=list)


class ComplianceAnswerService:
    def __init__(
        self,
        db: AsyncSession,
        event_producer=default_event_producer,
        retrieval_service: ComplianceRetrievalService | None = None,
    ) -> None:
        self.db = db
        self.event_producer = event_producer
        self.retrieval_service = retrieval_service or ComplianceRetrievalService(db, event_producer=event_producer)

    async def answer_question(
        self,
        *,
        tenant_id: uuid.UUID | str,
        question: str,
        user_id: uuid.UUID | str | None = None,
        framework_id: uuid.UUID | str | None = None,
        control_id: uuid.UUID | str | None = None,
        finding_id: uuid.UUID | str | None = None,
        assessment_id: uuid.UUID | str | None = None,
    ) -> ComplianceAnswerResult:
        tenant_uuid = self._uuid(tenant_id)
        user_uuid = self._uuid(user_id) if user_id is not None else None
        framework_uuid = self._uuid(framework_id) if framework_id is not None else None
        control_uuid = self._uuid(control_id) if control_id is not None else None
        finding_uuid = self._uuid(finding_id) if finding_id is not None else None
        assessment_uuid = self._uuid(assessment_id) if assessment_id is not None else None
        await self._set_tenant_context(tenant_uuid)

        raw_question = question or ""
        sanitized_question = self._sanitize_question(raw_question)
        normalized_hash = self._question_hash(sanitized_question)

        pre_refusal = self._pre_refusal_reason(raw_question, framework_uuid, control_uuid, finding_uuid, assessment_uuid)
        retrieval: RetrievalResult | None = None
        context = TenantComplianceContext()

        if pre_refusal is None:
            retrieval = await self.retrieval_service.retrieve(
                tenant_id=tenant_uuid,
                query=sanitized_question,
                framework_id=framework_uuid,
                control_id=control_uuid,
                limit=5,
            )
            if retrieval.confidence < MIN_RETRIEVAL_CONFIDENCE:
                pre_refusal = "low_confidence_retrieval"
            else:
                context = await self._tenant_context(
                    tenant_uuid=tenant_uuid,
                    framework_uuid=framework_uuid,
                    control_uuid=control_uuid,
                    finding_uuid=finding_uuid,
                    assessment_uuid=assessment_uuid,
                    retrieval=retrieval,
                )

        if pre_refusal is not None:
            result = await self._persist_result(
                tenant_id=tenant_uuid,
                user_id=user_uuid,
                question=sanitized_question,
                normalized_hash=normalized_hash,
                answer=self._refusal_answer(pre_refusal),
                citations=[],
                confidence=0.0,
                refusal_reason=pre_refusal,
                framework_id=framework_uuid,
                control_id=control_uuid,
                assessment_id=assessment_uuid,
                retrieval_trace_id=retrieval.trace.id if retrieval else None,
                metadata={"mode": "deterministic_template", "refused": True},
            )
            await self._emit_event(result)
            return result

        assert retrieval is not None
        citations = [self._safe_citation(item.citation) for item in retrieval.results]
        related_controls = self._related_controls(context, retrieval)
        related_evidence = self._related_evidence(context)
        related_gaps = self._related_gaps(context)
        next_steps = self._next_steps(context)
        answer = self._build_answer(
            question=sanitized_question,
            retrieval=retrieval,
            context=context,
            related_controls=related_controls,
            related_evidence=related_evidence,
            related_gaps=related_gaps,
            next_steps=next_steps,
        )

        result = await self._persist_result(
            tenant_id=tenant_uuid,
            user_id=user_uuid,
            question=sanitized_question,
            normalized_hash=normalized_hash,
            answer=answer,
            citations=citations,
            confidence=retrieval.confidence,
            refusal_reason=None,
            framework_id=framework_uuid or self._first_uuid(citations, "framework_id"),
            control_id=control_uuid or self._first_uuid(citations, "control_id"),
            assessment_id=context.assessment.id if context.assessment is not None else assessment_uuid,
            retrieval_trace_id=retrieval.trace.id,
            metadata={
                "mode": "deterministic_template",
                "refused": False,
                "related_controls": related_controls,
                "related_evidence": related_evidence,
                "related_gaps": related_gaps,
                "recommended_next_steps": next_steps,
            },
        )
        await self._emit_event(result)
        return result

    async def _tenant_context(
        self,
        *,
        tenant_uuid: uuid.UUID,
        framework_uuid: uuid.UUID | None,
        control_uuid: uuid.UUID | None,
        finding_uuid: uuid.UUID | None,
        assessment_uuid: uuid.UUID | None,
        retrieval: RetrievalResult,
    ) -> TenantComplianceContext:
        control_ids = {
            uuid.UUID(item.citation["control_id"])
            for item in retrieval.results
            if item.citation.get("control_id")
        }
        if control_uuid is not None:
            control_ids.add(control_uuid)

        context = TenantComplianceContext()
        context.assessment = await self._assessment(tenant_uuid, assessment_uuid, framework_uuid)
        context.controls = await self._controls(control_ids)
        context.evidence = await self._evidence(tenant_uuid, framework_uuid, control_ids)
        context.gaps = await self._gaps(tenant_uuid, framework_uuid, control_ids, context.assessment)
        context.mappings = await self._mappings(tenant_uuid, framework_uuid, control_ids, finding_uuid)
        return context

    async def _assessment(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID | None,
        framework_id: uuid.UUID | None,
    ) -> ComplianceAssessment | None:
        query = select(ComplianceAssessment).where(ComplianceAssessment.tenant_id == tenant_id)
        if assessment_id is not None:
            query = query.where(ComplianceAssessment.id == assessment_id)
        elif framework_id is not None:
            query = query.where(ComplianceAssessment.framework_id == framework_id)
        else:
            query = query.order_by(desc(ComplianceAssessment.started_at)).limit(1)
        if assessment_id is not None or framework_id is not None:
            query = query.order_by(desc(ComplianceAssessment.started_at)).limit(1)
        return (await self.db.execute(query)).scalars().first()

    async def _controls(self, control_ids: set[uuid.UUID]) -> list[ComplianceControl]:
        if not control_ids:
            return []
        result = await self.db.execute(
            select(ComplianceControl)
            .where(ComplianceControl.id.in_(control_ids))
            .options(selectinload(ComplianceControl.framework))
        )
        return list(result.scalars().all())

    async def _evidence(
        self,
        tenant_id: uuid.UUID,
        framework_id: uuid.UUID | None,
        control_ids: set[uuid.UUID],
    ) -> list[EvidenceItem]:
        query = (
            select(EvidenceItem)
            .join(ComplianceControl, EvidenceItem.control_id == ComplianceControl.id)
            .where(EvidenceItem.tenant_id == tenant_id)
            .options(selectinload(EvidenceItem.control).selectinload(ComplianceControl.framework))
            .order_by(desc(EvidenceItem.updated_at))
            .limit(10)
        )
        if framework_id is not None:
            query = query.where(ComplianceControl.framework_id == framework_id)
        if control_ids:
            query = query.where(EvidenceItem.control_id.in_(control_ids))
        return list((await self.db.execute(query)).scalars().all())

    async def _gaps(
        self,
        tenant_id: uuid.UUID,
        framework_id: uuid.UUID | None,
        control_ids: set[uuid.UUID],
        assessment: ComplianceAssessment | None,
    ) -> list[ComplianceGap]:
        query = (
            select(ComplianceGap)
            .join(ComplianceControl, ComplianceGap.control_id == ComplianceControl.id)
            .where(ComplianceGap.tenant_id == tenant_id)
            .options(selectinload(ComplianceGap.control).selectinload(ComplianceControl.framework))
            .order_by(desc(ComplianceGap.created_at))
            .limit(10)
        )
        if assessment is not None:
            query = query.where(ComplianceGap.assessment_id == assessment.id)
        if framework_id is not None:
            query = query.where(ComplianceControl.framework_id == framework_id)
        if control_ids:
            query = query.where(ComplianceGap.control_id.in_(control_ids))
        return list((await self.db.execute(query)).scalars().all())

    async def _mappings(
        self,
        tenant_id: uuid.UUID,
        framework_id: uuid.UUID | None,
        control_ids: set[uuid.UUID],
        finding_id: uuid.UUID | None,
    ) -> list[FindingControlMapping]:
        query = (
            select(FindingControlMapping)
            .join(SecurityFinding, FindingControlMapping.finding_id == SecurityFinding.id)
            .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
            .join(ComplianceControl, FindingControlMapping.control_id == ComplianceControl.id)
            .where(
                FindingControlMapping.tenant_id == tenant_id,
                CloudIntegration.tenant_id == tenant_id,
            )
            .options(selectinload(FindingControlMapping.control))
            .order_by(desc(FindingControlMapping.confidence))
            .limit(10)
        )
        if framework_id is not None:
            query = query.where(ComplianceControl.framework_id == framework_id)
        if control_ids:
            query = query.where(FindingControlMapping.control_id.in_(control_ids))
        if finding_id is not None:
            query = query.where(FindingControlMapping.finding_id == finding_id)
        return list((await self.db.execute(query)).scalars().all())

    def _build_answer(
        self,
        *,
        question: str,
        retrieval: RetrievalResult,
        context: TenantComplianceContext,
        related_controls: list[dict[str, Any]],
        related_evidence: list[dict[str, Any]],
        related_gaps: list[dict[str, Any]],
        next_steps: list[str],
    ) -> str:
        lines = [
            "This is not legal advice. Based on AuthClaw-curated knowledge and tenant-safe context, the answer below describes evidence-supported posture, not a legal compliance guarantee.",
            "",
            "Known facts:",
        ]
        if context.assessment is not None:
            lines.append(
                f"- Latest referenced assessment score is {context.assessment.score:.2f} with band {self._enum_value(context.assessment.score_band)}."
            )
        if related_controls:
            controls = ", ".join(item["control_code"] for item in related_controls[:5])
            lines.append(f"- Relevant controls: {controls}.")
        if related_evidence:
            lines.append(f"- {len(related_evidence)} related evidence item(s) were found.")
        if related_gaps:
            gap_types = ", ".join(sorted({gap["gap_type"] for gap in related_gaps}))
            lines.append(f"- Related gaps include: {gap_types}.")
        if not related_evidence and not related_gaps and context.assessment is None:
            lines.append("- No tenant-specific assessment/evidence/gap context was found for this question.")

        lines.extend(
            [
                "",
                "Answer:",
                (
                    "Use the cited controls and evidence as review inputs. "
                    "The retrieved knowledge supports evaluating the question against the listed controls, "
                    "while tenant findings, evidence, and gaps determine the current evidence-supported posture."
                ),
                "",
                "Recommended next steps:",
            ]
        )
        lines.extend([f"- {step}" for step in next_steps])
        lines.extend(
            [
                "",
                f"Citations used: {len(retrieval.results)}. Retrieval confidence: {retrieval.confidence:.2f}.",
            ]
        )
        return "\n".join(lines)

    def _next_steps(self, context: TenantComplianceContext) -> list[str]:
        steps = [
            "Review cited control summaries and confirm they match the audit scope.",
            "Refresh evidence before relying on stale or missing evidence in audit preparation.",
        ]
        if context.gaps:
            steps.append("Prioritize open compliance gaps by severity and control weight.")
        if any(evidence.status.value in {"resolved", "suppressed"} for evidence in context.evidence):
            steps.append("Keep resolved or suppressed findings visible as auditor context.")
        steps.append("Route any remediation action through the existing approval workflow; this assistant does not execute changes.")
        return steps

    async def _persist_result(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID | None,
        question: str,
        normalized_hash: str,
        answer: str,
        citations: list[dict[str, Any]],
        confidence: float,
        refusal_reason: str | None,
        framework_id: uuid.UUID | None,
        control_id: uuid.UUID | None,
        assessment_id: uuid.UUID | None,
        retrieval_trace_id: uuid.UUID | None,
        metadata: dict[str, Any],
    ) -> ComplianceAnswerResult:
        session = AgentComplianceSession(
            tenant_id=tenant_id,
            user_id=user_id,
            question=question,
            normalized_question_hash=normalized_hash,
            answer=answer,
            citations=citations,
            confidence=confidence,
            refusal_reason=refusal_reason,
            framework_id=framework_id,
            control_id=control_id,
            assessment_id=assessment_id,
            retrieval_trace_id=retrieval_trace_id,
            metadata_=metadata,
        )
        self.db.add(session)
        await self.db.flush()
        return ComplianceAnswerResult(
            session=session,
            answer=answer,
            confidence=confidence,
            citations=citations,
            related_controls=metadata.get("related_controls", []),
            related_evidence=metadata.get("related_evidence", []),
            related_gaps=metadata.get("related_gaps", []),
            recommended_next_steps=metadata.get("recommended_next_steps", []),
            refusal_reason=refusal_reason,
            retrieval_trace_id=retrieval_trace_id,
        )

    async def _emit_event(self, result: ComplianceAnswerResult) -> None:
        if self.event_producer is None:
            return
        event = ComplianceQuestionAskedEvent(
            tenant_id=str(result.session.tenant_id),
            session_id=str(result.session.id),
            query_hash=result.session.normalized_question_hash,
            framework_id=str(result.session.framework_id) if result.session.framework_id else None,
            control_id=str(result.session.control_id) if result.session.control_id else None,
            confidence=result.confidence,
            refused=result.refusal_reason is not None,
            refusal_reason=result.refusal_reason,
            retrieval_trace_id=str(result.retrieval_trace_id) if result.retrieval_trace_id else None,
            citation_count=len(result.citations),
        )
        try:
            publish_result = self.event_producer.publish(COMPLIANCE_QUESTION_EVENTS_TOPIC, event)
            if inspect.isawaitable(publish_result):
                await publish_result
        except Exception as exc:
            logger.warning("Failed to publish compliance question event: %s", exc)

    def _related_controls(self, context: TenantComplianceContext, retrieval: RetrievalResult) -> list[dict[str, Any]]:
        controls_by_id = {control.id: control for control in context.controls}
        for item in retrieval.results:
            if item.citation.get("control_id"):
                control_id = uuid.UUID(item.citation["control_id"])
                if control_id not in controls_by_id and item.chunk.control is not None:
                    controls_by_id[control_id] = item.chunk.control
        return [
            {
                "control_id": str(control.id),
                "control_code": control.control_code,
                "title": control.title,
                "framework_id": str(control.framework_id),
            }
            for control in controls_by_id.values()
        ]

    def _related_evidence(self, context: TenantComplianceContext) -> list[dict[str, Any]]:
        return [
            {
                "evidence_id": str(evidence.id),
                "control_id": str(evidence.control_id),
                "status": self._enum_value(evidence.status),
                "safe_summary": evidence.safe_summary,
            }
            for evidence in context.evidence
        ]

    def _related_gaps(self, context: TenantComplianceContext) -> list[dict[str, Any]]:
        return [
            {
                "gap_id": str(gap.id),
                "control_id": str(gap.control_id),
                "gap_type": self._enum_value(gap.gap_type),
                "severity": self._enum_value(gap.severity),
                "reason": gap.reason,
            }
            for gap in context.gaps
        ]

    def _safe_citation(self, citation: dict[str, Any]) -> dict[str, Any]:
        return {
            "document_id": citation.get("document_id"),
            "document_title": citation.get("document_title"),
            "source_locator": citation.get("source_locator"),
            "source_url": citation.get("source_url"),
            "license_status": citation.get("license_status"),
            "trust_level": citation.get("trust_level"),
            "framework_id": citation.get("framework_id"),
            "control_id": citation.get("control_id"),
        }

    def _pre_refusal_reason(
        self,
        question: str,
        framework_id: uuid.UUID | None,
        control_id: uuid.UUID | None,
        finding_id: uuid.UUID | None,
        assessment_id: uuid.UUID | None,
    ) -> str | None:
        if any(pattern.search(question) for pattern in LEGAL_GUARANTEE_PATTERNS):
            return "legal_guarantee_requested"
        if any(pattern.search(question) for pattern in SECRET_REQUEST_PATTERNS):
            return "secret_or_raw_payload_requested"
        if any(pattern.search(question) for pattern in REMEDIATION_EXECUTION_PATTERNS):
            return "remediation_execution_requested"
        if not any(term in question.lower() for term in COMPLIANCE_SCOPE_TERMS) and not any(
            item is not None for item in (framework_id, control_id, finding_id, assessment_id)
        ):
            return "outside_supported_compliance_scope"
        return None

    def _refusal_answer(self, reason: str) -> str:
        messages = {
            "legal_guarantee_requested": "I cannot provide legal guarantees, certification claims, or legal advice. I can summarize evidence-supported posture and cite AuthClaw controls for human review.",
            "secret_or_raw_payload_requested": "I cannot expose secrets, credentials, Vault references, or raw provider payloads. I can discuss sanitized evidence and control posture instead.",
            "remediation_execution_requested": "I cannot execute Terraform, scripts, CLI commands, or remediation actions. Use the approved remediation workflow for any change.",
            "outside_supported_compliance_scope": "I can only answer compliance, evidence, control, finding, and audit-posture questions for AuthClaw data.",
            "low_confidence_retrieval": "I do not have enough relevant retrieved knowledge to answer safely. Try asking about a specific framework, control, evidence item, or assessment.",
        }
        return messages.get(reason, "I cannot answer this question safely.")

    def _sanitize_question(self, question: str) -> str:
        sanitized = (question or "").strip()
        for pattern in SECRET_PATTERNS:
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
        return sanitized[:4000]

    def _question_hash(self, question: str) -> str:
        normalized = " ".join(question.lower().split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _first_uuid(self, items: list[dict[str, Any]], key: str) -> uuid.UUID | None:
        for item in items:
            value = item.get(key)
            if value:
                return uuid.UUID(str(value))
        return None

    def _enum_value(self, value) -> str:
        return value.value if hasattr(value, "value") else str(value)

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
