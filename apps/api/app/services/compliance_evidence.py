from __future__ import annotations

import hashlib
import inspect
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events.producer import producer as default_event_producer
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
    ControlAssessmentResult,
    EvidenceItem,
    EvidenceSourceType,
    EvidenceStatus,
    FindingControlMapping,
    MappingReviewStatus,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration
from app.schemas.events import (
    ComplianceAssessmentCompletedEvent,
    ComplianceAssessmentStartedEvent,
    ComplianceGapDetectedEvent,
    ControlStatusChangedEvent,
    EvidenceCreatedEvent,
    EvidenceExpiredEvent,
)

logger = logging.getLogger(__name__)

COMPLIANCE_EVIDENCE_EVENTS_TOPIC = "authclaw.compliance.evidence.events"
COMPLIANCE_ASSESSMENT_EVENTS_TOPIC = "authclaw.compliance.assessment.events"
EVIDENCE_TTL_DAYS = 30


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class GapSpec:
    gap_type: ComplianceGapType
    severity: ComplianceGapSeverity
    reason: str
    evidence_status: str
    evidence_id: uuid.UUID | None = None
    mapping_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    metadata: dict | None = None


class ComplianceEvidenceEngine:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer

    async def refresh_evidence_for_tenant(
        self,
        tenant_id: uuid.UUID | str,
        framework_id: uuid.UUID | str | None = None,
    ) -> list[EvidenceItem]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        query = (
            select(FindingControlMapping.id)
            .join(ComplianceControl, FindingControlMapping.control_id == ComplianceControl.id)
            .where(FindingControlMapping.tenant_id == tenant_uuid)
            .order_by(FindingControlMapping.updated_at.desc())
        )
        if framework_id is not None:
            query = query.where(ComplianceControl.framework_id == self._uuid(framework_id))

        evidence: list[EvidenceItem] = []
        for mapping_id in (await self.db.execute(query)).scalars().all():
            evidence.append(await self.refresh_evidence_for_mapping(tenant_uuid, mapping_id))
        await self.expire_stale_evidence(tenant_uuid)
        await self.db.flush()
        return evidence

    async def refresh_evidence_for_mapping(
        self,
        tenant_id: uuid.UUID | str,
        mapping_id: uuid.UUID | str,
    ) -> EvidenceItem:
        tenant_uuid = self._uuid(tenant_id)
        mapping_uuid = self._uuid(mapping_id)
        await self._set_tenant_context(tenant_uuid)
        mapping, finding = await self._get_mapping_and_finding(tenant_uuid, mapping_uuid)
        status = self._evidence_status_for_finding(finding.status)

        query = select(EvidenceItem).where(
            EvidenceItem.tenant_id == tenant_uuid,
            EvidenceItem.control_id == mapping.control_id,
            EvidenceItem.finding_id == finding.id,
            EvidenceItem.mapping_id == mapping.id,
            EvidenceItem.source_type == EvidenceSourceType.finding_mapping,
        )
        evidence = (await self.db.execute(query)).scalars().first()
        created = evidence is None
        if evidence is None:
            evidence = EvidenceItem(
                tenant_id=tenant_uuid,
                control_id=mapping.control_id,
                finding_id=finding.id,
                integration_id=finding.integration_id,
                mapping_id=mapping.id,
                source_type=EvidenceSourceType.finding_mapping,
            )
            self.db.add(evidence)

        evidence.status = status
        evidence.safe_summary = self._safe_summary(mapping, finding)
        evidence.freshness_expires_at = _utcnow() + timedelta(days=EVIDENCE_TTL_DAYS)
        evidence.metadata_ = self._safe_metadata(mapping, finding)
        evidence.proof_hash = self._proof_hash(evidence)
        await self.db.flush()

        if created:
            await self._publish_event(
                COMPLIANCE_EVIDENCE_EVENTS_TOPIC,
                EvidenceCreatedEvent(
                    tenant_id=str(tenant_uuid),
                    evidence_id=str(evidence.id),
                    control_id=str(evidence.control_id),
                    finding_id=str(evidence.finding_id) if evidence.finding_id else None,
                    mapping_id=str(evidence.mapping_id) if evidence.mapping_id else None,
                    status=evidence.status.value,
                ),
            )
        return evidence

    async def expire_stale_evidence(self, tenant_id: uuid.UUID | str) -> list[EvidenceItem]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        now = _utcnow()
        query = select(EvidenceItem).where(
            EvidenceItem.tenant_id == tenant_uuid,
            EvidenceItem.freshness_expires_at.is_not(None),
            EvidenceItem.freshness_expires_at < now,
            EvidenceItem.status != EvidenceStatus.expired,
        )
        expired = list((await self.db.execute(query)).scalars().all())
        for evidence in expired:
            evidence.status = EvidenceStatus.expired
            await self._publish_event(
                COMPLIANCE_EVIDENCE_EVENTS_TOPIC,
                EvidenceExpiredEvent(
                    tenant_id=str(tenant_uuid),
                    evidence_id=str(evidence.id),
                    control_id=str(evidence.control_id),
                    finding_id=str(evidence.finding_id) if evidence.finding_id else None,
                    mapping_id=str(evidence.mapping_id) if evidence.mapping_id else None,
                    status=evidence.status.value,
                ),
            )
        await self.db.flush()
        return expired

    async def get_evidence_for_control(
        self,
        tenant_id: uuid.UUID | str,
        control_id: uuid.UUID | str,
    ) -> list[EvidenceItem]:
        tenant_uuid = self._uuid(tenant_id)
        control_uuid = self._uuid(control_id)
        await self._set_tenant_context(tenant_uuid)
        query = (
            select(EvidenceItem)
            .where(EvidenceItem.tenant_id == tenant_uuid, EvidenceItem.control_id == control_uuid)
            .options(
                selectinload(EvidenceItem.control).selectinload(ComplianceControl.framework),
                selectinload(EvidenceItem.mapping),
                selectinload(EvidenceItem.finding),
            )
            .order_by(EvidenceItem.created_at.desc())
        )
        return list((await self.db.execute(query)).scalars().all())

    async def _get_mapping_and_finding(
        self,
        tenant_id: uuid.UUID,
        mapping_id: uuid.UUID,
    ) -> tuple[FindingControlMapping, SecurityFinding]:
        query = (
            select(FindingControlMapping, SecurityFinding)
            .join(SecurityFinding, FindingControlMapping.finding_id == SecurityFinding.id)
            .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
            .where(
                FindingControlMapping.tenant_id == tenant_id,
                FindingControlMapping.id == mapping_id,
                CloudIntegration.tenant_id == tenant_id,
            )
            .options(selectinload(FindingControlMapping.control))
        )
        row = (await self.db.execute(query)).first()
        if row is None:
            raise NotFoundException(detail="Finding control mapping not found")
        return row[0], row[1]

    def _evidence_status_for_finding(self, status: FindingStatus | str) -> EvidenceStatus:
        status_value = self._enum_value(status)
        if status_value == FindingStatus.resolved.value:
            return EvidenceStatus.resolved
        if status_value == FindingStatus.suppressed.value:
            return EvidenceStatus.suppressed
        return EvidenceStatus.active

    def _safe_summary(self, mapping: FindingControlMapping, finding: SecurityFinding) -> str:
        severity = self._enum_value(finding.severity)
        status = self._enum_value(finding.status)
        control_code = mapping.control.control_code if mapping.control is not None else str(mapping.control_id)
        return (
            f"{severity} {status} normalized security finding mapped to "
            f"{control_code} by rule {mapping.rule_id}."
        )

    def _safe_metadata(self, mapping: FindingControlMapping, finding: SecurityFinding) -> dict:
        return {
            "finding_severity": self._enum_value(finding.severity),
            "finding_status": self._enum_value(finding.status),
            "mapping_confidence": round(float(mapping.confidence), 4),
            "mapping_review_status": self._enum_value(mapping.review_status),
            "mapping_source": self._enum_value(mapping.mapping_source),
            "rule_id": mapping.rule_id,
        }

    def _proof_hash(self, evidence: EvidenceItem) -> str:
        stable = "|".join(
            [
                str(evidence.tenant_id),
                str(evidence.control_id),
                str(evidence.finding_id or ""),
                str(evidence.mapping_id or ""),
                self._enum_value(evidence.source_type),
                self._enum_value(evidence.status),
                json.dumps(evidence.metadata_, sort_keys=True),
            ]
        )
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    async def _publish_event(self, topic: str, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(topic, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish compliance evidence event %s: %s", event.event_type, exc)

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


class ComplianceScoringService:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer
        self.evidence_engine = ComplianceEvidenceEngine(db, event_producer=event_producer)

    async def run_assessment(
        self,
        tenant_id: uuid.UUID | str,
        framework_id: uuid.UUID | str,
    ) -> ComplianceAssessment:
        tenant_uuid = self._uuid(tenant_id)
        framework_uuid = self._uuid(framework_id)
        await self._set_tenant_context(tenant_uuid)
        framework = await self._get_framework(framework_uuid)

        await self.evidence_engine.refresh_evidence_for_tenant(tenant_uuid, framework_uuid)
        inputs_hash = await self._inputs_hash(tenant_uuid, framework_uuid)
        assessment = ComplianceAssessment(
            tenant_id=tenant_uuid,
            framework_id=framework_uuid,
            status=ComplianceAssessmentStatus.running,
            score=0,
            score_band=ComplianceScoreBand.high_risk,
            inputs_hash=inputs_hash,
            explanation="Assessment running. Scores represent evidence-supported posture, not legal compliance.",
        )
        self.db.add(assessment)
        await self.db.flush()
        await self._publish_event(
            COMPLIANCE_ASSESSMENT_EVENTS_TOPIC,
            ComplianceAssessmentStartedEvent(
                tenant_id=str(tenant_uuid),
                assessment_id=str(assessment.id),
                framework_id=str(framework_uuid),
                status=assessment.status.value,
            ),
        )

        controls = await self._framework_controls(framework_uuid)
        weighted_score = 0.0
        total_weight = 0
        critical_open_risk = False
        all_gaps: list[ComplianceGap] = []

        for control in controls:
            score, gap_specs, explanation, metadata = await self._score_control(tenant_uuid, control)
            band = self._score_band(score)
            result = ControlAssessmentResult(
                tenant_id=tenant_uuid,
                assessment_id=assessment.id,
                control_id=control.id,
                score=score,
                score_band=band,
                evidence_count=int(metadata["evidence_count"]),
                gap_count=len(gap_specs),
                explanation=explanation,
                metadata_=metadata,
            )
            self.db.add(result)
            weight = max(1, int(control.severity_weight or 1))
            weighted_score += score * weight
            total_weight += weight

            for spec in gap_specs:
                if spec.gap_type == ComplianceGapType.critical_open_risk:
                    critical_open_risk = True
                gap = ComplianceGap(
                    tenant_id=tenant_uuid,
                    assessment_id=assessment.id,
                    control_id=control.id,
                    evidence_id=spec.evidence_id,
                    mapping_id=spec.mapping_id,
                    finding_id=spec.finding_id,
                    gap_type=spec.gap_type,
                    severity=spec.severity,
                    reason=spec.reason,
                    evidence_status=spec.evidence_status,
                    metadata_=spec.metadata or {},
                )
                self.db.add(gap)
                all_gaps.append(gap)

            await self._publish_event(
                COMPLIANCE_ASSESSMENT_EVENTS_TOPIC,
                ControlStatusChangedEvent(
                    tenant_id=str(tenant_uuid),
                    assessment_id=str(assessment.id),
                    control_id=str(control.id),
                    score=score,
                    score_band=band.value,
                ),
            )

        score = round(weighted_score / total_weight, 2) if total_weight else 0.0
        if critical_open_risk:
            score = min(score, 49.0)
        assessment.status = ComplianceAssessmentStatus.completed
        assessment.score = score
        assessment.score_band = self._score_band(score)
        assessment.completed_at = _utcnow()
        assessment.explanation = self._assessment_explanation(framework, score, assessment.score_band, all_gaps)
        await self.db.flush()

        for gap in all_gaps:
            await self._publish_event(
                COMPLIANCE_ASSESSMENT_EVENTS_TOPIC,
                ComplianceGapDetectedEvent(
                    tenant_id=str(tenant_uuid),
                    assessment_id=str(assessment.id),
                    control_id=str(gap.control_id),
                    gap_type=gap.gap_type.value,
                    severity=gap.severity.value,
                    evidence_status=gap.evidence_status,
                    evidence_id=str(gap.evidence_id) if gap.evidence_id else None,
                    finding_id=str(gap.finding_id) if gap.finding_id else None,
                    mapping_id=str(gap.mapping_id) if gap.mapping_id else None,
                ),
            )

        await self._publish_event(
            COMPLIANCE_ASSESSMENT_EVENTS_TOPIC,
            ComplianceAssessmentCompletedEvent(
                tenant_id=str(tenant_uuid),
                assessment_id=str(assessment.id),
                framework_id=str(framework_uuid),
                status=assessment.status.value,
                score=assessment.score,
                score_band=assessment.score_band.value,
            ),
        )
        return assessment

    async def _score_control(
        self,
        tenant_id: uuid.UUID,
        control: ComplianceControl,
    ) -> tuple[float, list[GapSpec], str, dict]:
        evidence_items = await self._control_evidence(tenant_id, control.id)
        if not evidence_items:
            severity = ComplianceGapSeverity.high if int(control.severity_weight or 1) >= 3 else ComplianceGapSeverity.medium
            return (
                55.0,
                [
                    GapSpec(
                        gap_type=ComplianceGapType.missing_evidence,
                        severity=severity,
                        reason="No current evidence item supports this control.",
                        evidence_status="missing",
                        metadata={"control_weight": int(control.severity_weight or 1)},
                    )
                ],
                "No evidence item currently supports this control; posture is at risk.",
                {"evidence_count": 0, "penalties": [{"type": "missing_evidence", "points": 45}]},
            )

        penalties: list[dict] = []
        gaps: list[GapSpec] = []
        score = 96.0
        now = _utcnow()

        for evidence in evidence_items:
            mapping = evidence.mapping
            finding = evidence.finding
            evidence_status = self._enum_value(evidence.status)

            if evidence.status in {EvidenceStatus.stale, EvidenceStatus.expired} or (
                evidence.freshness_expires_at is not None and evidence.freshness_expires_at < now
            ):
                score -= 20
                penalties.append({"type": "stale_evidence", "points": 20})
                gaps.append(
                    GapSpec(
                        ComplianceGapType.stale_evidence,
                        ComplianceGapSeverity.medium,
                        "Evidence freshness has expired and should be refreshed.",
                        evidence_status,
                        evidence_id=evidence.id,
                        mapping_id=evidence.mapping_id,
                        finding_id=evidence.finding_id,
                    )
                )

            if mapping is not None:
                confidence = float(mapping.confidence)
                if confidence < 0.75:
                    points = round((0.75 - confidence) * 40, 2)
                    score -= points
                    penalties.append({"type": "low_confidence_mapping", "points": points})
                    gaps.append(
                        GapSpec(
                            ComplianceGapType.low_confidence_mapping,
                            ComplianceGapSeverity.medium,
                            "Finding-to-control mapping confidence is below the auto-review threshold.",
                            evidence_status,
                            evidence_id=evidence.id,
                            mapping_id=mapping.id,
                            finding_id=evidence.finding_id,
                            metadata={"confidence": confidence},
                        )
                    )
                if mapping.review_status in {
                    MappingReviewStatus.needs_review,
                    MappingReviewStatus.rejected,
                    MappingReviewStatus.overridden,
                }:
                    score -= 12
                    penalties.append({"type": "needs_review", "points": 12})
                    gaps.append(
                        GapSpec(
                            ComplianceGapType.needs_review,
                            ComplianceGapSeverity.medium,
                            "Mapped evidence requires human review before it should be treated as strong support.",
                            evidence_status,
                            evidence_id=evidence.id,
                            mapping_id=mapping.id,
                            finding_id=evidence.finding_id,
                            metadata={"review_status": self._enum_value(mapping.review_status)},
                        )
                    )

            if finding is None:
                continue

            finding_status = self._enum_value(finding.status)
            severity = self._enum_value(finding.severity)
            if finding_status in {
                FindingStatus.new.value,
                FindingStatus.active.value,
                FindingStatus.remediating.value,
            }:
                points = self._finding_penalty(severity, mapping.confidence if mapping is not None else 1.0)
                score -= points
                penalties.append({"type": "unresolved_finding", "severity": severity, "points": points})
                gaps.append(
                    GapSpec(
                        ComplianceGapType.unresolved_finding,
                        self._gap_severity(severity, control.severity_weight),
                        "A mapped security finding is still unresolved.",
                        evidence_status,
                        evidence_id=evidence.id,
                        mapping_id=evidence.mapping_id,
                        finding_id=finding.id,
                        metadata={"finding_severity": severity},
                    )
                )
                if severity == FindingSeverity.critical.value:
                    gaps.append(
                        GapSpec(
                            ComplianceGapType.critical_open_risk,
                            ComplianceGapSeverity.critical,
                            "A critical unresolved mapped finding caps framework posture.",
                            evidence_status,
                            evidence_id=evidence.id,
                            mapping_id=evidence.mapping_id,
                            finding_id=finding.id,
                            metadata={"finding_severity": severity},
                        )
                    )
            elif finding_status == FindingStatus.suppressed.value:
                score -= 8
                penalties.append({"type": "suppressed_context", "points": 8})
                gaps.append(
                    GapSpec(
                        ComplianceGapType.needs_review,
                        ComplianceGapSeverity.low,
                        "Suppressed finding remains visible as auditor context.",
                        evidence_status,
                        evidence_id=evidence.id,
                        mapping_id=evidence.mapping_id,
                        finding_id=finding.id,
                    )
                )

        score = max(0.0, min(100.0, round(score, 2)))
        if any(gap.gap_type == ComplianceGapType.critical_open_risk for gap in gaps):
            score = min(score, 49.0)
        explanation = self._control_explanation(score, gaps)
        metadata = {"evidence_count": len(evidence_items), "penalties": penalties}
        return score, gaps, explanation, metadata

    async def _control_evidence(self, tenant_id: uuid.UUID, control_id: uuid.UUID) -> list[EvidenceItem]:
        query = (
            select(EvidenceItem)
            .where(EvidenceItem.tenant_id == tenant_id, EvidenceItem.control_id == control_id)
            .options(selectinload(EvidenceItem.mapping), selectinload(EvidenceItem.finding))
            .order_by(EvidenceItem.updated_at.desc())
        )
        return list((await self.db.execute(query)).scalars().all())

    async def _framework_controls(self, framework_id: uuid.UUID) -> list[ComplianceControl]:
        query = (
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == framework_id)
            .order_by(ComplianceControl.sort_order, ComplianceControl.control_code)
        )
        return list((await self.db.execute(query)).scalars().all())

    async def _get_framework(self, framework_id: uuid.UUID) -> ComplianceFramework:
        framework = await self.db.get(ComplianceFramework, framework_id)
        if framework is None:
            raise NotFoundException(detail="Compliance framework not found")
        return framework

    async def _inputs_hash(self, tenant_id: uuid.UUID, framework_id: uuid.UUID) -> str:
        query = (
            select(EvidenceItem, FindingControlMapping)
            .join(ComplianceControl, EvidenceItem.control_id == ComplianceControl.id)
            .outerjoin(FindingControlMapping, EvidenceItem.mapping_id == FindingControlMapping.id)
            .where(EvidenceItem.tenant_id == tenant_id, ComplianceControl.framework_id == framework_id)
            .order_by(EvidenceItem.id)
        )
        rows = (await self.db.execute(query)).all()
        payload = [
            {
                "evidence_id": str(evidence.id),
                "status": self._enum_value(evidence.status),
                "proof_hash": evidence.proof_hash,
                "mapping_confidence": mapping.confidence if mapping is not None else None,
                "review_status": self._enum_value(mapping.review_status) if mapping is not None else None,
                "updated_at": evidence.updated_at.isoformat() if evidence.updated_at else None,
            }
            for evidence, mapping in rows
        ]
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def _finding_penalty(self, severity: str, confidence: float) -> float:
        base = {
            FindingSeverity.critical.value: 55,
            FindingSeverity.high.value: 38,
            FindingSeverity.medium.value: 22,
            FindingSeverity.low.value: 10,
        }.get(severity, 22)
        return round(base * max(0.5, min(1.0, float(confidence))), 2)

    def _gap_severity(self, finding_severity: str, control_weight: int) -> ComplianceGapSeverity:
        if finding_severity == FindingSeverity.critical.value:
            return ComplianceGapSeverity.critical
        if finding_severity == FindingSeverity.high.value or int(control_weight or 1) >= 3:
            return ComplianceGapSeverity.high
        if finding_severity == FindingSeverity.medium.value:
            return ComplianceGapSeverity.medium
        return ComplianceGapSeverity.low

    def _score_band(self, score: float) -> ComplianceScoreBand:
        if score >= 90:
            return ComplianceScoreBand.strong
        if score >= 75:
            return ComplianceScoreBand.mostly_supported
        if score >= 50:
            return ComplianceScoreBand.at_risk
        return ComplianceScoreBand.high_risk

    def _control_explanation(self, score: float, gaps: Iterable[GapSpec]) -> str:
        gap_types = sorted({gap.gap_type.value for gap in gaps})
        if not gap_types:
            return f"Control posture score {score} is supported by current evidence. This is not a legal compliance claim."
        return (
            f"Control posture score {score} reflects evidence gaps: "
            f"{', '.join(gap_types)}. This is not a legal compliance claim."
        )

    def _assessment_explanation(
        self,
        framework: ComplianceFramework,
        score: float,
        band: ComplianceScoreBand,
        gaps: list[ComplianceGap],
    ) -> str:
        counts: dict[str, int] = {}
        for gap in gaps:
            counts[gap.gap_type.value] = counts.get(gap.gap_type.value, 0) + 1
        return json.dumps(
            {
                "framework": framework.key,
                "score": score,
                "score_band": band.value,
                "posture_language": "evidence-supported posture",
                "legal_disclaimer": "This assessment does not claim legal compliance.",
                "gap_counts": counts,
            },
            sort_keys=True,
        )

    async def _publish_event(self, topic: str, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(topic, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish compliance assessment event %s: %s", event.event_type, exc)

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
