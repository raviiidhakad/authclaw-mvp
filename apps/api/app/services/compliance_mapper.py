from __future__ import annotations

import inspect
import logging
import uuid
from dataclasses import dataclass
from typing import Iterable, Sequence

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import NotFoundException
from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    FindingControlMapping,
    MappingReviewStatus,
    MappingSource,
)
from app.models.finding import FindingSeverity, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider
from app.schemas.events import (
    FindingMappedToControlEvent,
    FindingMappingNeedsReviewEvent,
    FindingMappingOverriddenEvent,
)
from app.services.findings_context import FindingsContextBuilder

logger = logging.getLogger(__name__)

COMPLIANCE_MAPPING_EVENTS_TOPIC = "authclaw.compliance.mapping.events"
MANUAL_RULE_ID = "manual_override"


@dataclass(frozen=True)
class MappingRule:
    rule_id: str
    control_codes: tuple[str, ...]
    confidence: float
    keywords: tuple[str, ...]
    providers: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    source: MappingSource = MappingSource.deterministic


@dataclass(frozen=True)
class MappingMatch:
    rule: MappingRule
    control_codes: tuple[str, ...]
    confidence: float
    review_status: MappingReviewStatus


RULES: tuple[MappingRule, ...] = (
    MappingRule(
        rule_id="aws_s3_public_bucket",
        providers=("aws",),
        services=("s3",),
        keywords=("public", "bucket"),
        control_codes=("SOC2-SEC-ACCESS", "GDPR-SEC-32", "ISO27001-ACCESS"),
        confidence=0.94,
    ),
    MappingRule(
        rule_id="aws_cloudtrail_missing",
        providers=("aws",),
        services=("cloudtrail",),
        keywords=("cloudtrail", "trail", "disabled", "missing", "not configured"),
        control_codes=("SOC2-SEC-MONITOR", "HIPAA-TECH-AUDIT", "ISO27001-LOGGING", "GDPR-SEC-32"),
        confidence=0.93,
    ),
    MappingRule(
        rule_id="aws_kms_weak_encryption",
        providers=("aws",),
        services=("kms",),
        keywords=("kms", "encryption", "rotation", "disabled", "unencrypted"),
        control_codes=("GDPR-SEC-32", "SOC2-SEC-ACCESS", "ISO27001-ACCESS"),
        confidence=0.88,
    ),
    MappingRule(
        rule_id="cloud_iam_overpermissioned",
        services=("iam",),
        keywords=("iam", "admin", "owner", "over", "permission", "privilege", "wildcard"),
        control_codes=("SOC2-SEC-ACCESS", "HIPAA-TECH-ACCESS", "ISO27001-ACCESS", "GDPR-SEC-32"),
        confidence=0.9,
    ),
    MappingRule(
        rule_id="github_secret_exposure",
        providers=("github",),
        services=("secret_scanning",),
        keywords=("secret", "token", "credential", "leak", "exposure"),
        control_codes=("SOC2-SEC-ACCESS", "GDPR-SEC-32", "ISO27001-ACCESS", "AC-AI-GW-POLICY"),
        confidence=0.95,
    ),
    MappingRule(
        rule_id="github_branch_protection_missing",
        providers=("github",),
        services=("branch_protection",),
        keywords=("branch", "protection", "missing", "disabled", "required review"),
        control_codes=("SOC2-SEC-ACCESS", "ISO27001-ACCESS"),
        confidence=0.86,
    ),
    MappingRule(
        rule_id="github_actions_insecure_permissions",
        providers=("github",),
        keywords=("actions", "workflow", "write", "permission"),
        control_codes=("SOC2-SEC-ACCESS", "ISO27001-ACCESS"),
        confidence=0.84,
    ),
    MappingRule(
        rule_id="gcp_public_bucket",
        providers=("gcp",),
        services=("cloud_storage",),
        keywords=("public", "bucket", "storage", "allusers", "allauthenticatedusers"),
        control_codes=("SOC2-SEC-ACCESS", "GDPR-SEC-32", "ISO27001-ACCESS"),
        confidence=0.93,
    ),
    MappingRule(
        rule_id="gcp_iam_overpermissioned",
        providers=("gcp",),
        services=("iam",),
        keywords=("iam", "owner", "allusers", "over", "permission", "binding"),
        control_codes=("SOC2-SEC-ACCESS", "HIPAA-TECH-ACCESS", "ISO27001-ACCESS", "GDPR-SEC-32"),
        confidence=0.89,
    ),
    MappingRule(
        rule_id="pii_phi_data_leakage",
        keywords=("pii", "phi", "personal data", "patient", "health", "redaction", "leak"),
        control_codes=("HIPAA-TECH-ACCESS", "HIPAA-TECH-AUDIT", "GDPR-ACC-5", "GDPR-SEC-32", "AC-AI-GW-POLICY"),
        confidence=0.92,
    ),
)


class FindingControlMapper:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer
        self.context_builder = FindingsContextBuilder(db=None)

    async def map_finding(
        self,
        tenant_id: uuid.UUID | str,
        finding_id: uuid.UUID | str,
    ) -> list[FindingControlMapping]:
        tenant_uuid = self._uuid(tenant_id)
        finding_uuid = self._uuid(finding_id)
        await self._set_tenant_context(tenant_uuid)
        finding, provider = await self._get_finding_for_tenant(tenant_uuid, finding_uuid)
        matches = self._match_rules(finding, provider)
        mappings = await self._upsert_matches(tenant_uuid, finding, matches)
        await self.db.flush()
        return mappings

    async def remap_finding(
        self,
        tenant_id: uuid.UUID | str,
        finding_id: uuid.UUID | str,
    ) -> list[FindingControlMapping]:
        return await self.map_finding(tenant_id, finding_id)

    async def map_findings_for_tenant(
        self,
        tenant_id: uuid.UUID | str,
        limit: int | None = None,
    ) -> list[FindingControlMapping]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        query = (
            select(SecurityFinding.id)
            .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
            .where(CloudIntegration.tenant_id == tenant_uuid)
            .order_by(SecurityFinding.updated_at.desc(), SecurityFinding.created_at.desc())
        )
        if limit is not None:
            query = query.limit(max(0, int(limit)))
        result = await self.db.execute(query)

        mapped: list[FindingControlMapping] = []
        for finding_id in result.scalars().all():
            mapped.extend(await self.map_finding(tenant_uuid, finding_id))
        return mapped

    async def get_mappings_for_finding(
        self,
        tenant_id: uuid.UUID | str,
        finding_id: uuid.UUID | str,
    ) -> list[FindingControlMapping]:
        tenant_uuid = self._uuid(tenant_id)
        finding_uuid = self._uuid(finding_id)
        await self._set_tenant_context(tenant_uuid)
        query = (
            select(FindingControlMapping)
            .where(
                FindingControlMapping.tenant_id == tenant_uuid,
                FindingControlMapping.finding_id == finding_uuid,
            )
            .options(selectinload(FindingControlMapping.control))
            .order_by(FindingControlMapping.confidence.desc())
        )
        return list((await self.db.execute(query)).scalars().all())

    async def get_mappings_for_control(
        self,
        tenant_id: uuid.UUID | str,
        control_id: uuid.UUID | str,
    ) -> list[FindingControlMapping]:
        tenant_uuid = self._uuid(tenant_id)
        control_uuid = self._uuid(control_id)
        await self._set_tenant_context(tenant_uuid)
        query = (
            select(FindingControlMapping)
            .where(
                FindingControlMapping.tenant_id == tenant_uuid,
                FindingControlMapping.control_id == control_uuid,
            )
            .options(selectinload(FindingControlMapping.control))
            .order_by(FindingControlMapping.confidence.desc())
        )
        return list((await self.db.execute(query)).scalars().all())

    async def override_mapping(
        self,
        tenant_id: uuid.UUID | str,
        mapping_id: uuid.UUID | str,
        review_status: MappingReviewStatus,
        override_reason: str,
        confidence: float | None = None,
    ) -> FindingControlMapping:
        tenant_uuid = self._uuid(tenant_id)
        mapping_uuid = self._uuid(mapping_id)
        await self._set_tenant_context(tenant_uuid)
        query = select(FindingControlMapping).where(
            FindingControlMapping.tenant_id == tenant_uuid,
            FindingControlMapping.id == mapping_uuid,
        )
        mapping = (await self.db.execute(query)).scalars().first()
        if mapping is None:
            raise NotFoundException(detail="Finding control mapping not found")

        mapping.review_status = review_status
        mapping.mapping_source = MappingSource.manual
        mapping.override_reason = override_reason
        if confidence is not None:
            mapping.confidence = self._bounded_confidence(confidence)
        await self.db.flush()
        await self._emit_override_event(mapping)
        return mapping

    async def _get_finding_for_tenant(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
    ) -> tuple[SecurityFinding, CloudProvider]:
        query = (
            select(SecurityFinding, CloudIntegration.provider_type)
            .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
            .where(
                CloudIntegration.tenant_id == tenant_id,
                SecurityFinding.id == finding_id,
            )
        )
        row = (await self.db.execute(query)).first()
        if row is None:
            raise NotFoundException(detail="Security finding not found")
        return row[0], row[1]

    def _match_rules(
        self,
        finding: SecurityFinding,
        provider: CloudProvider,
    ) -> list[MappingMatch]:
        provider_value = provider.value
        service = self.context_builder._infer_service(provider_value, finding.resource_id, finding.title)
        haystack = self._haystack(finding, provider_value, service)
        matches: list[MappingMatch] = []

        for rule in RULES:
            if rule.providers and provider_value not in rule.providers:
                continue
            if rule.services and service not in rule.services:
                continue
            if not any(keyword in haystack for keyword in rule.keywords):
                continue
            matches.append(
                MappingMatch(
                    rule=rule,
                    control_codes=rule.control_codes,
                    confidence=rule.confidence,
                    review_status=self._review_status(rule.confidence),
                )
            )

        if not matches and self._severity_value(finding.severity) in {"critical", "high"}:
            matches.append(
                MappingMatch(
                    rule=MappingRule(
                        rule_id="generic_high_severity_security_finding",
                        keywords=(),
                        control_codes=("GDPR-SEC-32", "SOC2-SEC-ACCESS"),
                        confidence=0.62,
                        source=MappingSource.heuristic,
                    ),
                    control_codes=("GDPR-SEC-32", "SOC2-SEC-ACCESS"),
                    confidence=0.62,
                    review_status=MappingReviewStatus.needs_review,
                )
            )

        return matches

    async def _upsert_matches(
        self,
        tenant_id: uuid.UUID,
        finding: SecurityFinding,
        matches: Sequence[MappingMatch],
    ) -> list[FindingControlMapping]:
        control_codes = sorted({code for match in matches for code in match.control_codes})
        controls = await self._controls_by_code(control_codes)
        mappings: list[FindingControlMapping] = []

        for match in matches:
            for control_code in match.control_codes:
                control = controls.get(control_code)
                if control is None:
                    logger.info("Compliance control missing for rule %s: %s", match.rule.rule_id, control_code)
                    continue
                mapping = await self._upsert_mapping(
                    tenant_id=tenant_id,
                    finding_id=finding.id,
                    control=control,
                    rule=match.rule,
                    confidence=match.confidence,
                    review_status=match.review_status,
                )
                mappings.append(mapping)
                await self._emit_mapping_event(mapping)
        return mappings

    async def _controls_by_code(self, control_codes: Iterable[str]) -> dict[str, ComplianceControl]:
        codes = list(control_codes)
        if not codes:
            return {}
        query = (
            select(ComplianceControl)
            .join(ComplianceFramework, ComplianceControl.framework_id == ComplianceFramework.id)
            .where(ComplianceControl.control_code.in_(codes))
        )
        controls = (await self.db.execute(query)).scalars().all()
        return {control.control_code: control for control in controls}

    async def _upsert_mapping(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        control: ComplianceControl,
        rule: MappingRule,
        confidence: float,
        review_status: MappingReviewStatus,
    ) -> FindingControlMapping:
        query = select(FindingControlMapping).where(
            FindingControlMapping.tenant_id == tenant_id,
            FindingControlMapping.finding_id == finding_id,
            FindingControlMapping.control_id == control.id,
            FindingControlMapping.rule_id == rule.rule_id,
        )
        mapping = (await self.db.execute(query)).scalars().first()
        if mapping is None:
            mapping = FindingControlMapping(
                tenant_id=tenant_id,
                finding_id=finding_id,
                control_id=control.id,
                rule_id=rule.rule_id,
            )
            self.db.add(mapping)

        if mapping.mapping_source == MappingSource.manual:
            return mapping

        mapping.confidence = self._bounded_confidence(confidence)
        mapping.mapping_source = rule.source
        mapping.review_status = review_status
        return mapping

    async def _emit_mapping_event(self, mapping: FindingControlMapping) -> None:
        event_cls = (
            FindingMappingNeedsReviewEvent
            if mapping.review_status == MappingReviewStatus.needs_review
            else FindingMappedToControlEvent
        )
        await self._publish_event(
            event_cls(
                tenant_id=str(mapping.tenant_id),
                finding_id=str(mapping.finding_id),
                control_id=str(mapping.control_id),
                rule_id=mapping.rule_id,
                confidence=mapping.confidence,
                review_status=mapping.review_status.value,
            )
        )

    async def _emit_override_event(self, mapping: FindingControlMapping) -> None:
        await self._publish_event(
            FindingMappingOverriddenEvent(
                tenant_id=str(mapping.tenant_id),
                finding_id=str(mapping.finding_id),
                control_id=str(mapping.control_id),
                rule_id=mapping.rule_id,
                confidence=mapping.confidence,
                review_status=mapping.review_status.value,
            )
        )

    async def _publish_event(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(COMPLIANCE_MAPPING_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish compliance mapping event %s: %s", event.event_type, exc)

    def _haystack(self, finding: SecurityFinding, provider: str, service: str) -> str:
        return " ".join(
            [
                provider,
                service,
                finding.resource_id or "",
                finding.title or "",
                finding.description or "",
                finding.remediation_instructions or "",
            ]
        ).lower()

    def _review_status(self, confidence: float) -> MappingReviewStatus:
        if confidence >= 0.75:
            return MappingReviewStatus.auto_approved
        return MappingReviewStatus.needs_review

    def _bounded_confidence(self, confidence: float) -> float:
        return max(0.0, min(1.0, float(confidence)))

    def _severity_value(self, severity: FindingSeverity | str) -> str:
        if isinstance(severity, FindingSeverity):
            return severity.value
        return str(severity).lower()

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
