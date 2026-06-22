"""
Safe SecurityFinding context builder for the LangGraph agent.

This service is the only Phase 8 path from persisted connector findings into
AgentState. It reads normalized PostgreSQL rows, keeps tenant scoping explicit,
and emits concise strings so the existing AgentState contract remains
``findings: List[str]``.
"""
from __future__ import annotations

import inspect
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from time import perf_counter
from typing import Sequence

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider
from app.schemas.events import AgentContextBuiltEvent

logger = logging.getLogger(__name__)

AGENT_EVENTS_TOPIC = "authclaw.agent.events"


SEVERITY_ORDER = {
    FindingSeverity.critical: 4,
    FindingSeverity.high: 3,
    FindingSeverity.medium: 2,
    FindingSeverity.low: 1,
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.I | re.S),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:xox[baprs]-)[A-Za-z0-9-]{10,}\b"),
    re.compile(
        r"\b(?:aws_secret_access_key|aws_session_token|github_token|private_key|"
        r"client_secret|access_token|refresh_token|id_token|vault_reference_id)\s*"
        r"[:=]\s*['\"]?[^'\"\s,;]+",
        re.I,
    ),
    re.compile(
        r"\b(?:aws_secret_access_key|aws_session_token|github_token|private_key|"
        r"client_secret|access_token|refresh_token|id_token|vault_reference_id|"
        r"raw_finding_data|raw_payload|raw_provider_payload)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:password|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*"
        r"['\"]?[^'\"\s,;]+",
        re.I,
    ),
]


@dataclass(frozen=True)
class FindingContextRow:
    finding: SecurityFinding
    provider_type: CloudProvider
    integration_id: uuid.UUID


class FindingsContextBuilder:
    def __init__(self, db: AsyncSession, event_producer=None) -> None:
        self.db = db
        self.event_producer = event_producer

    async def build_for_tenant(
        self,
        tenant_id: uuid.UUID | str,
        limit: int | None = None,
    ) -> list[str]:
        started = perf_counter()
        tenant_uuid = self._uuid(tenant_id)
        rows = await self._fetch_active_findings(tenant_uuid)
        return await self._finalize_context(tenant_uuid, rows, limit, started)

    async def build_for_integration(
        self,
        tenant_id: uuid.UUID | str,
        integration_id: uuid.UUID | str,
        limit: int | None = None,
    ) -> list[str]:
        started = perf_counter()
        tenant_uuid = self._uuid(tenant_id)
        rows = await self._fetch_active_findings(
            tenant_uuid,
            integration_id=self._uuid(integration_id),
        )
        return await self._finalize_context(tenant_uuid, rows, limit, started)

    async def build_for_provider(
        self,
        tenant_id: uuid.UUID | str,
        provider_type: CloudProvider | str,
        limit: int | None = None,
    ) -> list[str]:
        started = perf_counter()
        tenant_uuid = self._uuid(tenant_id)
        provider = self._provider(provider_type)
        rows = await self._fetch_active_findings(
            tenant_uuid,
            provider_type=provider,
        )
        return await self._finalize_context(tenant_uuid, rows, limit, started)

    async def _fetch_active_findings(
        self,
        tenant_id: uuid.UUID,
        integration_id: uuid.UUID | None = None,
        provider_type: CloudProvider | None = None,
    ) -> list[FindingContextRow]:
        query = (
            select(SecurityFinding, CloudIntegration.provider_type, CloudIntegration.id)
            .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
            .where(
                CloudIntegration.tenant_id == tenant_id,
                SecurityFinding.status == FindingStatus.active,
            )
        )
        if integration_id is not None:
            query = query.where(CloudIntegration.id == integration_id)
        if provider_type is not None:
            query = query.where(CloudIntegration.provider_type == provider_type)

        query = query.order_by(
            desc(SecurityFinding.updated_at),
            desc(SecurityFinding.created_at),
        )
        result = await self.db.execute(query)
        return [
            FindingContextRow(
                finding=finding,
                provider_type=provider,
                integration_id=row_integration_id,
            )
            for finding, provider, row_integration_id in result.all()
        ]

    async def _finalize_context(
        self,
        tenant_id: uuid.UUID,
        rows: Sequence[FindingContextRow],
        limit: int | None,
        started: float,
    ) -> list[str]:
        capped_limit = self._limit(limit)
        selected = self._prioritize(rows)[:capped_limit]
        context = [self._format_row(row) for row in selected]
        await self._emit_context_built(tenant_id, selected, started)
        return context

    def _prioritize(self, rows: Sequence[FindingContextRow]) -> list[FindingContextRow]:
        return sorted(
            rows,
            key=lambda row: (
                SEVERITY_ORDER.get(self._severity_value(row.finding.severity), 0),
                self._sort_timestamp(row.finding.updated_at),
                self._sort_timestamp(row.finding.created_at),
            ),
            reverse=True,
        )

    def _format_row(self, row: FindingContextRow) -> str:
        finding = row.finding
        provider = row.provider_type.value
        service = self._infer_service(provider, finding.resource_id, finding.title)
        description = self._clean_text(finding.description or "")
        remediation = self._clean_text(finding.remediation_instructions or "")
        title = self._clean_text(finding.title)
        resource_id = self._clean_text(finding.resource_id)
        dedup_ref = self._clean_text(finding.dedup_hash[:16])

        parts = [
            f"[{self._severity_value(finding.severity).upper()}]",
            f"provider={provider}",
            f"service={service}",
            f"resource_id={resource_id}",
            f"title={title}",
        ]
        if description:
            parts.append(f"description={description}")
        if remediation:
            parts.append(f"remediation={remediation}")
        parts.append(f"finding_ref={dedup_ref}")
        return " | ".join(parts)

    def _clean_text(self, value: object, max_length: int = 360) -> str:
        text = " ".join(str(value).replace("\x00", " ").split())
        for pattern in SECRET_PATTERNS:
            text = pattern.sub("[redacted]", text)
        if len(text) > max_length:
            text = text[: max_length - 3].rstrip() + "..."
        return text

    def _infer_service(self, provider: str, resource_id: str, title: str) -> str:
        haystack = f"{resource_id} {title}".lower()
        if provider == "aws":
            for service in ("s3", "iam", "kms", "cloudtrail", "securityhub", "ec2"):
                if service in haystack:
                    return service
            arn_parts = resource_id.split(":")
            if len(arn_parts) > 2 and arn_parts[0] == "arn" and arn_parts[2]:
                return self._clean_text(arn_parts[2], max_length=40)
        if provider == "github":
            if "secret" in haystack:
                return "secret_scanning"
            if "branch" in haystack or "protection" in haystack:
                return "branch_protection"
            return "code_security"
        if provider == "gcp":
            if "storage" in haystack or "bucket" in haystack:
                return "cloud_storage"
            if "iam" in haystack:
                return "iam"
            return "security_command_center"
        return "unknown"

    async def _emit_context_built(
        self,
        tenant_id: uuid.UUID,
        rows: Sequence[FindingContextRow],
        started: float,
    ) -> None:
        provider_types = sorted({row.provider_type.value for row in rows})
        integration_ids = sorted({str(row.integration_id) for row in rows})
        event = AgentContextBuiltEvent(
            tenant_id=str(tenant_id),
            finding_count=len(rows),
            max_severity=self._max_severity(rows),
            provider_types=provider_types,
            integration_ids=integration_ids,
            duration_ms=int((perf_counter() - started) * 1000),
        )
        if self.event_producer is None:
            logger.info("Agent finding context built: %s", event.model_dump(mode="json"))
            return
        try:
            result = self.event_producer.publish(AGENT_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to emit AgentContextBuiltEvent: %s", exc)

    def _max_severity(self, rows: Sequence[FindingContextRow]) -> str | None:
        if not rows:
            return None
        return self._severity_value(max(
            (row.finding.severity for row in rows),
            key=lambda severity: SEVERITY_ORDER.get(self._severity_value(severity), 0),
        ))

    def _limit(self, limit: int | None) -> int:
        configured = int(settings.MAX_AGENT_CONTEXT_FINDINGS)
        if limit is None:
            return configured
        return max(0, min(int(limit), configured))

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

    def _provider(self, provider_type: CloudProvider | str) -> CloudProvider:
        if isinstance(provider_type, CloudProvider):
            return provider_type
        return CloudProvider(str(provider_type).lower())

    def _severity_value(self, severity: FindingSeverity | str) -> str:
        if isinstance(severity, FindingSeverity):
            return severity.value
        return str(severity).lower()

    def _sort_timestamp(self, value: datetime | None) -> float:
        if value is None:
            return 0.0
        return value.timestamp()
