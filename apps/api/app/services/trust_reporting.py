from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events.producer import producer as default_event_producer
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceGap,
    ControlAssessmentResult,
    EvidenceItem,
)
from app.models.finding import SecurityFinding
from app.models.integration import CloudIntegration
from app.models.remediation import (
    RemediationApproval,
    RemediationDryRunResult,
    RemediationExecutionJob,
    RemediationPlan,
    RemediationVerificationResult,
)
from app.models.trust import ExportManifest, ReportArtifact, ReportRun, ReportRunStatus, ReportTemplate
from app.schemas.events import (
    EvidencePackageCreatedEvent,
    ReportRunCompletedEvent,
    ReportRunFailedEvent,
    ReportRunStartedEvent,
)


TRUST_REPORTING_RESOURCE = "trust_reporting"
TRUST_EVENTS_TOPIC = "authclaw.trust.events"
SANITIZATION_VERSION = "sprint5-phase2-v1"
REDACTION_MARKER = "[redacted]"
LEGAL_REVIEW_MARKER = "evidence-supported posture; needs review"

VIEW_TRUST_DASHBOARD = "view_trust_dashboard"
GENERATE_REPORT = "generate_report"
DOWNLOAD_REPORT = "download_report"
CREATE_SHARE_LINK = "create_share_link"
REVOKE_SHARE_LINK = "revoke_share_link"
VIEW_REPORT_ACCESS_LOGS = "view_report_access_logs"
EXPIRE_REPORT_ARTIFACT = "expire_report_artifact"
MANAGE_REPORT_TEMPLATES = "manage_report_templates"

SPRINT5_PERMISSION_ACTIONS = {
    VIEW_TRUST_DASHBOARD,
    GENERATE_REPORT,
    DOWNLOAD_REPORT,
    CREATE_SHARE_LINK,
    REVOKE_SHARE_LINK,
    VIEW_REPORT_ACCESS_LOGS,
    EXPIRE_REPORT_ARTIFACT,
    MANAGE_REPORT_TEMPLATES,
}

ROLE_PERMISSION_MAP: dict[str, set[str]] = {
    "viewer": {VIEW_TRUST_DASHBOARD},
    "member": {VIEW_TRUST_DASHBOARD},
    "analyst": {VIEW_TRUST_DASHBOARD},
    "auditor": {
        VIEW_TRUST_DASHBOARD,
        GENERATE_REPORT,
        DOWNLOAD_REPORT,
        VIEW_REPORT_ACCESS_LOGS,
    },
    "admin": {
        VIEW_TRUST_DASHBOARD,
        GENERATE_REPORT,
        DOWNLOAD_REPORT,
        VIEW_REPORT_ACCESS_LOGS,
        MANAGE_REPORT_TEMPLATES,
    },
    "owner": {
        VIEW_TRUST_DASHBOARD,
        GENERATE_REPORT,
        DOWNLOAD_REPORT,
        CREATE_SHARE_LINK,
        REVOKE_SHARE_LINK,
        VIEW_REPORT_ACCESS_LOGS,
        EXPIRE_REPORT_ARTIFACT,
        MANAGE_REPORT_TEMPLATES,
    },
}

EXPORT_SENSITIVE_FIELD_DENYLIST = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "artifact_content",
        "authorization",
        "aws_access_key_id",
        "aws_secret_access_key",
        "client_secret",
        "content_redacted",
        "credential",
        "credentials",
        "ip",
        "ip_address",
        "private_key",
        "provider_payload",
        "raw_artifact",
        "raw_content",
        "raw_payload",
        "raw_provider_payload",
        "refresh_token",
        "secret",
        "secret_access_key",
        "token",
        "user_agent",
        "vault_ref",
        "vault_reference",
        "vault_reference_id",
    }
)

_SENSITIVE_SUBSTRINGS = (
    "authorization",
    "credential",
    "header",
    "private_key",
    "raw_payload",
    "raw_provider_payload",
    "secret",
    "token",
    "vault",
)

_HASH_FIELD_ALLOWLIST = {
    "content_hash",
    "hash_algorithm",
    "ip_hash",
    "manifest_hash",
    "token_hash",
    "user_agent_hash",
}

_SECRET_VALUE_PATTERNS = (
    re.compile(r"\braw[_\s-]?provider[_\s-]?payload\b", re.I),
    re.compile(r"\braw[_\s-]?artifact\b", re.I),
    re.compile(r"\braw[_\s-]?payload\b", re.I),
    re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    re.compile(r"AIza[0-9A-Za-z_-]{35}", re.I),
    re.compile(r"gh[pousr]_[0-9A-Za-z_]{20,}", re.I),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}", re.I),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |)?PRIVATE KEY-----.*?-----END (?:RSA |OPENSSH |EC |DSA |)?PRIVATE KEY-----", re.I | re.S),
    re.compile(r"\bBearer\s+[0-9A-Za-z._~+/-]+=*", re.I),
    re.compile(r"\bBasic\s+[0-9A-Za-z+/]+=*", re.I),
    re.compile(r"\bvault://[^\s\"']+", re.I),
    re.compile(r"\bsecret/authclaw/[^\s\"']+", re.I),
)

_LEGAL_OVERCLAIM_PATTERNS = (
    re.compile(r"\blegally\s+compliant\b", re.I),
    re.compile(r"\bfully\s+compliant\b", re.I),
    re.compile(r"\bcompliant\b", re.I),
    re.compile(r"\bcertified\b", re.I),
    re.compile(r"\bguaranteed?\b", re.I),
    re.compile(r"\baudit[-\s]?ready\b", re.I),
    re.compile(r"\bpass(?:es|ed)?\s+audit\b", re.I),
)


@dataclass(frozen=True)
class StoredArtifact:
    storage_key: str
    content_hash: str
    size_bytes: int


@dataclass(frozen=True)
class ReportGenerationRequest:
    report_type: str = "trust_overview"
    template_id: uuid.UUID | None = None
    requested_by: uuid.UUID | None = None
    filters: Mapping[str, Any] = field(default_factory=dict)
    retention_days: int = 90


@dataclass(frozen=True)
class EvidencePackageRequest:
    framework_id: uuid.UUID | None = None
    control_ids: list[uuid.UUID] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    evidence_freshness_days: int | None = None
    include_findings: bool = True
    include_remediation: bool = True
    output_format: Literal["json"] = "json"
    template_id: uuid.UUID | None = None
    requested_by: uuid.UUID | None = None
    retention_days: int = 90


@dataclass(frozen=True)
class GenerationResult:
    report_run: ReportRun
    artifact: ReportArtifact | None
    manifest: ExportManifest | None
    payload: dict[str, Any] | None = None


def has_permission(role_names: set[str], action: str) -> bool:
    if action not in SPRINT5_PERMISSION_ACTIONS:
        return False
    return any(action in ROLE_PERMISSION_MAP.get(role, set()) for role in role_names)


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def build_manifest_hash(manifest_json: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest_json).encode("utf-8")).hexdigest()


def hash_share_token(raw_token: str) -> str:
    if not raw_token:
        raise ValueError("share token must not be empty")
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def hash_access_metadata(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def expiry_from_retention(days: int = 90, *, now: datetime | None = None) -> datetime:
    if days <= 0:
        raise ValueError("retention days must be positive")
    base = now or datetime.now(timezone.utc)
    return base + timedelta(days=days)


def sanitize_export_metadata(value: Any) -> Any:
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, nested in value.items():
            normalized = str(key).lower()
            if _is_sensitive_key(normalized):
                continue
            else:
                sanitized[str(key)] = sanitize_export_metadata(nested)
        return sanitized
    if isinstance(value, list):
        return [sanitize_export_metadata(item) for item in value]
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return sanitize_export_text(value)
    return value


def sanitize_export_text(value: str) -> str:
    sanitized = value
    for pattern in _SECRET_VALUE_PATTERNS:
        sanitized = pattern.sub(REDACTION_MARKER, sanitized)
    for pattern in _LEGAL_OVERCLAIM_PATTERNS:
        sanitized = pattern.sub(LEGAL_REVIEW_MARKER, sanitized)
    return sanitized


def validate_artifact_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = sanitize_export_metadata(metadata)
    serialized = canonical_json(sanitized)
    unsafe_tokens = ("AKIA", "-----BEGIN", "ghp_", "xoxb-", "raw_provider_payload")
    if any(token.lower() in serialized.lower() for token in unsafe_tokens):
        raise ValueError("artifact metadata contains unsafe export content")
    return sanitized


def immutable_manifest_update_guard(existing_hash: str, proposed_manifest: Mapping[str, Any]) -> None:
    if existing_hash != build_manifest_hash(proposed_manifest):
        raise ValueError("export manifests are immutable after creation")


def sanitized_event_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return validate_artifact_metadata(payload)


class ExportSanitizer:
    sanitization_version = SANITIZATION_VERSION

    def sanitize(self, value: Any) -> Any:
        return sanitize_export_metadata(value)

    def sanitize_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        sanitized = validate_artifact_metadata(payload)
        sanitized["sanitization_version"] = self.sanitization_version
        return sanitized

    def sanitize_failure_reason(self, reason: str) -> str:
        return sanitize_export_text(reason)[:1000]


class LocalReportArtifactStore:
    """Internal JSON artifact store with a future S3-compatible boundary."""

    def __init__(self, base_dir: Path | str | None = None) -> None:
        self.base_dir = Path(base_dir or Path("tmp") / "trust-report-artifacts")

    async def write_json(self, *, tenant_id: uuid.UUID, run_id: uuid.UUID, payload: Mapping[str, Any]) -> StoredArtifact:
        serialized = canonical_json(payload).encode("utf-8")
        content_hash = hashlib.sha256(serialized).hexdigest()
        relative_key = Path(str(tenant_id)) / f"{run_id}.json"
        path = self.base_dir / relative_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(serialized)
        return StoredArtifact(
            storage_key=relative_key.as_posix(),
            content_hash=content_hash,
            size_bytes=len(serialized),
        )

    def read_json(self, storage_key: str) -> dict[str, Any]:
        with (self.base_dir / storage_key).open("r", encoding="utf-8") as handle:
            return json.load(handle)


class ReportGenerationService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        artifact_store: LocalReportArtifactStore | None = None,
        event_producer=default_event_producer,
        sanitizer: ExportSanitizer | None = None,
    ) -> None:
        self.db = db
        self.artifact_store = artifact_store or LocalReportArtifactStore()
        self.event_producer = event_producer
        self.sanitizer = sanitizer or ExportSanitizer()

    async def generate_report(self, tenant_id: uuid.UUID | str, request: ReportGenerationRequest) -> GenerationResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        filters = self.sanitizer.sanitize_payload(
            {
                "report_type": request.report_type,
                "filters": dict(request.filters),
                "template_id": str(request.template_id) if request.template_id else None,
                "output_format": "json",
            }
        )
        filter_hash = build_manifest_hash(filters)
        existing = await self._running_duplicate(tenant_uuid, request.template_id, filter_hash)
        if existing is not None:
            return GenerationResult(report_run=existing, artifact=None, manifest=None, payload=None)

        run = ReportRun(
            tenant_id=tenant_uuid,
            template_id=request.template_id,
            requested_by=request.requested_by,
            status=ReportRunStatus.queued,
            filters={**filters, "filter_hash": filter_hash},
            expires_at=expiry_from_retention(request.retention_days).replace(tzinfo=None),
        )
        self.db.add(run)
        await self.db.flush()
        try:
            run.status = ReportRunStatus.running
            run.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
            await self.db.flush()
            await self._emit(
                ReportRunStartedEvent(
                    tenant_id=tenant_uuid,
                    actor_id=request.requested_by,
                    report_run_id=run.id,
                    payload=sanitized_event_payload({"report_type": request.report_type, "filter_hash": filter_hash}),
                )
            )

            payload = await self.build_report_payload(tenant_uuid, request.report_type, dict(request.filters))
            artifact, manifest = await self._persist_artifact_and_manifest(
                tenant_uuid=tenant_uuid,
                run=run,
                artifact_type="json",
                payload=payload,
            )
            run.status = ReportRunStatus.completed
            run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            await self.db.flush()
            await self._emit(
                ReportRunCompletedEvent(
                    tenant_id=tenant_uuid,
                    actor_id=request.requested_by,
                    report_run_id=run.id,
                    artifact_id=artifact.id,
                    payload=sanitized_event_payload(
                        {
                            "report_type": request.report_type,
                            "artifact_type": artifact.artifact_type,
                            "content_hash": artifact.content_hash,
                            "manifest_hash": manifest.manifest_hash,
                        }
                    ),
                )
            )
            return GenerationResult(report_run=run, artifact=artifact, manifest=manifest, payload=payload)
        except Exception as exc:
            run.status = ReportRunStatus.failed
            run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            run.failed_reason = self.sanitizer.sanitize_failure_reason(str(exc))
            await self.db.flush()
            await self._emit(
                ReportRunFailedEvent(
                    tenant_id=tenant_uuid,
                    actor_id=request.requested_by,
                    report_run_id=run.id,
                    reason_category="generation_failed",
                    payload=sanitized_event_payload({"failed_reason": run.failed_reason}),
                )
            )
            return GenerationResult(report_run=run, artifact=None, manifest=None, payload=None)

    async def build_report_payload(
        self,
        tenant_id: uuid.UUID,
        report_type: str = "trust_overview",
        filters: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        filters = filters or {}
        payload = {
            "metadata": {
                "report_type": report_type,
                "tenant_id": str(tenant_id),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "language": "Evidence-supported posture summary. This is not legal advice and does not certify compliance.",
                "filters": filters,
            },
            "compliance_assessments": await self._compliance_assessments(tenant_id),
            "control_results": await self._control_results(tenant_id),
            "evidence_summaries": await self._evidence_summaries(tenant_id, filters=filters),
            "gaps": await self._gaps(tenant_id),
            "findings": await self._finding_summaries(tenant_id),
            "remediation": await self._remediation_summaries(tenant_id),
            "integration_health": await self._integration_health(tenant_id),
        }
        return self.sanitizer.sanitize_payload(payload)

    async def _persist_artifact_and_manifest(
        self,
        *,
        tenant_uuid: uuid.UUID,
        run: ReportRun,
        artifact_type: str,
        payload: Mapping[str, Any],
    ) -> tuple[ReportArtifact, ExportManifest]:
        stored = await self.artifact_store.write_json(tenant_id=tenant_uuid, run_id=run.id, payload=payload)
        artifact = ReportArtifact(
            tenant_id=tenant_uuid,
            run_id=run.id,
            artifact_type=artifact_type,
            storage_key=stored.storage_key,
            content_hash=stored.content_hash,
            size_bytes=stored.size_bytes,
            sanitization_version=self.sanitizer.sanitization_version,
            expires_at=run.expires_at,
        )
        self.db.add(artifact)
        await self.db.flush()
        manifest_json = {
            "artifact_id": str(artifact.id),
            "report_run_id": str(run.id),
            "artifact_type": artifact.artifact_type,
            "content_hash": artifact.content_hash,
            "size_bytes": artifact.size_bytes,
            "sanitization_version": artifact.sanitization_version,
            "storage_key_hash": hashlib.sha256(artifact.storage_key.encode("utf-8")).hexdigest(),
        }
        manifest_json = self.sanitizer.sanitize_payload(manifest_json)
        manifest = ExportManifest(
            tenant_id=tenant_uuid,
            artifact_id=artifact.id,
            manifest_json=manifest_json,
            manifest_hash=build_manifest_hash(manifest_json),
        )
        self.db.add(manifest)
        await self.db.flush()
        return artifact, manifest

    async def _compliance_assessments(self, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
        rows = (
            await self.db.execute(
                select(ComplianceAssessment)
                .options(selectinload(ComplianceAssessment.framework))
                .where(ComplianceAssessment.tenant_id == tenant_id)
                .order_by(desc(ComplianceAssessment.started_at))
                .limit(20)
            )
        ).scalars().all()
        return [
            {
                "id": item.id,
                "framework_id": item.framework_id,
                "framework": item.framework.name if item.framework else None,
                "status": _enum_value(item.status),
                "score": item.score,
                "score_band": _enum_value(item.score_band),
                "started_at": item.started_at,
                "completed_at": item.completed_at,
                "explanation": item.explanation,
            }
            for item in rows
        ]

    async def _control_results(self, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
        rows = (
            await self.db.execute(
                select(ControlAssessmentResult)
                .options(selectinload(ControlAssessmentResult.control))
                .where(ControlAssessmentResult.tenant_id == tenant_id)
                .order_by(desc(ControlAssessmentResult.created_at))
                .limit(50)
            )
        ).scalars().all()
        return [
            {
                "id": item.id,
                "assessment_id": item.assessment_id,
                "control_id": item.control_id,
                "control_code": item.control.control_code if item.control else None,
                "control_title": item.control.title if item.control else None,
                "score": item.score,
                "score_band": _enum_value(item.score_band),
                "evidence_count": item.evidence_count,
                "gap_count": item.gap_count,
                "explanation": item.explanation,
            }
            for item in rows
        ]

    async def _evidence_summaries(self, tenant_id: uuid.UUID, *, filters: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        stmt = select(EvidenceItem).options(selectinload(EvidenceItem.control)).where(EvidenceItem.tenant_id == tenant_id)
        if filters.get("framework_id"):
            stmt = stmt.join(ComplianceControl, ComplianceControl.id == EvidenceItem.control_id).where(
                ComplianceControl.framework_id == self._uuid(filters["framework_id"])
            )
        if filters.get("control_ids"):
            stmt = stmt.where(EvidenceItem.control_id.in_([self._uuid(item) for item in filters["control_ids"]]))
        if filters.get("date_from"):
            stmt = stmt.where(EvidenceItem.created_at >= filters["date_from"])
        if filters.get("date_to"):
            stmt = stmt.where(EvidenceItem.created_at <= filters["date_to"])
        rows = (await self.db.execute(stmt.order_by(desc(EvidenceItem.created_at)).limit(100))).scalars().all()
        return [
            {
                "id": item.id,
                "control_id": item.control_id,
                "control_code": item.control.control_code if item.control else None,
                "source_type": _enum_value(item.source_type),
                "status": _enum_value(item.status),
                "safe_summary": item.safe_summary,
                "proof_hash": item.proof_hash,
                "freshness_expires_at": item.freshness_expires_at,
                "finding_id": item.finding_id,
                "integration_id": item.integration_id,
            }
            for item in rows
        ]

    async def _gaps(self, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
        rows = (
            await self.db.execute(
                select(ComplianceGap).where(ComplianceGap.tenant_id == tenant_id).order_by(desc(ComplianceGap.created_at)).limit(50)
            )
        ).scalars().all()
        return [
            {
                "id": item.id,
                "assessment_id": item.assessment_id,
                "control_id": item.control_id,
                "gap_type": _enum_value(item.gap_type),
                "severity": _enum_value(item.severity),
                "reason": item.reason,
                "evidence_status": item.evidence_status,
                "finding_id": item.finding_id,
            }
            for item in rows
        ]

    async def _finding_summaries(self, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
        rows = (
            await self.db.execute(
                select(SecurityFinding)
                .join(CloudIntegration, CloudIntegration.id == SecurityFinding.integration_id)
                .where(CloudIntegration.tenant_id == tenant_id)
                .order_by(desc(SecurityFinding.updated_at))
                .limit(100)
            )
        ).scalars().all()
        return [
            {
                "id": item.id,
                "integration_id": item.integration_id,
                "title": item.title,
                "resource_id": item.resource_id,
                "severity": _enum_value(item.severity),
                "status": _enum_value(item.status),
                "created_at": item.created_at,
                "updated_at": item.updated_at,
                "resolved_at": item.resolved_at,
            }
            for item in rows
        ]

    async def _remediation_summaries(self, tenant_id: uuid.UUID) -> dict[str, list[dict[str, Any]]]:
        plans = (
            await self.db.execute(
                select(RemediationPlan).where(RemediationPlan.tenant_id == tenant_id).order_by(desc(RemediationPlan.updated_at)).limit(50)
            )
        ).scalars().all()
        approvals = (
            await self.db.execute(
                select(RemediationApproval)
                .where(RemediationApproval.tenant_id == tenant_id)
                .order_by(desc(RemediationApproval.created_at))
                .limit(50)
            )
        ).scalars().all()
        dry_runs = (
            await self.db.execute(
                select(RemediationDryRunResult)
                .where(RemediationDryRunResult.tenant_id == tenant_id)
                .order_by(desc(RemediationDryRunResult.created_at))
                .limit(50)
            )
        ).scalars().all()
        jobs = (
            await self.db.execute(
                select(RemediationExecutionJob)
                .where(RemediationExecutionJob.tenant_id == tenant_id)
                .order_by(desc(RemediationExecutionJob.created_at))
                .limit(50)
            )
        ).scalars().all()
        verifications = (
            await self.db.execute(
                select(RemediationVerificationResult)
                .where(RemediationVerificationResult.tenant_id == tenant_id)
                .order_by(desc(RemediationVerificationResult.created_at))
                .limit(50)
            )
        ).scalars().all()
        return {
            "plans": [
                {
                    "id": item.id,
                    "finding_id": item.finding_id,
                    "gap_id": item.gap_id,
                    "provider": item.provider,
                    "risk_level": _enum_value(item.risk_level),
                    "status": _enum_value(item.status),
                    "summary": item.summary,
                    "expected_impact": item.expected_impact,
                }
                for item in plans
            ],
            "approvals": [
                {
                    "id": item.id,
                    "plan_id": item.plan_id,
                    "status": _enum_value(item.status),
                    "requested_by": item.requested_by,
                    "approved_by": item.approved_by,
                    "expires_at": item.expires_at,
                    "resolved_at": item.resolved_at,
                    "mfa_verified": item.mfa_verified,
                }
                for item in approvals
            ],
            "dry_runs": [
                {
                    "id": item.id,
                    "plan_id": item.plan_id,
                    "status": _enum_value(item.status),
                    "dry_run_type": item.dry_run_type,
                    "output_summary": item.output_summary,
                    "warning_count": len(item.warnings or []),
                    "blocking_reason_count": len(item.blocking_reasons or []),
                }
                for item in dry_runs
            ],
            "execution_jobs": [
                {
                    "id": item.id,
                    "plan_id": item.plan_id,
                    "status": _enum_value(item.status),
                    "started_at": item.started_at,
                    "completed_at": item.completed_at,
                    "disabled_reason": item.disabled_reason,
                }
                for item in jobs
            ],
            "verification_results": [
                {
                    "id": item.id,
                    "plan_id": item.plan_id,
                    "job_id": item.job_id,
                    "verified": item.verified,
                    "status": _enum_value(item.status),
                    "verification_summary": item.verification_summary,
                }
                for item in verifications
            ],
        }

    async def _integration_health(self, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
        rows = (
            await self.db.execute(
                select(CloudIntegration)
                .where(CloudIntegration.tenant_id == tenant_id)
                .order_by(desc(CloudIntegration.updated_at))
                .limit(50)
            )
        ).scalars().all()
        return [
            {
                "id": item.id,
                "provider_type": _enum_value(item.provider_type),
                "target_identifier": item.target_identifier,
                "display_name": item.display_name,
                "status": _enum_value(item.status),
                "last_sync_at": item.last_sync_at,
                "last_sync_finding_count": item.last_sync_finding_count,
                "has_error": bool(item.error_message),
            }
            for item in rows
        ]

    async def _running_duplicate(
        self,
        tenant_id: uuid.UUID,
        template_id: uuid.UUID | None,
        filter_hash: str,
    ) -> ReportRun | None:
        rows = (
            await self.db.execute(
                select(ReportRun).where(
                    ReportRun.tenant_id == tenant_id,
                    ReportRun.status == ReportRunStatus.running,
                    ReportRun.template_id.is_(None) if template_id is None else ReportRun.template_id == template_id,
                )
            )
        ).scalars().all()
        for row in rows:
            if (row.filters or {}).get("filter_hash") == filter_hash:
                return row
        return None

    async def _emit(self, event: Any) -> None:
        if self.event_producer is not None:
            await self.event_producer.publish(TRUST_EVENTS_TOPIC, event)

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class EvidencePackageBuilder(ReportGenerationService):
    async def create_evidence_package(
        self,
        tenant_id: uuid.UUID | str,
        request: EvidencePackageRequest,
    ) -> GenerationResult:
        if request.output_format != "json":
            raise ValueError("Sprint 5 Phase 2 supports JSON evidence packages only")
        filters = {
            "framework_id": str(request.framework_id) if request.framework_id else None,
            "control_ids": [str(item) for item in request.control_ids] if request.control_ids else None,
            "date_from": request.date_from,
            "date_to": request.date_to,
            "evidence_freshness_days": request.evidence_freshness_days,
            "include_findings": request.include_findings,
            "include_remediation": request.include_remediation,
        }
        report_request = ReportGenerationRequest(
            report_type="evidence_package",
            template_id=request.template_id,
            requested_by=request.requested_by,
            filters=filters,
            retention_days=request.retention_days,
        )
        result = await self.generate_report(tenant_id, report_request)
        if result.artifact is not None and result.manifest is not None:
            await self._emit(
                EvidencePackageCreatedEvent(
                    tenant_id=self._uuid(tenant_id),
                    actor_id=request.requested_by,
                    report_run_id=result.report_run.id,
                    artifact_id=result.artifact.id,
                    manifest_hash=result.manifest.manifest_hash,
                    payload=sanitized_event_payload(
                        {
                            "artifact_type": result.artifact.artifact_type,
                            "content_hash": result.artifact.content_hash,
                            "manifest_hash": result.manifest.manifest_hash,
                        }
                    ),
                )
            )
        return result

    async def build_report_payload(
        self,
        tenant_id: uuid.UUID,
        report_type: str = "evidence_package",
        filters: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        filters = filters or {}
        evidence = await self._evidence_summaries(tenant_id, filters=filters)
        finding_ids = {item.get("finding_id") for item in evidence if item.get("finding_id")}
        findings = await self._finding_summaries(tenant_id) if filters.get("include_findings", True) else []
        if finding_ids:
            findings = [item for item in findings if str(item["id"]) in {str(finding_id) for finding_id in finding_ids}]
        remediation = await self._remediation_summaries(tenant_id) if filters.get("include_remediation", True) else {}
        payload = {
            "metadata": {
                "report_type": "evidence_package",
                "tenant_id": str(tenant_id),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "language": "Evidence-supported package for review. This is not legal advice and does not certify compliance.",
                "filters": filters,
            },
            "evidence_summaries": evidence,
            "linked_findings": findings,
            "remediation_status": remediation,
            "verification_summaries": (remediation or {}).get("verification_results", []),
        }
        return self.sanitizer.sanitize_payload(payload)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _is_sensitive_key(key: str) -> bool:
    if key in _HASH_FIELD_ALLOWLIST:
        return False
    if key in EXPORT_SENSITIVE_FIELD_DENYLIST:
        return True
    return any(fragment in key for fragment in _SENSITIVE_SUBSTRINGS)
