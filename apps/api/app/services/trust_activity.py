from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import desc, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.models.compliance import EvidenceItem
from app.models.integration import CloudIntegration
from app.models.remediation import (
    RemediationApproval,
    RemediationExecutionJob,
    RemediationPlan,
    RemediationVerificationResult,
)
from app.models.trust import ReportAccessLog, ReportRun, TrustNotification
from app.schemas.events import NotificationCreatedEvent
from app.services.trust_reporting import (
    TRUST_EVENTS_TOPIC,
    ExportSanitizer,
    sanitized_event_payload,
)


@dataclass(frozen=True)
class ActivityTimelineItem:
    id: str
    tenant_id: uuid.UUID
    occurred_at: datetime
    source: str
    action: str
    severity: str
    actor_user_id: uuid.UUID | None
    resource_type: str
    resource_id: uuid.UUID | None
    title: str
    summary: str
    metadata: dict[str, Any]


class TrustNotificationService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        sanitizer: ExportSanitizer | None = None,
        event_producer=default_event_producer,
    ) -> None:
        self.db = db
        self.sanitizer = sanitizer or ExportSanitizer()
        self.event_producer = event_producer

    async def create_notification(
        self,
        *,
        tenant_id: uuid.UUID,
        recipient_user_id: uuid.UUID | None,
        type: str,
        severity: str,
        title: str,
        body: str,
        resource_type: str | None = None,
        resource_id: uuid.UUID | None = None,
    ) -> TrustNotification:
        await self._set_tenant_context(tenant_id)
        payload = self.sanitizer.sanitize_payload(
            {
                "type": type,
                "severity": severity,
                "title": title,
                "body": body,
                "resource_type": resource_type,
                "resource_id": resource_id,
            }
        )
        payload.pop("sanitization_version", None)
        row = TrustNotification(
            tenant_id=tenant_id,
            recipient_user_id=recipient_user_id,
            type=str(payload["type"])[:80],
            severity=str(payload["severity"])[:40],
            title=str(payload["title"])[:200],
            body=str(payload["body"]),
            resource_type=payload.get("resource_type"),
            resource_id=_coerce_uuid(payload.get("resource_id")),
        )
        self.db.add(row)
        await self.db.flush()
        if self.event_producer is not None:
            await self.event_producer.publish(
                TRUST_EVENTS_TOPIC,
                NotificationCreatedEvent(
                    tenant_id=tenant_id,
                    actor_id=recipient_user_id,
                    notification_id=row.id,
                    payload=sanitized_event_payload(
                        {
                            "notification_id": row.id,
                            "type": row.type,
                            "severity": row.severity,
                            "resource_type": row.resource_type,
                            "resource_id": row.resource_id,
                        }
                    ),
                ),
            )
        return row

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


class TrustActivityTimelineService:
    def __init__(self, db: AsyncSession, *, sanitizer: ExportSanitizer | None = None) -> None:
        self.db = db
        self.sanitizer = sanitizer or ExportSanitizer()

    async def list_timeline(
        self,
        tenant_id: uuid.UUID,
        *,
        source: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: uuid.UUID | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[ActivityTimelineItem], int]:
        await self._set_tenant_context(tenant_id)
        items: list[ActivityTimelineItem] = []
        items.extend(await self._report_runs(tenant_id))
        items.extend(await self._report_access(tenant_id))
        items.extend(await self._remediation_approvals(tenant_id))
        items.extend(await self._remediation_plans(tenant_id))
        items.extend(await self._remediation_jobs(tenant_id))
        items.extend(await self._remediation_verifications(tenant_id))
        items.extend(await self._evidence_updates(tenant_id))
        items.extend(await self._integration_health(tenant_id))

        if source:
            items = [item for item in items if item.source == source]
        if action:
            items = [item for item in items if item.action == action]
        if resource_type:
            items = [item for item in items if item.resource_type == resource_type]
        if resource_id:
            items = [item for item in items if item.resource_id == resource_id]
        if date_from:
            items = [item for item in items if item.occurred_at >= _normalize_datetime(date_from)]
        if date_to:
            items = [item for item in items if item.occurred_at <= _normalize_datetime(date_to)]

        items.sort(key=lambda item: (item.occurred_at, item.id), reverse=True)
        return items[skip : skip + limit], len(items)

    async def notification_rows(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        *,
        unread_only: bool = False,
        type: str | None = None,
        severity: str | None = None,
        resource_type: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[TrustNotification], int, int]:
        await self._set_tenant_context(tenant_id)
        base = select(TrustNotification).where(
            TrustNotification.tenant_id == tenant_id,
            or_(TrustNotification.recipient_user_id == user_id, TrustNotification.recipient_user_id.is_(None)),
        )
        if unread_only:
            base = base.where(TrustNotification.read_at.is_(None))
        if type:
            base = base.where(TrustNotification.type == type)
        if severity:
            base = base.where(TrustNotification.severity == severity)
        if resource_type:
            base = base.where(TrustNotification.resource_type == resource_type)
        rows = (await self.db.execute(base.order_by(desc(TrustNotification.created_at), desc(TrustNotification.id)))).scalars().all()
        unread = sum(1 for row in rows if row.read_at is None)
        return rows[skip : skip + limit], len(rows), unread

    async def notification_or_none(self, tenant_id: uuid.UUID, user_id: uuid.UUID, notification_id: uuid.UUID) -> TrustNotification | None:
        await self._set_tenant_context(tenant_id)
        return (
            await self.db.execute(
                select(TrustNotification).where(
                    TrustNotification.tenant_id == tenant_id,
                    TrustNotification.id == notification_id,
                    or_(TrustNotification.recipient_user_id == user_id, TrustNotification.recipient_user_id.is_(None)),
                )
            )
        ).scalars().first()

    async def mark_notification_read(self, row: TrustNotification) -> TrustNotification:
        if row.read_at is None:
            row.read_at = datetime.now(timezone.utc).replace(tzinfo=None)
            await self.db.flush()
        return row

    async def mark_all_read(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
        await self._set_tenant_context(tenant_id)
        rows = (
            await self.db.execute(
                select(TrustNotification).where(
                    TrustNotification.tenant_id == tenant_id,
                    TrustNotification.read_at.is_(None),
                    or_(TrustNotification.recipient_user_id == user_id, TrustNotification.recipient_user_id.is_(None)),
                )
            )
        ).scalars().all()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        count = 0
        for row in rows:
            if row.read_at is None:
                row.read_at = now
                count += 1
        await self.db.flush()
        return count

    async def _report_runs(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(ReportRun).where(ReportRun.tenant_id == tenant_id).order_by(desc(ReportRun.completed_at), desc(ReportRun.started_at)).limit(100)
            )
        ).scalars().all()
        items = []
        for row in rows:
            occurred_at = row.completed_at or row.started_at
            if occurred_at is None:
                continue
            status = _enum_value(row.status)
            items.append(
                self._item(
                    tenant_id=tenant_id,
                    occurred_at=occurred_at,
                    source="report",
                    action=f"report_run_{status}",
                    severity="error" if status == "failed" else "info",
                    actor_user_id=row.requested_by,
                    resource_type="report_run",
                    resource_id=row.id,
                    title=f"Report run {status}",
                    summary="Sanitized report run metadata updated.",
                    metadata={"status": status, "report_type": (row.filters or {}).get("report_type"), "failed_reason": row.failed_reason},
                )
            )
        return items

    async def _report_access(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(ReportAccessLog)
                .where(ReportAccessLog.tenant_id == tenant_id)
                .order_by(desc(ReportAccessLog.created_at))
                .limit(100)
            )
        ).scalars().all()
        return [
            self._item(
                tenant_id=tenant_id,
                occurred_at=row.created_at,
                source="report",
                action=row.action,
                severity="info",
                actor_user_id=row.actor_user_id,
                resource_type="report_artifact",
                resource_id=row.artifact_id,
                title=f"Report artifact {row.action}",
                summary="Metadata-only report access event.",
                metadata={
                    "external_share_id": row.external_share_id,
                    "ip_hash": row.ip_hash,
                    "user_agent_hash": row.user_agent_hash,
                },
            )
            for row in rows
        ]

    async def _remediation_approvals(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(RemediationApproval)
                .where(RemediationApproval.tenant_id == tenant_id)
                .order_by(desc(RemediationApproval.resolved_at), desc(RemediationApproval.created_at))
                .limit(100)
            )
        ).scalars().all()
        items = []
        for row in rows:
            status = _enum_value(row.status)
            items.append(
                self._item(
                    tenant_id=tenant_id,
                    occurred_at=row.resolved_at or row.created_at,
                    source="remediation",
                    action=f"approval_{status}",
                    severity="warning" if status in {"pending", "rejected", "expired", "revoked"} else "info",
                    actor_user_id=row.approved_by or row.requested_by,
                    resource_type="remediation_approval",
                    resource_id=row.id,
                    title=f"Remediation approval {status}",
                    summary="Human approval state changed for a remediation plan.",
                    metadata={"plan_id": row.plan_id, "status": status, "mfa_verified": row.mfa_verified},
                )
            )
        return items

    async def _remediation_plans(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(RemediationPlan).where(RemediationPlan.tenant_id == tenant_id).order_by(desc(RemediationPlan.updated_at)).limit(100)
            )
        ).scalars().all()
        return [
            self._item(
                tenant_id=tenant_id,
                occurred_at=row.updated_at or row.created_at,
                source="remediation",
                action=f"plan_{_enum_value(row.status)}",
                severity=_severity_from_risk(_enum_value(row.risk_level)),
                actor_user_id=row.created_by,
                resource_type="remediation_plan",
                resource_id=row.id,
                title=f"Remediation plan {_enum_value(row.status)}",
                summary=row.summary,
                metadata={
                    "risk_level": _enum_value(row.risk_level),
                    "status": _enum_value(row.status),
                    "provider": row.provider,
                    "finding_id": row.finding_id,
                    "gap_id": row.gap_id,
                },
            )
            for row in rows
        ]

    async def _remediation_jobs(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(RemediationExecutionJob)
                .where(RemediationExecutionJob.tenant_id == tenant_id)
                .order_by(desc(RemediationExecutionJob.completed_at), desc(RemediationExecutionJob.started_at), desc(RemediationExecutionJob.created_at))
                .limit(100)
            )
        ).scalars().all()
        return [
            self._item(
                tenant_id=tenant_id,
                occurred_at=row.completed_at or row.started_at or row.created_at,
                source="remediation",
                action=f"execution_{_enum_value(row.status)}",
                severity="warning" if _enum_value(row.status) in {"failed", "rollback_required"} else "info",
                actor_user_id=None,
                resource_type="remediation_job",
                resource_id=row.id,
                title=f"Remediation execution {_enum_value(row.status)}",
                summary="Controlled remediation execution record updated.",
                metadata={"plan_id": row.plan_id, "approval_id": row.approval_id, "status": _enum_value(row.status), "disabled_reason": row.disabled_reason},
            )
            for row in rows
        ]

    async def _remediation_verifications(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(RemediationVerificationResult)
                .where(RemediationVerificationResult.tenant_id == tenant_id)
                .order_by(desc(RemediationVerificationResult.updated_at))
                .limit(100)
            )
        ).scalars().all()
        return [
            self._item(
                tenant_id=tenant_id,
                occurred_at=row.updated_at or row.created_at,
                source="remediation",
                action=f"verification_{_enum_value(row.status)}",
                severity="info" if row.verified else "warning",
                actor_user_id=None,
                resource_type="remediation_verification",
                resource_id=row.id,
                title=f"Remediation verification {_enum_value(row.status)}",
                summary=row.verification_summary,
                metadata={"plan_id": row.plan_id, "job_id": row.job_id, "verified": row.verified, "evidence_id": row.evidence_id},
            )
            for row in rows
        ]

    async def _evidence_updates(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(EvidenceItem).where(EvidenceItem.tenant_id == tenant_id).order_by(desc(EvidenceItem.updated_at)).limit(100)
            )
        ).scalars().all()
        return [
            self._item(
                tenant_id=tenant_id,
                occurred_at=row.updated_at or row.created_at,
                source="evidence",
                action=f"evidence_{_enum_value(row.status)}",
                severity="warning" if _enum_value(row.status) in {"stale", "expired"} else "info",
                actor_user_id=None,
                resource_type="evidence_item",
                resource_id=row.id,
                title=f"Evidence {_enum_value(row.status)}",
                summary=row.safe_summary,
                metadata={
                    "control_id": row.control_id,
                    "finding_id": row.finding_id,
                    "integration_id": row.integration_id,
                    "source_type": _enum_value(row.source_type),
                    "proof_hash": row.proof_hash,
                    "freshness_expires_at": row.freshness_expires_at,
                },
            )
            for row in rows
        ]

    async def _integration_health(self, tenant_id: uuid.UUID) -> list[ActivityTimelineItem]:
        rows = (
            await self.db.execute(
                select(CloudIntegration).where(CloudIntegration.tenant_id == tenant_id).order_by(desc(CloudIntegration.updated_at)).limit(100)
            )
        ).scalars().all()
        return [
            self._item(
                tenant_id=tenant_id,
                occurred_at=row.updated_at or row.created_at,
                source="integration",
                action=f"integration_{_enum_value(row.status)}",
                severity="warning" if _enum_value(row.status) == "error" else "info",
                actor_user_id=None,
                resource_type="cloud_integration",
                resource_id=row.id,
                title=f"Integration {_enum_value(row.status)}",
                summary=f"{_enum_value(row.provider_type)} integration health updated.",
                metadata={
                    "provider_type": _enum_value(row.provider_type),
                    "display_name": row.display_name,
                    "status": _enum_value(row.status),
                    "last_sync_at": row.last_sync_at,
                    "last_sync_finding_count": row.last_sync_finding_count,
                    "has_error": bool(row.error_message),
                },
            )
            for row in rows
        ]

    def _item(
        self,
        *,
        tenant_id: uuid.UUID,
        occurred_at: datetime,
        source: str,
        action: str,
        severity: str,
        actor_user_id: uuid.UUID | None,
        resource_type: str,
        resource_id: uuid.UUID | None,
        title: str,
        summary: str,
        metadata: Mapping[str, Any],
    ) -> ActivityTimelineItem:
        payload = self.sanitizer.sanitize_payload(
            {
                "title": title,
                "summary": summary,
                "metadata": metadata,
            }
        )
        payload.pop("sanitization_version", None)
        occurred_at = _normalize_datetime(occurred_at)
        return ActivityTimelineItem(
            id=f"{source}:{resource_type}:{resource_id or action}:{occurred_at.isoformat()}",
            tenant_id=tenant_id,
            occurred_at=occurred_at,
            source=source,
            action=action,
            severity=severity,
            actor_user_id=actor_user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            title=str(payload["title"]),
            summary=str(payload["summary"]),
            metadata=dict(payload.get("metadata") or {}),
        )

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _severity_from_risk(risk: str | None) -> str:
    if risk in {"critical", "high"}:
        return "warning"
    return "info"


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    if value is None or isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))
