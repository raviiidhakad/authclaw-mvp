"""
AuthClaw Sprint 2 — SecurityFinding Model
------------------------------------------
Stores the structured inventory of all cloud security findings retrieved
by the ConnectorWorker from AWS, GitHub, and GCP.

Design principles:
  • Raw JSON payloads are NOT stored here. They go to ClickHouse keyed by
    `id` (see app/services/finding_raw_store.py). This keeps the Postgres
    table lean and index-efficient.
  • Deduplication uses a composite SHA-256 hash of
    (integration_id + external_id + resource_id). On re-scan:
      - Hash match → update `updated_at`; if RESOLVED, transition to ACTIVE
      - No match   → insert as NEW
      - Orphan     → any ACTIVE finding with `updated_at` before scan start
                      transitions to RESOLVED (fixed outside AuthClaw)
  • Tenant isolation is guaranteed by the FK chain:
      finding.integration_id → integration.tenant_id
    All queries enforce `integration.tenant_id = :current_tenant`.

Finding lifecycle:
  NEW         → just imported, not yet triaged
  ACTIVE      → confirmed present in latest scan
  REMEDIATING → a LangGraph AgentState is currently processing this finding
  RESOLVED    → absent from the latest scan (auto) or marked fixed via API
  SUPPRESSED  → muted by tenant policy; excluded from agent context
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin, TimestampMixin


class FindingSeverity(str, enum.Enum):
    """Normalized severity regardless of source provider's scale."""
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class FindingStatus(str, enum.Enum):
    """Lifecycle states of a SecurityFinding."""
    new          = "new"
    active       = "active"
    remediating  = "remediating"
    resolved     = "resolved"
    suppressed   = "suppressed"


# Severity → numeric priority for ContextBuilder ordering (higher = more urgent)
SEVERITY_PRIORITY: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
}


class SecurityFinding(Base, UUIDMixin, TimestampMixin):
    """
    One row per unique cloud security finding per integration.

    The `dedup_hash` column is the primary deduplication key. It is computed
    by the ConnectorWorker before upsert and is unique per integration:
        SHA256(integration_id + ":" + external_id + ":" + resource_id)

    Tenant isolation:
      - Access is always through `integration_id → CloudIntegration.tenant_id`.
      - Direct queries without a tenant_id join are disallowed in all services.
    """
    __tablename__ = "security_findings"
    __table_args__ = (
        # Primary lookup: all findings for an integration
        Index("idx_security_findings_integration_id", "integration_id"),
        # Dashboard / agent queries: tenant findings by severity + status
        Index("idx_security_findings_status_severity", "status", "severity"),
        # Deduplication enforcement
        Index(
            "uq_security_findings_dedup_hash",
            "dedup_hash",
            unique=True,
        ),
    )

    integration_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_integrations.id", ondelete="CASCADE"),
        nullable=False,
        comment="Parent integration. Provides tenant_id chain for isolation.",
    )

    # ── Deduplication ──────────────────────────────────────────────────────────
    dedup_hash: Mapped[str] = mapped_column(
        String(64),   # SHA-256 hex digest = 64 chars
        nullable=False,
        comment=(
            "SHA-256 hex digest of (integration_id + external_id + resource_id). "
            "Used for upsert deduplication. Enforced UNIQUE at DB level."
        ),
    )

    # ── Provider identity ──────────────────────────────────────────────────────
    external_id: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        comment="Provider-native finding ID (e.g. Security Hub ARN, GitHub alert number).",
    )

    resource_id: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        comment="Affected resource (e.g. S3 bucket ARN, GitHub repo full_name, GCP project ID).",
    )

    # ── Content ────────────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        comment="Short human-readable description of the finding.",
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Detailed description. May be truncated for very long provider descriptions.",
    )

    remediation_instructions: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Raw remediation guidance from the provider, if available.",
    )

    # ── Classification ─────────────────────────────────────────────────────────
    severity: Mapped[FindingSeverity] = mapped_column(
        SAEnum(FindingSeverity, name="finding_severity", create_type=True),
        nullable=False,
        index=True,
        comment="Normalized severity level mapped from the provider's scale.",
    )

    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, name="finding_status", create_type=True),
        nullable=False,
        server_default="new",
        index=True,
        comment="Lifecycle state of this finding.",
    )

    # ── Timestamps ─────────────────────────────────────────────────────────────
    # created_at and updated_at from TimestampMixin
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True,
        comment="UTC timestamp when the finding transitioned to RESOLVED.",
    )

    # Relationships
    integration = relationship(
        "CloudIntegration",
        back_populates="findings",
    )

    def to_agent_context_string(self) -> str:
        """
        Produce a concise one-line summary for injection into LangGraph AgentState.
        Keeps context window consumption minimal.

        Format: [{SEVERITY}] {title} — Resource: {resource_id}
        """
        return (
            f"[{self.severity.upper()}] {self.title} "
            f"— Resource: {self.resource_id}"
        )
