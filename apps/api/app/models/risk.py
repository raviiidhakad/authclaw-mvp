from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class AdversarialProbeCategory(str, enum.Enum):
    prompt_injection = "prompt_injection"
    data_disclosure = "data_disclosure"
    credential_leakage = "credential_leakage"
    harmful_content = "harmful_content"
    sycophancy_policy_bypass = "sycophancy_policy_bypass"
    policy_bypass = "policy_bypass"
    report_export_leakage = "report_export_leakage"


class AdversarialProbeStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    blocked = "blocked"


class VulnerabilitySeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class VulnerabilityStatus(str, enum.Enum):
    open = "open"
    triaged = "triaged"
    remediating = "remediating"
    accepted_risk = "accepted_risk"
    resolved = "resolved"
    false_positive = "false_positive"


class GoNoGoVerdict(str, enum.Enum):
    go = "go"
    needs_review = "needs_review"
    no_go = "no_go"


class AdversarialProbeRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "adversarial_probe_runs"
    __table_args__ = (
        Index("idx_adversarial_probe_runs_tenant", "tenant_id"),
        Index("idx_adversarial_probe_runs_category", "tenant_id", "category"),
        Index("idx_adversarial_probe_runs_status", "tenant_id", "status"),
        Index("idx_adversarial_probe_runs_owner", "tenant_id", "owner_user_id"),
        Index("idx_adversarial_probe_runs_completed", "tenant_id", "completed_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    category: Mapped[AdversarialProbeCategory] = mapped_column(
        Enum(AdversarialProbeCategory, name="adversarial_probe_category", create_type=True),
        nullable=False,
    )
    status: Mapped[AdversarialProbeStatus] = mapped_column(
        Enum(AdversarialProbeStatus, name="adversarial_probe_status", create_type=True),
        nullable=False,
        server_default=AdversarialProbeStatus.queued.value,
    )
    target_surface: Mapped[str] = mapped_column(String(120), nullable=False, server_default="gateway")
    model_target: Mapped[str | None] = mapped_column(String(160), nullable=True)
    execution_mode: Mapped[str] = mapped_column(String(40), nullable=False, server_default="simulated")
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    safe_prompt_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_summary: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    probes_total: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    blocked_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    allowed_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    raw_payload_stored: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    vulnerabilities = relationship("VulnerabilityRegisterItem", back_populates="probe_run")
    results = relationship("RedTeamProbeResult", back_populates="probe_run", cascade="all, delete-orphan")


class RedTeamProbeResult(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "red_team_probe_results"
    __table_args__ = (
        Index("idx_red_team_probe_results_tenant", "tenant_id"),
        Index("idx_red_team_probe_results_run", "tenant_id", "probe_run_id"),
        Index("idx_red_team_probe_results_category", "tenant_id", "category"),
        Index("idx_red_team_probe_results_surface", "tenant_id", "target_surface"),
        Index("idx_red_team_probe_results_status", "tenant_id", "status"),
        Index("idx_red_team_probe_results_severity", "tenant_id", "severity"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    probe_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("adversarial_probe_runs.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[AdversarialProbeCategory] = mapped_column(
        Enum(AdversarialProbeCategory, name="adversarial_probe_category", create_type=False),
        nullable=False,
    )
    target_surface: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, server_default="blocked")
    severity: Mapped[VulnerabilitySeverity] = mapped_column(
        Enum(VulnerabilitySeverity, name="vulnerability_severity", create_type=False),
        nullable=False,
        server_default=VulnerabilitySeverity.low.value,
    )
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("80"))
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_input_summary: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_output_summary: Mapped[str] = mapped_column(Text, nullable=False)
    linked_finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    linked_remediation_plan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("remediation_plans.id", ondelete="SET NULL"),
        nullable=True,
    )
    linked_control_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    linked_report_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    raw_payload_stored: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    probe_run = relationship("AdversarialProbeRun", back_populates="results")
    remediation_plan = relationship("RemediationPlan")


class VulnerabilityRegisterItem(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "vulnerability_register_items"
    __table_args__ = (
        Index("idx_vulnerability_register_tenant", "tenant_id"),
        Index("idx_vulnerability_register_probe", "tenant_id", "probe_run_id"),
        Index("idx_vulnerability_register_category", "tenant_id", "category"),
        Index("idx_vulnerability_register_severity", "tenant_id", "severity"),
        Index("idx_vulnerability_register_status", "tenant_id", "status"),
        Index("idx_vulnerability_register_owner", "tenant_id", "owner_user_id"),
        Index("idx_vulnerability_register_remediation", "tenant_id", "remediation_plan_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    probe_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("adversarial_probe_runs.id", ondelete="SET NULL"), nullable=True)
    remediation_plan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_plans.id", ondelete="SET NULL"), nullable=True)
    category: Mapped[AdversarialProbeCategory] = mapped_column(
        Enum(AdversarialProbeCategory, name="adversarial_probe_category", create_type=False),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[VulnerabilitySeverity] = mapped_column(
        Enum(VulnerabilitySeverity, name="vulnerability_severity", create_type=True),
        nullable=False,
        server_default=VulnerabilitySeverity.medium.value,
    )
    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus, name="vulnerability_status", create_type=True),
        nullable=False,
        server_default=VulnerabilityStatus.open.value,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("80"))
    due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    linked_finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    linked_control_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    linked_report_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"))

    probe_run = relationship("AdversarialProbeRun", back_populates="vulnerabilities")
    remediation_plan = relationship("RemediationPlan")


class RiskPostureSnapshot(Base, UUIDMixin):
    __tablename__ = "risk_posture_snapshots"
    __table_args__ = (
        Index("idx_risk_posture_snapshots_tenant", "tenant_id"),
        Index("idx_risk_posture_snapshots_verdict", "tenant_id", "verdict"),
        Index("idx_risk_posture_snapshots_generated", "tenant_id", "generated_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    verdict: Mapped[GoNoGoVerdict] = mapped_column(
        Enum(GoNoGoVerdict, name="go_no_go_verdict", create_type=True),
        nullable=False,
        server_default=GoNoGoVerdict.needs_review.value,
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    blockers: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    recommendations: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"))


RedTeamProbeRun = AdversarialProbeRun
GoNoGoPostureSnapshot = RiskPostureSnapshot
