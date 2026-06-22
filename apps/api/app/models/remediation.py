from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Dict

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class RemediationRiskLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RemediationPlanStatus(str, enum.Enum):
    detected = "detected"
    recommendation_created = "recommendation_created"
    plan_drafted = "plan_drafted"
    plan_validated = "plan_validated"
    approval_requested = "approval_requested"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"
    queued_for_execution = "queued_for_execution"
    executing = "executing"
    succeeded = "succeeded"
    failed = "failed"
    rollback_required = "rollback_required"
    rolled_back = "rolled_back"
    verified = "verified"


class RemediationArtifactType(str, enum.Enum):
    terraform_plan_draft = "terraform_plan_draft"
    aws_cli_command_draft = "aws_cli_command_draft"
    github_pr_patch_draft = "github_pr_patch_draft"
    iam_policy_diff = "iam_policy_diff"
    documentation_only = "documentation_only"


class RemediationArtifactStatus(str, enum.Enum):
    draft = "draft"
    active = "active"
    superseded = "superseded"
    rejected = "rejected"
    archived = "archived"


class RemediationApprovalStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"
    revoked = "revoked"
    used = "used"


class RemediationExecutionStatus(str, enum.Enum):
    disabled = "disabled"
    queued = "queued"
    dry_run_requested = "dry_run_requested"
    dry_run_succeeded = "dry_run_succeeded"
    dry_run_failed = "dry_run_failed"
    executing = "executing"
    succeeded = "succeeded"
    failed = "failed"
    rollback_required = "rollback_required"
    rolled_back = "rolled_back"


class RemediationDryRunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    rejected = "rejected"


class RemediationApprovalLevel(str, enum.Enum):
    operator = "operator"
    admin = "admin"
    owner = "owner"
    security_admin = "security_admin"


class RemediationVerificationStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    failed = "failed"
    inconclusive = "inconclusive"


class RemediationPlan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_plans"
    __table_args__ = (
        Index("idx_remediation_plans_tenant", "tenant_id"),
        Index("idx_remediation_plans_status", "tenant_id", "status"),
        Index("idx_remediation_plans_risk", "tenant_id", "risk_level"),
        Index("idx_remediation_plans_finding", "tenant_id", "finding_id"),
        Index("idx_remediation_plans_gap", "tenant_id", "gap_id"),
        Index("idx_remediation_plans_integration", "tenant_id", "integration_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("security_findings.id", ondelete="SET NULL"), nullable=True)
    gap_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("compliance_gaps.id", ondelete="SET NULL"), nullable=True)
    recommendation_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    integration_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cloud_integrations.id", ondelete="SET NULL"), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(80), nullable=True)
    resource_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    risk_level: Mapped[RemediationRiskLevel] = mapped_column(
        Enum(RemediationRiskLevel, name="remediation_risk_level", create_type=True),
        nullable=False,
        server_default=RemediationRiskLevel.medium.value,
    )
    status: Mapped[RemediationPlanStatus] = mapped_column(
        Enum(RemediationPlanStatus, name="remediation_plan_status", create_type=True),
        nullable=False,
        server_default=RemediationPlanStatus.detected.value,
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    expected_impact: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    artifacts = relationship("RemediationArtifact", back_populates="plan", cascade="all, delete-orphan")
    rollback_plan = relationship("RemediationRollbackPlan", back_populates="plan", uselist=False, cascade="all, delete-orphan")
    policy_checks = relationship("RemediationPolicyCheck", back_populates="plan", cascade="all, delete-orphan")
    approvals = relationship("RemediationApproval", back_populates="plan", cascade="all, delete-orphan")
    execution_jobs = relationship("RemediationExecutionJob", back_populates="plan", cascade="all, delete-orphan")
    dry_run_results = relationship("RemediationDryRunResult", back_populates="plan", cascade="all, delete-orphan")
    verification_results = relationship("RemediationVerificationResult", back_populates="plan", cascade="all, delete-orphan")


class RemediationArtifact(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_artifacts"
    __table_args__ = (
        UniqueConstraint("plan_id", "artifact_hash", name="uq_remediation_artifacts_plan_hash"),
        Index("idx_remediation_artifacts_tenant", "tenant_id"),
        Index("idx_remediation_artifacts_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_artifacts_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[RemediationArtifactType] = mapped_column(
        Enum(RemediationArtifactType, name="remediation_artifact_type", create_type=True),
        nullable=False,
    )
    content_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    diff_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_flags: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    status: Mapped[RemediationArtifactStatus] = mapped_column(
        Enum(RemediationArtifactStatus, name="remediation_artifact_status", create_type=True),
        nullable=False,
        server_default=RemediationArtifactStatus.draft.value,
    )

    plan = relationship("RemediationPlan", back_populates="artifacts")


class RemediationRollbackPlan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_rollback_plans"
    __table_args__ = (
        UniqueConstraint("plan_id", name="uq_remediation_rollback_plans_plan"),
        Index("idx_remediation_rollback_plans_tenant", "tenant_id"),
        Index("idx_remediation_rollback_plans_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_rollback_plans_risk", "tenant_id", "risk_level"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    rollback_steps: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_artifact_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_level: Mapped[RemediationRiskLevel] = mapped_column(
        Enum(RemediationRiskLevel, name="remediation_risk_level", create_type=False),
        nullable=False,
    )

    plan = relationship("RemediationPlan", back_populates="rollback_plan")


class RemediationPolicyCheck(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_policy_checks"
    __table_args__ = (
        UniqueConstraint("plan_id", "policy_check_hash", name="uq_remediation_policy_checks_plan_hash"),
        Index("idx_remediation_policy_checks_tenant", "tenant_id"),
        Index("idx_remediation_policy_checks_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_policy_checks_artifact", "tenant_id", "artifact_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_artifacts.id", ondelete="SET NULL"), nullable=True)
    passed: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    warnings: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    blocking_reasons: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    required_approval_level: Mapped[RemediationApprovalLevel] = mapped_column(
        Enum(RemediationApprovalLevel, name="remediation_approval_level", create_type=True),
        nullable=False,
        server_default=RemediationApprovalLevel.admin.value,
    )
    policy_check_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    plan = relationship("RemediationPlan", back_populates="policy_checks")
    artifact = relationship("RemediationArtifact")


class RemediationApproval(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_approvals"
    __table_args__ = (
        UniqueConstraint("nonce", name="uq_remediation_approvals_nonce"),
        Index("idx_remediation_approvals_tenant", "tenant_id"),
        Index("idx_remediation_approvals_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_approvals_status", "tenant_id", "status"),
        Index("idx_remediation_approvals_expires", "tenant_id", "expires_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_check_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[RemediationApprovalStatus] = mapped_column(
        Enum(RemediationApprovalStatus, name="remediation_approval_status", create_type=True),
        nullable=False,
        server_default=RemediationApprovalStatus.pending.value,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    nonce: Mapped[str] = mapped_column(String(120), nullable=False)
    approval_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    plan = relationship("RemediationPlan", back_populates="approvals")


class RemediationExecutionJob(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_execution_jobs"
    __table_args__ = (
        Index("idx_remediation_execution_jobs_tenant", "tenant_id"),
        Index("idx_remediation_execution_jobs_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_execution_jobs_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_approvals.id", ondelete="SET NULL"), nullable=True)
    sandbox_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    dry_run_result_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    status: Mapped[RemediationExecutionStatus] = mapped_column(
        Enum(RemediationExecutionStatus, name="remediation_execution_status", create_type=True),
        nullable=False,
        server_default=RemediationExecutionStatus.disabled.value,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    plan = relationship("RemediationPlan", back_populates="execution_jobs")
    approval = relationship("RemediationApproval")


class RemediationDryRunResult(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_dry_run_results"
    __table_args__ = (
        Index("idx_remediation_dry_run_results_tenant", "tenant_id"),
        Index("idx_remediation_dry_run_results_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_dry_run_results_artifact", "tenant_id", "artifact_id"),
        Index("idx_remediation_dry_run_results_job", "tenant_id", "job_id"),
        Index("idx_remediation_dry_run_results_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_execution_jobs.id", ondelete="SET NULL"), nullable=True)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_artifacts.id", ondelete="CASCADE"), nullable=False)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_approvals.id", ondelete="SET NULL"), nullable=True)
    sandbox_id: Mapped[str] = mapped_column(String(120), nullable=False)
    dry_run_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[RemediationDryRunStatus] = mapped_column(
        Enum(RemediationDryRunStatus, name="remediation_dry_run_status", create_type=True),
        nullable=False,
        server_default=RemediationDryRunStatus.queued.value,
    )
    output_summary: Mapped[str] = mapped_column(Text, nullable=False)
    warnings: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    blocking_reasons: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    plan = relationship("RemediationPlan", back_populates="dry_run_results")
    artifact = relationship("RemediationArtifact")
    approval = relationship("RemediationApproval")
    job = relationship("RemediationExecutionJob")


class RemediationVerificationResult(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_verification_results"
    __table_args__ = (
        Index("idx_remediation_verification_results_tenant", "tenant_id"),
        Index("idx_remediation_verification_results_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_verification_results_verified", "tenant_id", "verified"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_execution_jobs.id", ondelete="SET NULL"), nullable=True)
    finding_status_before: Mapped[str | None] = mapped_column(String(80), nullable=True)
    finding_status_after: Mapped[str | None] = mapped_column(String(80), nullable=True)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    verification_summary: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[RemediationVerificationStatus] = mapped_column(
        Enum(RemediationVerificationStatus, name="remediation_verification_status", create_type=True),
        nullable=False,
        server_default=RemediationVerificationStatus.pending.value,
    )

    plan = relationship("RemediationPlan", back_populates="verification_results")
    job = relationship("RemediationExecutionJob")
    evidence = relationship("EvidenceItem")


class RemediationAuditLink(Base, UUIDMixin):
    __tablename__ = "remediation_audit_links"
    __table_args__ = (
        Index("idx_remediation_audit_links_tenant", "tenant_id"),
        Index("idx_remediation_audit_links_plan", "tenant_id", "plan_id"),
        Index("idx_remediation_audit_links_approval", "tenant_id", "approval_id"),
        Index("idx_remediation_audit_links_job", "tenant_id", "job_id"),
        Index("idx_remediation_audit_links_event", "tenant_id", "audit_event_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=True)
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_artifacts.id", ondelete="CASCADE"), nullable=True)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_approvals.id", ondelete="CASCADE"), nullable=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediation_execution_jobs.id", ondelete="CASCADE"), nullable=True)
    audit_event_id: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
