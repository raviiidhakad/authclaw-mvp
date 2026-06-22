from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class ReportRunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    expired = "expired"


class ReportTemplate(Base, UUIDMixin):
    __tablename__ = "report_templates"
    __table_args__ = (
        Index("idx_report_templates_tenant", "tenant_id"),
        Index("idx_report_templates_type", "tenant_id", "type"),
        UniqueConstraint("tenant_id", "name", name="uq_report_templates_tenant_name"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    type: Mapped[str] = mapped_column(String(80), nullable=False)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    filters_schema: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    default_sections: Mapped[List[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
    is_system: Mapped[bool] = mapped_column(server_default=text("false"), nullable=False)

    runs = relationship("ReportRun", back_populates="template")


class ReportRun(Base, UUIDMixin):
    __tablename__ = "report_runs"
    __table_args__ = (
        Index("idx_report_runs_tenant", "tenant_id"),
        Index("idx_report_runs_status", "tenant_id", "status"),
        Index("idx_report_runs_template", "tenant_id", "template_id"),
        Index("idx_report_runs_requested_by", "tenant_id", "requested_by"),
        Index("idx_report_runs_expires", "tenant_id", "expires_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    template_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("report_templates.id", ondelete="SET NULL"), nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[ReportRunStatus] = mapped_column(
        Enum(ReportRunStatus, name="report_run_status", create_type=True),
        server_default=ReportRunStatus.queued.value,
        nullable=False,
    )
    filters: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    template = relationship("ReportTemplate", back_populates="runs")
    artifacts = relationship("ReportArtifact", back_populates="run", cascade="all, delete-orphan")


class ReportArtifact(Base, UUIDMixin):
    __tablename__ = "report_artifacts"
    __table_args__ = (
        Index("idx_report_artifacts_tenant", "tenant_id"),
        Index("idx_report_artifacts_run", "tenant_id", "run_id"),
        Index("idx_report_artifacts_type", "tenant_id", "artifact_type"),
        Index("idx_report_artifacts_expires", "tenant_id", "expires_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("report_runs.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(80), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    sanitization_version: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    run = relationship("ReportRun", back_populates="artifacts")
    manifest = relationship("ExportManifest", back_populates="artifact", uselist=False, cascade="all, delete-orphan")
    share_links = relationship("ExternalShareLink", back_populates="artifact", cascade="all, delete-orphan")
    access_logs = relationship("ReportAccessLog", back_populates="artifact", cascade="all, delete-orphan")


class ExportManifest(Base, UUIDMixin):
    __tablename__ = "export_manifests"
    __table_args__ = (
        UniqueConstraint("artifact_id", name="uq_export_manifests_artifact"),
        Index("idx_export_manifests_tenant", "tenant_id"),
        Index("idx_export_manifests_artifact", "tenant_id", "artifact_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("report_artifacts.id", ondelete="CASCADE"), nullable=False)
    manifest_json: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_algorithm: Mapped[str] = mapped_column(String(32), server_default="sha256", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    artifact = relationship("ReportArtifact", back_populates="manifest")


class ExternalShareLink(Base, UUIDMixin):
    __tablename__ = "external_share_links"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_external_share_links_token_hash"),
        Index("idx_external_share_links_tenant", "tenant_id"),
        Index("idx_external_share_links_artifact", "tenant_id", "artifact_id"),
        Index("idx_external_share_links_expires", "tenant_id", "expires_at"),
        Index("idx_external_share_links_revoked", "tenant_id", "revoked_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("report_artifacts.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    max_downloads: Mapped[int] = mapped_column(Integer, server_default=text("1"), nullable=False)

    artifact = relationship("ReportArtifact", back_populates="share_links")
    access_logs = relationship("ReportAccessLog", back_populates="external_share")


class ReportAccessLog(Base, UUIDMixin):
    __tablename__ = "report_access_logs"
    __table_args__ = (
        Index("idx_report_access_logs_tenant", "tenant_id"),
        Index("idx_report_access_logs_artifact", "tenant_id", "artifact_id"),
        Index("idx_report_access_logs_actor", "tenant_id", "actor_user_id"),
        Index("idx_report_access_logs_external_share", "tenant_id", "external_share_id"),
        Index("idx_report_access_logs_action", "tenant_id", "action"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("report_artifacts.id", ondelete="CASCADE"), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    external_share_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("external_share_links.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    artifact = relationship("ReportArtifact", back_populates="access_logs")
    external_share = relationship("ExternalShareLink", back_populates="access_logs")


class TrustNotification(Base, UUIDMixin):
    __tablename__ = "trust_notifications"
    __table_args__ = (
        Index("idx_trust_notifications_tenant", "tenant_id"),
        Index("idx_trust_notifications_recipient", "tenant_id", "recipient_user_id"),
        Index("idx_trust_notifications_type", "tenant_id", "type"),
        Index("idx_trust_notifications_read", "tenant_id", "read_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), server_default="info", nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
