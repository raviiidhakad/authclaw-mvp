import enum
import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Enum,
    String,
    Text,
    UniqueConstraint,
    text,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Any, Dict

from app.models.base import Base, UUIDMixin, TimestampMixin

class ComplianceFrameworkKey(str, enum.Enum):
    gdpr = "gdpr"
    hipaa = "hipaa"
    soc2 = "soc2"
    iso27001 = "iso27001"
    iso42001 = "iso42001"
    eu_ai_act = "eu_ai_act"


class MappingSource(str, enum.Enum):
    deterministic = "deterministic"
    heuristic = "heuristic"
    manual = "manual"
    imported = "imported"


class MappingReviewStatus(str, enum.Enum):
    auto_approved = "auto_approved"
    needs_review = "needs_review"
    approved = "approved"
    rejected = "rejected"
    overridden = "overridden"


class EvidenceSourceType(str, enum.Enum):
    finding_mapping = "finding_mapping"
    audit_log = "audit_log"
    manual = "manual"
    system = "system"


class EvidenceStatus(str, enum.Enum):
    active = "active"
    resolved = "resolved"
    suppressed = "suppressed"
    stale = "stale"
    expired = "expired"


class ComplianceAssessmentStatus(str, enum.Enum):
    running = "running"
    completed = "completed"
    failed = "failed"


class ComplianceScoreBand(str, enum.Enum):
    strong = "strong"
    mostly_supported = "mostly_supported"
    at_risk = "at_risk"
    high_risk = "high_risk"


class ComplianceGapType(str, enum.Enum):
    missing_evidence = "missing_evidence"
    stale_evidence = "stale_evidence"
    unresolved_finding = "unresolved_finding"
    low_confidence_mapping = "low_confidence_mapping"
    needs_review = "needs_review"
    critical_open_risk = "critical_open_risk"


class ComplianceGapSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class KnowledgeDocumentStatus(str, enum.Enum):
    active = "active"
    archived = "archived"


class ComplianceFramework(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_frameworks"
    __table_args__ = (
        UniqueConstraint("key", "version", name="uq_compliance_frameworks_key_version"),
        Index("idx_compliance_frameworks_key", "key"),
        Index("idx_compliance_frameworks_status", "status"),
    )

    key: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    license_note: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), server_default="active", nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    controls = relationship(
        "ComplianceControl",
        back_populates="framework",
        cascade="all, delete-orphan",
    )


class ComplianceControl(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "control_code", name="uq_compliance_controls_framework_code"),
        Index("idx_compliance_controls_framework", "framework_id"),
        Index("idx_compliance_controls_domain", "framework_id", "domain"),
        Index("idx_compliance_controls_requires_review", "framework_id", "requires_review"),
    )

    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_code: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True)
    severity_weight: Mapped[int] = mapped_column(Integer, server_default="1", nullable=False)
    requires_review: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    framework = relationship("ComplianceFramework", back_populates="controls")
    requirements = relationship(
        "ControlRequirement",
        back_populates="control",
        cascade="all, delete-orphan",
        order_by="ControlRequirement.sort_order",
    )


class ControlRequirement(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "control_requirements"
    __table_args__ = (
        UniqueConstraint("control_id", "requirement_key", name="uq_control_requirements_control_key"),
        Index("idx_control_requirements_control", "control_id"),
    )

    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    requirement_key: Mapped[str] = mapped_column(String(100), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_expectation: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)

    control = relationship("ComplianceControl", back_populates="requirements")


class FrameworkSeedVersion(Base, UUIDMixin):
    __tablename__ = "framework_seed_versions"
    __table_args__ = (
        UniqueConstraint("seed_key", name="uq_framework_seed_versions_seed_key"),
        Index("idx_framework_seed_versions_applied", "applied_at"),
    )

    seed_key: Mapped[str] = mapped_column(String(255), nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    framework_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    control_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    requirement_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )
    applied_at: Mapped[datetime] = mapped_column(
        server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        nullable=False,
    )


class FindingControlMapping(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "finding_control_mappings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "finding_id",
            "control_id",
            "rule_id",
            name="uq_finding_control_mappings_rule",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_finding_control_mappings_confidence_bounds",
        ),
        Index("idx_finding_control_mappings_tenant", "tenant_id"),
        Index("idx_finding_control_mappings_finding", "finding_id"),
        Index("idx_finding_control_mappings_control", "control_id"),
        Index("idx_finding_control_mappings_tenant_control", "tenant_id", "control_id"),
        Index("idx_finding_control_mappings_tenant_finding", "tenant_id", "finding_id"),
        Index("idx_finding_control_mappings_review", "review_status"),
        Index("idx_finding_control_mappings_confidence", "confidence"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(120), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    mapping_source: Mapped[MappingSource] = mapped_column(
        Enum(MappingSource, name="mapping_source", create_type=True),
        nullable=False,
        server_default=MappingSource.deterministic.value,
    )
    review_status: Mapped[MappingReviewStatus] = mapped_column(
        Enum(MappingReviewStatus, name="mapping_review_status", create_type=True),
        nullable=False,
        server_default=MappingReviewStatus.needs_review.value,
    )
    override_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding = relationship("SecurityFinding")
    control = relationship("ComplianceControl")


class EvidenceItem(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "evidence_items"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "control_id",
            "finding_id",
            "mapping_id",
            "source_type",
            name="uq_evidence_items_mapping_source",
        ),
        Index("idx_evidence_items_tenant", "tenant_id"),
        Index("idx_evidence_items_tenant_control", "tenant_id", "control_id"),
        Index("idx_evidence_items_tenant_status", "tenant_id", "status"),
        Index("idx_evidence_items_tenant_finding", "tenant_id", "finding_id"),
        Index("idx_evidence_items_tenant_mapping", "tenant_id", "mapping_id"),
        Index("idx_evidence_items_freshness", "tenant_id", "freshness_expires_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_integrations.id", ondelete="SET NULL"),
        nullable=True,
    )
    audit_log_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("audit_logs.id", ondelete="SET NULL"),
        nullable=True,
    )
    mapping_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding_control_mappings.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_type: Mapped[EvidenceSourceType] = mapped_column(
        Enum(EvidenceSourceType, name="evidence_source_type", create_type=True),
        nullable=False,
    )
    status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus, name="evidence_status", create_type=True),
        nullable=False,
        server_default=EvidenceStatus.active.value,
    )
    safe_summary: Mapped[str] = mapped_column(Text, nullable=False)
    proof_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    freshness_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    control = relationship("ComplianceControl")
    finding = relationship("SecurityFinding")
    mapping = relationship("FindingControlMapping")


class ComplianceAssessment(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_assessments"
    __table_args__ = (
        CheckConstraint("score >= 0.0 AND score <= 100.0", name="ck_compliance_assessments_score_bounds"),
        Index("idx_compliance_assessments_tenant", "tenant_id"),
        Index("idx_compliance_assessments_tenant_framework", "tenant_id", "framework_id"),
        Index("idx_compliance_assessments_tenant_status", "tenant_id", "status"),
        Index("idx_compliance_assessments_started", "tenant_id", "started_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[ComplianceAssessmentStatus] = mapped_column(
        Enum(ComplianceAssessmentStatus, name="compliance_assessment_status", create_type=True),
        nullable=False,
        server_default=ComplianceAssessmentStatus.running.value,
    )
    score: Mapped[float] = mapped_column(Float, server_default="0", nullable=False)
    score_band: Mapped[ComplianceScoreBand] = mapped_column(
        Enum(ComplianceScoreBand, name="compliance_score_band", create_type=True),
        nullable=False,
        server_default=ComplianceScoreBand.high_risk.value,
    )
    started_at: Mapped[datetime] = mapped_column(
        server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    inputs_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    framework = relationship("ComplianceFramework")
    control_results = relationship(
        "ControlAssessmentResult",
        back_populates="assessment",
        cascade="all, delete-orphan",
    )
    gaps = relationship(
        "ComplianceGap",
        back_populates="assessment",
        cascade="all, delete-orphan",
    )


class ControlAssessmentResult(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "control_assessment_results"
    __table_args__ = (
        UniqueConstraint("assessment_id", "control_id", name="uq_control_assessment_results_assessment_control"),
        CheckConstraint("score >= 0.0 AND score <= 100.0", name="ck_control_assessment_results_score_bounds"),
        Index("idx_control_results_tenant", "tenant_id"),
        Index("idx_control_results_assessment", "assessment_id"),
        Index("idx_control_results_control", "tenant_id", "control_id"),
        Index("idx_control_results_band", "tenant_id", "score_band"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_assessments.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    score_band: Mapped[ComplianceScoreBand] = mapped_column(
        Enum(ComplianceScoreBand, name="compliance_score_band", create_type=False),
        nullable=False,
    )
    evidence_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    gap_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    assessment = relationship("ComplianceAssessment", back_populates="control_results")
    control = relationship("ComplianceControl")


class ComplianceGap(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_gaps"
    __table_args__ = (
        Index("idx_compliance_gaps_tenant", "tenant_id"),
        Index("idx_compliance_gaps_assessment", "tenant_id", "assessment_id"),
        Index("idx_compliance_gaps_control", "tenant_id", "control_id"),
        Index("idx_compliance_gaps_type", "tenant_id", "gap_type"),
        Index("idx_compliance_gaps_severity", "tenant_id", "severity"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_assessments.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True,
    )
    mapping_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding_control_mappings.id", ondelete="SET NULL"),
        nullable=True,
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    gap_type: Mapped[ComplianceGapType] = mapped_column(
        Enum(ComplianceGapType, name="compliance_gap_type", create_type=True),
        nullable=False,
    )
    severity: Mapped[ComplianceGapSeverity] = mapped_column(
        Enum(ComplianceGapSeverity, name="compliance_gap_severity", create_type=True),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(50), nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    assessment = relationship("ComplianceAssessment", back_populates="gaps")
    control = relationship("ComplianceControl")
    evidence = relationship("EvidenceItem")
    mapping = relationship("FindingControlMapping")
    finding = relationship("SecurityFinding")


class KnowledgeDocument(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "knowledge_documents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "checksum", name="uq_knowledge_documents_tenant_checksum"),
        Index("idx_knowledge_documents_tenant", "tenant_id"),
        Index("idx_knowledge_documents_framework", "framework_id"),
        Index("idx_knowledge_documents_status", "status"),
        Index("idx_knowledge_documents_source", "source_type"),
    )

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
    )
    framework_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=True,
    )
    source_type: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    license_status: Mapped[str] = mapped_column(String(120), nullable=False)
    trust_level: Mapped[str] = mapped_column(String(80), nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[KnowledgeDocumentStatus] = mapped_column(
        Enum(KnowledgeDocumentStatus, name="knowledge_document_status", create_type=True),
        nullable=False,
        server_default=KnowledgeDocumentStatus.active.value,
    )
    ingested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    framework = relationship("ComplianceFramework")
    chunks = relationship(
        "KnowledgeChunk",
        back_populates="document",
        cascade="all, delete-orphan",
        order_by="KnowledgeChunk.chunk_index",
    )


class KnowledgeChunk(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "chunk_index", name="uq_knowledge_chunks_document_index"),
        Index("idx_knowledge_chunks_document", "document_id"),
        Index("idx_knowledge_chunks_tenant", "tenant_id"),
        Index("idx_knowledge_chunks_framework", "framework_id"),
        Index("idx_knowledge_chunks_control", "control_id"),
    )

    document_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=True,
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
    )
    control_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=True,
    )
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    embedding: Mapped[Dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )
    source_locator: Mapped[str | None] = mapped_column(String(512), nullable=True)

    document = relationship("KnowledgeDocument", back_populates="chunks")
    framework = relationship("ComplianceFramework")
    control = relationship("ComplianceControl")


class RetrievalTrace(Base, UUIDMixin):
    __tablename__ = "retrieval_traces"
    __table_args__ = (
        Index("idx_retrieval_traces_tenant", "tenant_id"),
        Index("idx_retrieval_traces_framework", "tenant_id", "framework_id"),
        Index("idx_retrieval_traces_created", "tenant_id", "created_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    session_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    query_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    framework_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="SET NULL"),
        nullable=True,
    )
    filters: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    chunk_ids: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    scores: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    answer_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        nullable=False,
    )

    framework = relationship("ComplianceFramework")


class AgentComplianceSession(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "agent_compliance_sessions"
    __table_args__ = (
        Index("idx_agent_compliance_sessions_tenant", "tenant_id"),
        Index("idx_agent_compliance_sessions_framework", "tenant_id", "framework_id"),
        Index("idx_agent_compliance_sessions_created", "tenant_id", "created_at"),
        Index("idx_agent_compliance_sessions_question_hash", "tenant_id", "normalized_question_hash"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_question_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    citations: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    refusal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="SET NULL"),
        nullable=True,
    )
    control_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="SET NULL"),
        nullable=True,
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_assessments.id", ondelete="SET NULL"),
        nullable=True,
    )
    retrieval_trace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("retrieval_traces.id", ondelete="SET NULL"),
        nullable=True,
    )
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )

    framework = relationship("ComplianceFramework")
    control = relationship("ComplianceControl")
    assessment = relationship("ComplianceAssessment")
    retrieval_trace = relationship("RetrievalTrace")


class ComplianceScore(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_scores"
    __table_args__ = (
        Index("idx_compliance_framework", "tenant_id", "framework"),
        Index("idx_compliance_calculated", "tenant_id", "calculated_at", postgresql_using="btree"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    framework: Mapped[ComplianceFrameworkKey] = mapped_column(Enum(ComplianceFrameworkKey, name="compliance_framework", create_type=False), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    critical_violations: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    policy_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    security_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    breakdown: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
