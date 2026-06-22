from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from typing import Literal

from pydantic import BaseModel, Field


class ControlRequirementResponse(BaseModel):
    id: uuid.UUID
    requirement_key: str
    summary: str
    evidence_expectation: str | None = None
    sort_order: int


class ComplianceControlResponse(BaseModel):
    id: uuid.UUID
    framework_id: uuid.UUID
    control_code: str
    title: str
    summary: str
    domain: str
    category: str | None = None
    severity_weight: int
    requires_review: bool
    sort_order: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    requirements: list[ControlRequirementResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ComplianceControlListResponse(BaseModel):
    items: list[ComplianceControlResponse]
    total: int
    skip: int
    limit: int


class ComplianceFrameworkResponse(BaseModel):
    id: uuid.UUID
    key: str
    version: str
    name: str
    description: str | None = None
    source_url: str | None = None
    license_note: str
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    control_count: int = 0
    created_at: datetime
    updated_at: datetime


class FindingControlMappingResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    control_id: uuid.UUID
    rule_id: str
    confidence: float
    mapping_source: str
    review_status: str
    override_reason: str | None = None
    control_code: str | None = None
    control_title: str | None = None
    framework_key: str | None = None
    created_at: datetime
    updated_at: datetime


class FindingControlMappingListResponse(BaseModel):
    items: list[FindingControlMappingResponse]
    total: int
    skip: int
    limit: int


class MappingReviewRequest(BaseModel):
    review_status: Literal["approved", "rejected", "overridden"]
    override_reason: str | None = Field(None, max_length=1000)


class ComplianceAssessmentRunRequest(BaseModel):
    framework_id: uuid.UUID | None = None
    framework: str | None = Field(None, description="Framework key such as gdpr, hipaa, soc2")


class EvidenceItemResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    control_id: uuid.UUID
    finding_id: uuid.UUID | None = None
    integration_id: uuid.UUID | None = None
    audit_log_id: uuid.UUID | None = None
    mapping_id: uuid.UUID | None = None
    source_type: str
    status: str
    safe_summary: str
    proof_hash: str | None = None
    freshness_expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    control_code: str | None = None
    framework_key: str | None = None
    created_at: datetime
    updated_at: datetime


class EvidenceItemListResponse(BaseModel):
    items: list[EvidenceItemResponse]
    total: int
    skip: int
    limit: int


class ComplianceGapResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    assessment_id: uuid.UUID
    control_id: uuid.UUID
    evidence_id: uuid.UUID | None = None
    mapping_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    gap_type: str
    severity: str
    reason: str
    evidence_status: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    control_code: str | None = None
    framework_key: str | None = None
    created_at: datetime
    updated_at: datetime


class ComplianceGapListResponse(BaseModel):
    items: list[ComplianceGapResponse]
    total: int
    skip: int
    limit: int


class ComplianceRecommendationResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    control_id: uuid.UUID
    gap_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    severity: str
    status: str
    title: str
    summary: str
    control_code: str | None = None
    framework_key: str | None = None
    created_at: datetime


class ComplianceRecommendationListResponse(BaseModel):
    items: list[ComplianceRecommendationResponse]
    total: int
    skip: int
    limit: int
    status: str = "derived_from_existing_gaps"


class ControlAssessmentResultResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    assessment_id: uuid.UUID
    control_id: uuid.UUID
    score: float
    score_band: str
    evidence_count: int
    gap_count: int
    explanation: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    control_code: str | None = None
    control_title: str | None = None
    created_at: datetime
    updated_at: datetime


class ComplianceAssessmentResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    framework_id: uuid.UUID
    framework_key: str | None = None
    status: str
    score: float
    score_band: str
    started_at: datetime
    completed_at: datetime | None = None
    inputs_hash: str
    explanation: str
    control_results: list[ControlAssessmentResultResponse] = Field(default_factory=list)
    gaps: list[ComplianceGapResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ComplianceAssessmentListResponse(BaseModel):
    items: list[ComplianceAssessmentResponse]
    total: int
    skip: int
    limit: int


class KnowledgeIngestRequest(BaseModel):
    tenant_scoped: bool = False


class KnowledgeChunkResponse(BaseModel):
    id: uuid.UUID
    document_id: uuid.UUID
    framework_id: uuid.UUID | None = None
    tenant_id: uuid.UUID | None = None
    control_id: uuid.UUID | None = None
    chunk_index: int
    chunk_text: str
    summary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_locator: str | None = None
    created_at: datetime
    updated_at: datetime


class KnowledgeDocumentResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None = None
    framework_id: uuid.UUID | None = None
    source_type: str
    title: str
    source_url: str | None = None
    license_status: str
    trust_level: str
    checksum: str
    status: str
    ingested_by: uuid.UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    chunk_count: int = 0
    chunks: list[KnowledgeChunkResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class KnowledgeDocumentListResponse(BaseModel):
    items: list[KnowledgeDocumentResponse]
    total: int
    skip: int
    limit: int


class KnowledgeIngestResponse(BaseModel):
    documents_seen: int
    documents_created: int
    documents_updated: int
    chunks_created: int


class RetrievalQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    framework_id: uuid.UUID | None = None
    control_id: uuid.UUID | None = None
    limit: int = Field(5, ge=1, le=20)
    session_id: str | None = Field(None, max_length=120)


class RetrievalCitationResponse(BaseModel):
    document_id: uuid.UUID
    document_title: str
    source_locator: str | None = None
    source_url: str | None = None
    license_status: str
    trust_level: str
    framework_id: uuid.UUID | None = None
    control_id: uuid.UUID | None = None


class RetrievalChunkResultResponse(BaseModel):
    chunk_id: uuid.UUID
    document_id: uuid.UUID
    chunk_text: str
    summary: str | None = None
    score: float
    citation: RetrievalCitationResponse
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievalQueryResponse(BaseModel):
    query_hash: str
    trace_id: uuid.UUID
    confidence: float
    strategy: str
    results: list[RetrievalChunkResultResponse]
    generated_answer: None = None


class ComplianceAskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=4000)
    framework_id: uuid.UUID | None = None
    control_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    assessment_id: uuid.UUID | None = None


class ComplianceAskResponse(BaseModel):
    answer: str
    confidence: float
    citations: list[dict[str, Any]] = Field(default_factory=list)
    related_controls: list[dict[str, Any]] = Field(default_factory=list)
    related_evidence: list[dict[str, Any]] = Field(default_factory=list)
    related_gaps: list[dict[str, Any]] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    refusal_reason: str | None = None
    retrieval_trace_id: uuid.UUID | None = None
    session_id: uuid.UUID


class ComplianceAskSessionResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    user_id: uuid.UUID | None = None
    question_hash: str
    answer: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float
    refused: bool
    refusal_reason: str | None = None
    framework_id: uuid.UUID | None = None
    control_id: uuid.UUID | None = None
    assessment_id: uuid.UUID | None = None
    retrieval_trace_id: uuid.UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class ComplianceAskSessionListResponse(BaseModel):
    items: list[ComplianceAskSessionResponse]
    total: int
    skip: int
    limit: int
