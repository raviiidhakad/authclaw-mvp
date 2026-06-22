from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class TrustPostureResponse(BaseModel):
    tenant_id: uuid.UUID
    generated_at: datetime
    language: str
    posture: str
    counts: dict[str, Any] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    freshness: dict[str, Any] = Field(default_factory=dict)


class TrustOverviewResponse(BaseModel):
    tenant_id: uuid.UUID
    generated_at: datetime
    language: str
    security_posture: TrustPostureResponse
    compliance_posture: TrustPostureResponse
    remediation_posture: TrustPostureResponse
    integration_health: TrustPostureResponse


class ReportTemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=160)
    type: str = Field(..., min_length=1, max_length=80)
    format: Literal["json"] = "json"
    filters_schema: dict[str, Any] = Field(default_factory=dict)
    default_sections: list[Any] = Field(default_factory=list)
    is_system: bool = False


class ReportTemplateUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=160)
    type: str | None = Field(None, min_length=1, max_length=80)
    format: Literal["json"] | None = None
    filters_schema: dict[str, Any] | None = None
    default_sections: list[Any] | None = None
    is_system: bool | None = None


class ReportTemplateResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    type: str
    format: str
    filters_schema: dict[str, Any]
    default_sections: list[Any]
    created_by: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime
    is_system: bool


class ReportTemplateListResponse(BaseModel):
    items: list[ReportTemplateResponse]
    total: int
    skip: int
    limit: int


class ReportRunCreateRequest(BaseModel):
    template_id: uuid.UUID | None = None
    report_type: str = Field("trust_overview", min_length=1, max_length=80)
    filters: dict[str, Any] = Field(default_factory=dict)
    retention_days: int = Field(90, ge=1, le=365)


class ReportArtifactMetadataResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    run_id: uuid.UUID
    artifact_type: str
    content_hash: str
    size_bytes: int
    sanitization_version: str
    created_at: datetime
    expires_at: datetime | None = None
    manifest_hash: str | None = None


class ExportManifestResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    artifact_id: uuid.UUID
    manifest_json: dict[str, Any]
    manifest_hash: str
    hash_algorithm: str
    created_at: datetime


class ReportRunResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    template_id: uuid.UUID | None = None
    requested_by: uuid.UUID | None = None
    status: str
    filters: dict[str, Any]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failed_reason: str | None = None
    expires_at: datetime | None = None
    artifacts: list[ReportArtifactMetadataResponse] = Field(default_factory=list)
    manifest_hash: str | None = None


class ReportRunListResponse(BaseModel):
    items: list[ReportRunResponse]
    total: int
    skip: int
    limit: int


class ReportArtifactListResponse(BaseModel):
    items: list[ReportArtifactMetadataResponse]
    total: int
    skip: int
    limit: int


class EvidencePackageCreateRequest(BaseModel):
    framework_id: uuid.UUID | None = None
    control_ids: list[uuid.UUID] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    evidence_freshness_days: int | None = Field(None, ge=1, le=365)
    include_findings: bool = True
    include_remediation: bool = True
    output_format: Literal["json"] = "json"
    template_id: uuid.UUID | None = None
    retention_days: int = Field(90, ge=1, le=365)


class EvidencePackageResponse(BaseModel):
    run: ReportRunResponse
    artifact: ReportArtifactMetadataResponse | None = None
    manifest: ExportManifestResponse | None = None


class EvidencePackageListResponse(BaseModel):
    items: list[ReportRunResponse]
    total: int
    skip: int
    limit: int


class ReportAccessLogResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    artifact_id: uuid.UUID
    actor_user_id: uuid.UUID | None = None
    external_share_id: uuid.UUID | None = None
    action: str
    ip_hash: str | None = None
    user_agent_hash: str | None = None
    created_at: datetime


class ReportAccessLogListResponse(BaseModel):
    items: list[ReportAccessLogResponse]
    total: int
    skip: int
    limit: int
