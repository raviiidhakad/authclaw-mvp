from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field


class AdversarialProbeRunCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=180)
    category: str
    target_surface: str = Field("gateway", min_length=1, max_length=120)
    model_target: str | None = Field(None, max_length=160)
    owner_user_id: uuid.UUID | None = None


class AdversarialProbeRunResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    category: str
    status: str
    target_surface: str
    model_target: str | None = None
    execution_mode: str
    owner_user_id: uuid.UUID | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    safe_prompt_preview: str | None = None
    result_summary: str
    risk_score: int
    probes_total: int
    blocked_count: int
    allowed_count: int
    vulnerability_count: int
    evidence: dict[str, Any] = Field(default_factory=dict)
    raw_payload_stored: bool
    created_at: datetime
    updated_at: datetime


class VulnerabilityUpdateRequest(BaseModel):
    status: str | None = None
    owner_user_id: uuid.UUID | None = None
    remediation_plan_id: uuid.UUID | None = None
    remediation_summary: str | None = Field(None, max_length=1200)


class VulnerabilityRegisterItemResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    probe_run_id: uuid.UUID | None = None
    remediation_plan_id: uuid.UUID | None = None
    category: str
    title: str
    description: str
    severity: str
    status: str
    owner_user_id: uuid.UUID | None = None
    evidence_summary: str
    remediation_summary: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class RiskPostureResponse(BaseModel):
    verdict: str
    summary: str
    counts: dict[str, Any] = Field(default_factory=dict)
    blockers: list[Any] = Field(default_factory=list)
    recommendations: list[Any] = Field(default_factory=list)
    evidence_summary: str
    generated_at: datetime


T = TypeVar("T")


class RiskListResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    skip: int
    limit: int
