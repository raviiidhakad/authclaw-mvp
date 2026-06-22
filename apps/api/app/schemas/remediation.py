from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class RemediationArtifactResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    plan_id: uuid.UUID
    artifact_type: str
    content_redacted: str | None = None
    diff_summary: str | None = None
    artifact_hash: str
    risk_flags: dict[str, Any] = Field(default_factory=dict)
    status: str
    created_at: datetime
    updated_at: datetime


class RemediationRollbackPlanResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    plan_id: uuid.UUID
    rollback_summary: str
    rollback_artifact_hash: str | None = None
    risk_level: str
    created_at: datetime
    updated_at: datetime | None = None


class RemediationPolicyCheckResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    plan_id: uuid.UUID
    artifact_id: uuid.UUID | None = None
    passed: bool
    warnings: list[Any] = Field(default_factory=list)
    blocking_reasons: list[Any] = Field(default_factory=list)
    required_approval_level: str
    policy_check_hash: str
    created_at: datetime
    updated_at: datetime


class RemediationApprovalResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    plan_id: uuid.UUID
    artifact_hash: str
    policy_check_hash: str
    required_approval_level: str | None = None
    requested_by: uuid.UUID | None = None
    approved_by: uuid.UUID | None = None
    status: str
    expires_at: datetime
    resolved_at: datetime | None = None
    mfa_verified: bool
    approval_reason: str | None = None
    created_at: datetime
    updated_at: datetime


class RemediationExecutionJobResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    plan_id: uuid.UUID
    approval_id: uuid.UUID | None = None
    sandbox_id: str | None = None
    dry_run_result_id: uuid.UUID | None = None
    status: str
    disabled_reason: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RemediationDryRunResultResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    job_id: uuid.UUID | None = None
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    approval_id: uuid.UUID | None = None
    sandbox_id: str
    dry_run_type: str
    status: str
    output_summary: str
    warnings: list[Any] = Field(default_factory=list)
    blocking_reasons: list[Any] = Field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RemediationVerificationResultResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    plan_id: uuid.UUID
    job_id: uuid.UUID | None = None
    finding_status_before: str | None = None
    finding_status_after: str | None = None
    evidence_id: uuid.UUID | None = None
    verified: bool
    verification_summary: str
    status: str
    created_at: datetime
    updated_at: datetime


class RemediationExecutionResultResponse(BaseModel):
    job: RemediationExecutionJobResponse
    verification_result: RemediationVerificationResultResponse | None = None


class RemediationPlanResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID | None = None
    gap_id: uuid.UUID | None = None
    recommendation_id: uuid.UUID | None = None
    integration_id: uuid.UUID | None = None
    provider: str | None = None
    resource_ref: str | None = None
    risk_level: str
    status: str
    summary: str
    expected_impact: str
    created_by: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


class RemediationPlanDetailResponse(RemediationPlanResponse):
    artifacts: list[RemediationArtifactResponse] = Field(default_factory=list)
    rollback_plan: RemediationRollbackPlanResponse | None = None
    policy_checks: list[RemediationPolicyCheckResponse] = Field(default_factory=list)
    approvals: list[RemediationApprovalResponse] = Field(default_factory=list)
    execution_jobs: list[RemediationExecutionJobResponse] = Field(default_factory=list)


class RemediationPlanListResponse(BaseModel):
    items: list[RemediationPlanResponse]
    total: int
    skip: int
    limit: int


class RemediationArtifactListResponse(BaseModel):
    items: list[RemediationArtifactResponse]
    total: int
    skip: int
    limit: int


class RemediationPolicyCheckListResponse(BaseModel):
    items: list[RemediationPolicyCheckResponse]
    total: int
    skip: int
    limit: int


class RemediationApprovalListResponse(BaseModel):
    items: list[RemediationApprovalResponse]
    total: int
    skip: int
    limit: int


class RemediationExecutionJobListResponse(BaseModel):
    items: list[RemediationExecutionJobResponse]
    total: int
    skip: int
    limit: int


class RemediationDryRunResultListResponse(BaseModel):
    items: list[RemediationDryRunResultResponse]
    total: int
    skip: int
    limit: int


class RemediationVerificationResultListResponse(BaseModel):
    items: list[RemediationVerificationResultResponse]
    total: int
    skip: int
    limit: int


class GenerateRemediationPlanRequest(BaseModel):
    source_type: Literal["finding", "gap", "recommendation"]
    source_id: uuid.UUID


class ValidateRemediationPlanResponse(BaseModel):
    plan: RemediationPlanResponse
    artifact: RemediationArtifactResponse
    policy_check: RemediationPolicyCheckResponse


class RequestApprovalRequest(BaseModel):
    reason: str | None = Field(None, max_length=1000)


class ApproveRemediationRequest(BaseModel):
    approval_reason: str = Field(..., min_length=1, max_length=1000)
    mfa_verified: bool = False


class RejectRemediationRequest(BaseModel):
    rejection_reason: str = Field(..., min_length=1, max_length=1000)


class RevokeApprovalRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


class CreateDryRunRequest(BaseModel):
    approval_id: uuid.UUID | None = None


class CreateExecutionRequest(BaseModel):
    approval_id: uuid.UUID


class ExecutionDisabledResponse(BaseModel):
    detail: str
    execution_enabled: bool = False
