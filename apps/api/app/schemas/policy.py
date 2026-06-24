import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field

from app.models.policy import RuleType, PolicyAction, ViolationSeverity, ViolationResolution


# ── PolicyRule schemas ───────────────────────────────────────────
class PolicyRuleCreate(BaseModel):
    rule_type: RuleType
    conditions: Dict[str, Any] = Field(default_factory=dict)
    action: PolicyAction
    message: Optional[str] = None
    is_active: bool = True


class PolicyRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    policy_id: uuid.UUID
    rule_type: RuleType
    conditions: Dict[str, Any]
    action: PolicyAction
    message: Optional[str]
    is_active: bool
    created_at: datetime


# ── Policy schemas ───────────────────────────────────────────────
class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: bool = True
    priority: int = Field(default=0, ge=0)
    rules: List[PolicyRuleCreate] = Field(default_factory=list)


class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = Field(None, ge=0)
    rules: Optional[List[PolicyRuleCreate]] = None


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: Optional[str]
    is_active: bool
    priority: int
    rules: List[PolicyRuleResponse] = []
    created_at: datetime
    updated_at: datetime


class PolicyListResponse(BaseModel):
    items: list[PolicyResponse]
    total: int


# ── Violation schemas ────────────────────────────────────────────
class PolicyYamlRequest(BaseModel):
    yaml_source: str = Field(..., min_length=1)


class PolicyYamlValidationResponse(BaseModel):
    valid: bool
    schema_version: Optional[str] = None
    normalized: Optional[Dict[str, Any]] = None
    errors: List[Dict[str, str]] = Field(default_factory=list)
    warnings: List[Dict[str, str]] = Field(default_factory=list)
    opa: Dict[str, Any] = Field(default_factory=dict)


class PolicyYamlImportResponse(BaseModel):
    policy: PolicyResponse
    validation: PolicyYamlValidationResponse


class PolicyYamlExportResponse(BaseModel):
    policy_id: uuid.UUID
    schema_version: str
    yaml_source: str


class PolicyTestRequest(BaseModel):
    yaml_source: Optional[str] = None
    policy_id: Optional[uuid.UUID] = None
    sample_text: str = Field(..., min_length=1, max_length=4000)


class PolicyTestResponse(BaseModel):
    allowed: bool
    blocked: bool
    action: str
    matched_rules: List[Dict[str, Any]] = Field(default_factory=list)
    redaction_required: bool = False
    reason: str
    validation: Optional[PolicyYamlValidationResponse] = None


class ViolationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    request_id: Optional[uuid.UUID]
    policy_id: Optional[uuid.UUID]
    rule_id: Optional[uuid.UUID]
    severity: ViolationSeverity
    description: str
    context: Dict[str, Any]
    resolution: ViolationResolution
    created_at: datetime


class ViolationUpdateResolution(BaseModel):
    resolution: ViolationResolution


class ViolationListResponse(BaseModel):
    items: list[ViolationResponse]
    total: int
