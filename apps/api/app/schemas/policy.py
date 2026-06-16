import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from app.models.policy import RuleType, PolicyAction, ViolationSeverity, ViolationResolution


# ── PolicyRule schemas ───────────────────────────────────────────
class PolicyRuleCreate(BaseModel):
    rule_type: RuleType
    conditions: Dict[str, Any] = Field(default_factory=dict)
    action: PolicyAction
    message: Optional[str] = None
    is_active: bool = True


class PolicyRuleResponse(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    rule_type: RuleType
    conditions: Dict[str, Any]
    action: PolicyAction
    message: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


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
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: Optional[str]
    is_active: bool
    priority: int
    rules: List[PolicyRuleResponse] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PolicyListResponse(BaseModel):
    items: list[PolicyResponse]
    total: int


# ── Violation schemas ────────────────────────────────────────────
class ViolationResponse(BaseModel):
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

    class Config:
        from_attributes = True


class ViolationUpdateResolution(BaseModel):
    resolution: ViolationResolution


class ViolationListResponse(BaseModel):
    items: list[ViolationResponse]
    total: int
