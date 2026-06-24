import uuid
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, ConfigDict, Field
from app.models.gateway import RequestStatus
from app.models.policy import ViolationSeverity, ViolationResolution

class GatewayResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    request_id: uuid.UUID
    response_original: Optional[str]
    response_redacted: Optional[str]
    pii_detections: List[Dict[str, Any]] = Field(default_factory=list)
    token_count_completion: int
    latency_ms: int
    created_at: datetime

class PolicyViolationSchema(BaseModel):
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

class GatewayRequestResponseBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    provider_id: Optional[uuid.UUID]
    model: Optional[str]
    status: RequestStatus
    token_count_prompt: int
    latency_ms: int
    provider_status_code: Optional[int] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    error_code: Optional[str] = None
    created_at: datetime

class GatewayRequestDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    provider_id: Optional[uuid.UUID]
    model: Optional[str]
    prompt_original: str
    prompt_redacted: Optional[str]
    pii_detections: List[Dict[str, Any]] = Field(default_factory=list)
    status: RequestStatus
    token_count_prompt: int
    latency_ms: int
    provider_status_code: Optional[int] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    error_code: Optional[str] = None
    created_at: datetime
    request_payload: Optional[Dict[str, Any]] = None
    modified_payload: Optional[Dict[str, Any]] = None
    response_payload: Optional[Dict[str, Any]] = None
    response: Optional[GatewayResponseSchema] = None
    violations: List[PolicyViolationSchema] = Field(default_factory=list)

class GatewayRequestListResponse(BaseModel):
    items: List[GatewayRequestResponseBrief]
    total: int
