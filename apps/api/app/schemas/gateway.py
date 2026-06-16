import uuid
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel
from app.models.gateway import RequestStatus
from app.models.policy import ViolationSeverity, ViolationResolution

class GatewayResponseSchema(BaseModel):
    id: uuid.UUID
    request_id: uuid.UUID
    response_original: Optional[str]
    response_redacted: Optional[str]
    pii_detections: List[Dict[str, Any]]
    token_count_completion: int
    latency_ms: int
    created_at: datetime

    class Config:
        from_attributes = True

class PolicyViolationSchema(BaseModel):
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

class GatewayRequestResponseBrief(BaseModel):
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

    class Config:
        from_attributes = True

class GatewayRequestDetail(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    provider_id: Optional[uuid.UUID]
    model: Optional[str]
    prompt_original: str
    prompt_redacted: Optional[str]
    pii_detections: List[Dict[str, Any]]
    status: RequestStatus
    token_count_prompt: int
    latency_ms: int
    provider_status_code: Optional[int] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    error_code: Optional[str] = None
    created_at: datetime
    response: Optional[GatewayResponseSchema] = None
    violations: List[PolicyViolationSchema] = []

    class Config:
        from_attributes = True

class GatewayRequestListResponse(BaseModel):
    items: List[GatewayRequestResponseBrief]
    total: int
