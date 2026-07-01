import uuid
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict

class TenantCreate(BaseModel):
    name: str

class TenantUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    plan: Optional[str] = None
    settings: Optional[dict[str, Any]] = None

class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    plan: str
    status: str
    settings: dict[str, Any]
    created_at: datetime
    updated_at: datetime

class TenantStats(BaseModel):
    user_count: int
    policy_count: int
    api_key_count: int
    total_requests: int
    blocked_requests: int


class RateLimitTierResponse(BaseModel):
    plan_name: str
    requests_per_minute: int
    requests_per_day: int
    api_key_requests_per_minute: int
    route_model_requests_per_minute: int
    provider_requests_per_minute: int
    concurrent_gateway_requests: int
    concurrent_streams: int
    max_body_bytes: int
    connector_scan_concurrency: int
    connector_scan_interval_seconds: int
    report_generation_per_hour: int
    remediation_job_concurrency: int
