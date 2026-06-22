import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class TenantCreate(BaseModel):
    name: str

class TenantUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None

class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime

class TenantStats(BaseModel):
    user_count: int
    policy_count: int
    api_key_count: int
    total_requests: int
    blocked_requests: int
