import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.api_key import ApiKeyScope

class ApiKeyCreate(BaseModel):
    name: str
    scope: ApiKeyScope = ApiKeyScope.full
    expires_at: Optional[datetime] = None

class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    name: str
    key_prefix: str
    scope: ApiKeyScope
    is_active: bool
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    created_at: datetime

class ApiKeyCreateResponse(ApiKeyResponse):
    raw_key: Optional[str] = None
