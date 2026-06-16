import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

from app.models.provider import ProviderType


# ── Request schemas ──────────────────────────────────────────────
class ProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    type: ProviderType
    api_key: str = Field(..., min_length=1, description="Plaintext API key — encrypted at rest")
    config: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class ProviderUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    api_key: Optional[str] = Field(None, min_length=1)
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


# ── Response schemas ─────────────────────────────────────────────
class ProviderResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    type: ProviderType
    config: Dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProviderListResponse(BaseModel):
    items: list[ProviderResponse]
    total: int
