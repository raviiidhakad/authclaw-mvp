import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.models.provider import ProviderType
from app.services.api_safety import SECRET_FIELD_NAMES, sanitize_text


SAFE_PROVIDER_CONFIG_FIELDS = {"base_url", "model", "default_model", "organization", "api_version"}


def sanitize_provider_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in dict(config or {}).items():
        lowered = str(key).lower()
        if lowered in SECRET_FIELD_NAMES or "vault" in lowered or "raw" in lowered:
            continue
        if key not in SAFE_PROVIDER_CONFIG_FIELDS:
            continue
        sanitized[key] = sanitize_text(value) if isinstance(value, str) else value
    return sanitized


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
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    type: ProviderType
    config: Dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @field_serializer("config")
    def serialize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_provider_config(config)


class ProviderListResponse(BaseModel):
    items: list[ProviderResponse]
    total: int
