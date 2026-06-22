from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.integration import CloudProvider, IntegrationStatus


class IntegrationCreate(BaseModel):
    provider_type: CloudProvider
    target_identifier: str = Field(..., min_length=1, max_length=512)
    display_name: Optional[str] = Field(None, max_length=255)
    credentials: dict[str, Any] = Field(..., min_length=1)


class IntegrationUpdate(BaseModel):
    target_identifier: Optional[str] = Field(None, min_length=1, max_length=512)
    display_name: Optional[str] = Field(None, max_length=255)
    status: Optional[IntegrationStatus] = None
    credentials: Optional[dict[str, Any]] = None


class IntegrationValidateRequest(BaseModel):
    provider_type: CloudProvider
    target_identifier: str = Field(..., min_length=1, max_length=512)
    credentials: dict[str, Any] = Field(..., min_length=1)


class IntegrationValidationResponse(BaseModel):
    provider_type: CloudProvider
    valid: bool
    error_code: Optional[str] = None
    missing_permissions: list[str] = Field(default_factory=list)


class IntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    provider_type: CloudProvider
    target_identifier: str
    display_name: Optional[str] = None
    status: IntegrationStatus
    vault_reference_id: str
    last_sync_at: Optional[datetime] = None
    last_sync_finding_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class IntegrationListResponse(BaseModel):
    items: list[IntegrationResponse]
    total: int


class IntegrationSyncResponse(BaseModel):
    integration_id: uuid.UUID
    status: str = "accepted"
    queued: bool = True


class IntegrationHealthResponse(BaseModel):
    integration_id: Optional[uuid.UUID] = None
    provider_type: Optional[CloudProvider] = None
    status: Optional[IntegrationStatus] = None
    last_sync_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error_code: Optional[str] = None
    circuit_breaker_state: Optional[dict[str, Any]] = None
    worker_visibility: str = "event_scheduled"
    registered_connector_available: bool = False


class ConnectorHealthListResponse(BaseModel):
    registered_providers: list[str]
    circuit_breakers: dict[str, dict[str, Any]]
    items: list[IntegrationHealthResponse]
