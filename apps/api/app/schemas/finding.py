from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.finding import FindingSeverity, FindingStatus
from app.models.integration import CloudProvider


class FindingResponse(BaseModel):
    id: uuid.UUID
    integration_id: uuid.UUID
    provider_type: CloudProvider
    dedup_hash: str
    external_id: str
    resource_id: str
    title: str
    description: Optional[str] = None
    remediation_instructions: Optional[str] = None
    severity: FindingSeverity
    status: FindingStatus
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    compliance_tags: list[str] = Field(default_factory=list)
    service: Optional[str] = None


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    skip: int
    limit: int


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
