import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.models.approval import ApprovalStatus, ApprovalActionType

class ApprovalResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str
    action_type: ApprovalActionType
    status: ApprovalStatus
    diff_content: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True

class ScanRequest(BaseModel):
    target: str # e.g., "AWS", "GitHub"
