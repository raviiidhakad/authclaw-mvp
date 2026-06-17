import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.models.base import Base

class ApprovalStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    executed = "executed"
    failed = "failed"

class ApprovalActionType(str, enum.Enum):
    terraform = "terraform"
    cli = "cli"
    config = "config"

class Approval(Base):
    __tablename__ = "approvals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    
    action_type = Column(Enum(ApprovalActionType), nullable=False)
    status = Column(Enum(ApprovalStatus), default=ApprovalStatus.pending, nullable=False)
    
    diff_content = Column(Text, nullable=True) # E.g. terraform plan output or script
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    
    tenant = relationship("Tenant", backref="approvals")
