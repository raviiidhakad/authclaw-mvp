from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum
from datetime import datetime, timezone
from app.models.base import Base

class WALEventStatus(str, enum.Enum):
    PENDING = "PENDING"
    PUBLISHED = "PUBLISHED"
    FAILED = "FAILED"

class ProcessedEvent(Base):
    """
    Tracks successfully processed events by Consumers for idempotency.
    """
    __tablename__ = "processed_events"
    
    event_id = Column(UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), index=True, nullable=True)
    consumer_group = Column(String(255), primary_key=True)
    processed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class WALEvent(Base):
    """
    Write-Ahead Log for events when Redpanda/MSK is unreachable.
    """
    __tablename__ = "wal_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    topic = Column(String(255), nullable=False, index=True)
    payload_bytes = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status = Column(String(50), default=WALEventStatus.PENDING.value, index=True)
