import enum
import uuid
from datetime import datetime
from sqlalchemy import String, ForeignKey, Integer, Enum, text, Index, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional

from app.models.base import Base, UUIDMixin

class RequestStatus(str, enum.Enum):
    pending = "pending"
    completed = "completed"
    blocked = "blocked"
    error = "error"

class GatewayRequest(Base, UUIDMixin):
    __tablename__ = "gateway_requests"
    __table_args__ = (
        Index("idx_gw_requests_created", "tenant_id", "created_at"),
        Index("idx_gw_requests_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    provider_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("providers.id"), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    prompt_original: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_redacted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Sprint 1: lightweight counter — detailed detections live in ClickHouse audit events.
    security_event_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    status: Mapped[RequestStatus] = mapped_column(Enum(RequestStatus, name="request_status", create_type=False), server_default="pending", nullable=False)
    token_count_prompt: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    
    # Provider error details for audit
    provider_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    provider = relationship("Provider", back_populates="gateway_requests")
    response = relationship("GatewayResponse", back_populates="request", uselist=False, cascade="all, delete-orphan")
    violations = relationship("PolicyViolation", back_populates="gateway_request", cascade="all, delete-orphan")

class GatewayResponse(Base, UUIDMixin):
    __tablename__ = "gateway_responses"

    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("gateway_requests.id", ondelete="CASCADE"), unique=True, nullable=False)
    response_original: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_redacted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Sprint 1: lightweight counter — detailed detections live in ClickHouse audit events.
    security_event_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    token_count_completion: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    request = relationship("GatewayRequest", back_populates="response")
