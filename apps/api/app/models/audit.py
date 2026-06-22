import enum
import uuid
from datetime import datetime
from sqlalchemy import String, ForeignKey, Enum, text, Index, Text
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column
from typing import Any, Dict, Optional

from app.models.base import Base, UUIDMixin

class EventType(str, enum.Enum):
    auth_login = "auth_login"
    auth_logout = "auth_logout"
    auth_signup = "auth_signup"
    auth_password_reset = "auth_password_reset"
    gateway_request = "gateway_request"
    gateway_response = "gateway_response"
    gateway_blocked = "gateway_blocked"
    gateway_rate_limit_exceeded = "gateway_rate_limit_exceeded"
    gateway_stream_started = "gateway_stream_started"
    gateway_stream_completed = "gateway_stream_completed"
    gateway_stream_failed = "gateway_stream_failed"
    policy_violation = "policy_violation"
    policy_created = "policy_created"
    policy_updated = "policy_updated"
    policy_deleted = "policy_deleted"
    compliance_score_calculated = "compliance_score_calculated"
    admin_user_created = "admin_user_created"
    admin_user_updated = "admin_user_updated"
    admin_role_changed = "admin_role_changed"
    admin_provider_created = "admin_provider_created"
    admin_provider_updated = "admin_provider_updated"
    admin_gateway_route_created = "admin_gateway_route_created"
    admin_gateway_route_updated = "admin_gateway_route_updated"
    admin_gateway_route_deleted = "admin_gateway_route_deleted"
    approval_requested = "approval_requested"
    approval_approved = "approval_approved"
    approval_rejected = "approval_rejected"
    unknown = "unknown"

class AuditAction(str, enum.Enum):
    create = "create"
    read = "read"
    update = "update"
    delete = "delete"
    execute = "execute"

class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("idx_audit_event", "tenant_id", "event_type"),
        Index("idx_audit_created", "tenant_id", "created_at", postgresql_using="btree"),
        Index("idx_audit_user", "tenant_id", "user_id"),
        Index("idx_audit_resource", "tenant_id", "resource", "resource_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True, nullable=False)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    event_type: Mapped[EventType] = mapped_column(Enum(EventType, name="event_type", create_type=False, values_callable=lambda x: [e.value for e in x]), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction, name="audit_action", create_type=False, values_callable=lambda x: [e.value for e in x]), nullable=False)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
