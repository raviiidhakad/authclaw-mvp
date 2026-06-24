import enum
import uuid
from sqlalchemy import String, Boolean, ForeignKey, Integer, Enum, text, Index, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Any, Dict, List, Optional
from datetime import datetime

from app.models.base import Base, UUIDMixin, TimestampMixin

class RuleType(str, enum.Enum):
    pii_block = "pii_block"
    pii_redact = "pii_redact"
    pii_synthetic = "pii_synthetic"
    content_filter = "content_filter"
    rate_limit = "rate_limit"
    model_restrict = "model_restrict"
    custom = "custom"

class PolicyAction(str, enum.Enum):
    allow = "allow"
    warn = "warn"
    block = "block"

class ViolationSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class ViolationResolution(str, enum.Enum):
    pending = "pending"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"

class Policy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "policies"
    __table_args__ = (
        Index("idx_policies_active", "tenant_id", "is_active"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    tenant = relationship("Tenant", back_populates="policies")
    rules = relationship("PolicyRule", back_populates="policy", cascade="all, delete-orphan")
    violations = relationship("PolicyViolation", back_populates="policy")

class PolicyRule(Base, UUIDMixin):
    __tablename__ = "policy_rules"

    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True, nullable=False)
    rule_type: Mapped[RuleType] = mapped_column(Enum(RuleType, name="rule_type", create_type=False), nullable=False)
    conditions: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    action: Mapped[PolicyAction] = mapped_column(Enum(PolicyAction, name="policy_action", create_type=False), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    policy = relationship("Policy", back_populates="rules")
    violations = relationship("PolicyViolation", back_populates="rule")

class PolicyViolation(Base, UUIDMixin):
    __tablename__ = "policy_violations"
    __table_args__ = (
        Index("idx_violations_severity", "tenant_id", "severity"),
        Index("idx_violations_created", "tenant_id", "created_at", postgresql_using="btree"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    request_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("gateway_requests.id"), nullable=True)
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("policies.id"), nullable=True)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("policy_rules.id"), nullable=True)
    severity: Mapped[ViolationSeverity] = mapped_column(Enum(ViolationSeverity, name="violation_severity", create_type=False), server_default="medium", nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    resolution: Mapped[ViolationResolution] = mapped_column(Enum(ViolationResolution, name="violation_resolution", create_type=False), server_default="pending", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    policy = relationship("Policy", back_populates="violations")
    rule = relationship("PolicyRule", back_populates="violations")
    gateway_request = relationship("GatewayRequest", back_populates="violations")
