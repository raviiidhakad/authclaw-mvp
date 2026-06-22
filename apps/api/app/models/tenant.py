import uuid
from sqlalchemy import String, Enum, text, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum
from typing import Any, Dict

from datetime import datetime

from app.models.base import Base, UUIDMixin, TimestampMixin

class TenantPlan(str, enum.Enum):
    free = "free"
    starter = "starter"
    professional = "professional"
    enterprise = "enterprise"

class TenantStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"
    deactivated = "deactivated"

class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    plan: Mapped[TenantPlan] = mapped_column(Enum(TenantPlan, name="tenant_plan", create_type=False), server_default="free", nullable=False)
    status: Mapped[TenantStatus] = mapped_column(Enum(TenantStatus, name="tenant_status", create_type=False), server_default="active", index=True, nullable=False)
    settings: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    providers = relationship("Provider", back_populates="tenant", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="tenant", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")
    domains = relationship("TenantDomain", back_populates="tenant", cascade="all, delete-orphan")
    invites = relationship("TenantInvite", back_populates="tenant", cascade="all, delete-orphan")

class TenantDomain(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenant_domains"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    verified: Mapped[bool] = mapped_column(default=False, server_default="false", nullable=False)

    tenant = relationship("Tenant", back_populates="domains")

class TenantInvite(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenant_invites"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    token: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    
    tenant = relationship("Tenant", back_populates="invites")
