"""
AuthClaw Gateway Route Model
-----------------------------
Represents a named, tenant-scoped routing rule that maps incoming requests
to a specific AI provider with a chosen redaction strategy.

Each tenant can define multiple routes. The gateway engine resolves
the route to use based on the request's `route_name` field or falls
back to the default route.
"""
import uuid
from datetime import datetime
from typing import Optional, Any, Dict

import enum
from sqlalchemy import String, Boolean, ForeignKey, Enum, text, Index, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin, TimestampMixin


class RedactionStrategy(str, enum.Enum):
    """Defines how PII/sensitive data is handled before forwarding."""
    none = "none"              # Pass through unmodified
    mask = "mask"              # Replace with [ENTITY_TYPE] placeholder
    hash = "hash"              # Replace with SHA-256 hash of the value
    synthetic = "synthetic"    # Replace with AI-generated synthetic data (Phase 2)


class GatewayRoute(Base, UUIDMixin, TimestampMixin):
    """
    A named routing rule scoped to a tenant.

    Fields
    ------
    name          : Human-readable name, e.g. "production-openai"
    description   : Optional documentation string
    is_default    : Only one route per tenant can be the default
    provider_id   : Target provider for this route
    redaction     : Redaction strategy applied before forwarding
    is_active     : Gates whether the route is considered during resolution
    config        : Arbitrary JSON config (model overrides, temperature, etc.)
    """
    __tablename__ = "gateway_routes"
    __table_args__ = (
        Index("idx_gw_routes_tenant_active", "tenant_id", "is_active"),
        Index("idx_gw_routes_tenant_default", "tenant_id", "is_default"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("providers.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    redaction: Mapped[RedactionStrategy] = mapped_column(
        Enum(
            RedactionStrategy,
            name="redaction_strategy",
            create_type=False,
            values_callable=lambda x: [e.value for e in x],
        ),
        server_default="none",
        nullable=False,
    )
    config: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )

    tenant = relationship("Tenant")
    provider = relationship("Provider")
