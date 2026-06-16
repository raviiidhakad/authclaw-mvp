import enum
from datetime import datetime
import uuid
from sqlalchemy import String, Boolean, ForeignKey, Enum, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional

from app.models.base import Base, UUIDMixin

class ApiKeyScope(str, enum.Enum):
    full = "full"
    gateway_only = "gateway_only"
    read_only = "read_only"

class ApiKey(Base, UUIDMixin):
    __tablename__ = "api_keys"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    scope: Mapped[ApiKeyScope] = mapped_column(Enum(ApiKeyScope, name="api_key_scope", create_type=False), server_default="full", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    tenant = relationship("Tenant", back_populates="api_keys")
    user = relationship("User", back_populates="api_keys")
