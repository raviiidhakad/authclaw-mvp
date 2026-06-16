import enum
import uuid
from sqlalchemy import String, Boolean, ForeignKey, text, Enum, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Any, Dict

from app.models.base import Base, UUIDMixin, TimestampMixin

class ProviderType(str, enum.Enum):
    openai = "openai"
    anthropic = "anthropic"
    gemini = "gemini"
    cohere = "cohere"
    azure_openai = "azure_openai"

class Provider(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "providers"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    type: Mapped[ProviderType] = mapped_column(Enum(ProviderType, name="provider_type", create_type=False), nullable=False)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    config: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)

    tenant = relationship("Tenant", back_populates="providers")
    gateway_requests = relationship("GatewayRequest", back_populates="provider")
