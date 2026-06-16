import uuid
from sqlalchemy import String, ForeignKey, text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from typing import Any, Dict

from app.models.base import Base, UUIDMixin, TimestampMixin

class Setting(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "settings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_settings_tenant_key"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    key: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
