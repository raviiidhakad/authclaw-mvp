from datetime import datetime
import uuid
from sqlalchemy import String, Boolean, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional

from app.models.base import Base, UUIDMixin

class RefreshToken(Base, UUIDMixin):
    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    family: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    user = relationship("User", backref="refresh_tokens")
