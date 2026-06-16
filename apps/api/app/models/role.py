from datetime import datetime
import uuid
from sqlalchemy import String, Boolean, ForeignKey, text, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List, Optional

from app.models.base import Base, UUIDMixin

class Role(Base, UUIDMixin):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    permissions = relationship("Permission", back_populates="role", cascade="all, delete-orphan")
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")

class Permission(Base, UUIDMixin):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "resource", "action", name="uq_permissions_role_resource_action"),
    )

    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    role = relationship("Role", back_populates="permissions")

class UserRole(Base, UUIDMixin):
    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "tenant_id", name="uq_user_roles_user_role_tenant"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)

    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="user_roles")
