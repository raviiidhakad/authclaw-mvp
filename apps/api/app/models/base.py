from datetime import datetime
import uuid
from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression
from sqlalchemy.types import DateTime

# UTC Timestamp type helper
class utcnow(expression.FunctionElement):
    type = DateTime()
    inherit_cache = True

@compiles(utcnow, 'postgresql')
def pg_utcnow(element, compiler, **kw):
    return "TIMEZONE('utc', CURRENT_TIMESTAMP)"

# Naming convention for constraints/indexes
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=convention)

class UUIDMixin:
    """Provides a UUID primary key"""
    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=expression.text("gen_random_uuid()")
    )

class TimestampMixin:
    """Provides created_at and updated_at timestamps"""
    created_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow,
        server_default=utcnow(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=utcnow(),
        nullable=False
    )
