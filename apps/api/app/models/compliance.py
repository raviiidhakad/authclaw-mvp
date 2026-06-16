import enum
import uuid
from datetime import datetime
from sqlalchemy import Float, ForeignKey, Integer, Enum, text, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from typing import Any, Dict

from app.models.base import Base, UUIDMixin, TimestampMixin

class ComplianceFramework(str, enum.Enum):
    gdpr = "gdpr"
    hipaa = "hipaa"
    soc2 = "soc2"
    iso27001 = "iso27001"
    iso42001 = "iso42001"
    eu_ai_act = "eu_ai_act"

class ComplianceScore(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_scores"
    __table_args__ = (
        Index("idx_compliance_framework", "tenant_id", "framework"),
        Index("idx_compliance_calculated", "tenant_id", "calculated_at", postgresql_using="btree"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework, name="compliance_framework", create_type=False), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    critical_violations: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    policy_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    security_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    breakdown: Mapped[Dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"), nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(server_default=text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False)
