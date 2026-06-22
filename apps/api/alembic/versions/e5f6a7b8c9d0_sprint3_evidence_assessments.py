"""Sprint 3 Phase 3: evidence lifecycle and compliance assessments

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-06-21 11:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "evidence_items",
    "compliance_assessments",
    "control_assessment_results",
    "compliance_gaps",
)


def _tenant_policy(table_name: str) -> None:
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table_name};")
    op.execute(
        f"""
        CREATE POLICY tenant_isolation ON {table_name}
        FOR ALL
        TO authclaw_app
        USING (
            tenant_id = NULLIF(
                current_setting('app.current_tenant_id', TRUE), ''
            )::uuid
        );
        """
    )


def upgrade() -> None:
    evidence_source_type = postgresql.ENUM(
        "finding_mapping",
        "audit_log",
        "manual",
        "system",
        name="evidence_source_type",
        create_type=False,
    )
    evidence_status = postgresql.ENUM(
        "active",
        "resolved",
        "suppressed",
        "stale",
        "expired",
        name="evidence_status",
        create_type=False,
    )
    assessment_status = postgresql.ENUM(
        "running",
        "completed",
        "failed",
        name="compliance_assessment_status",
        create_type=False,
    )
    score_band = postgresql.ENUM(
        "strong",
        "mostly_supported",
        "at_risk",
        "high_risk",
        name="compliance_score_band",
        create_type=False,
    )
    gap_type = postgresql.ENUM(
        "missing_evidence",
        "stale_evidence",
        "unresolved_finding",
        "low_confidence_mapping",
        "needs_review",
        "critical_open_risk",
        name="compliance_gap_type",
        create_type=False,
    )
    gap_severity = postgresql.ENUM(
        "low",
        "medium",
        "high",
        "critical",
        name="compliance_gap_severity",
        create_type=False,
    )

    for enum_type in (
        evidence_source_type,
        evidence_status,
        assessment_status,
        score_band,
        gap_type,
        gap_severity,
    ):
        enum_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "evidence_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("security_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cloud_integrations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("audit_log_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("audit_logs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mapping_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("finding_control_mappings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_type", evidence_source_type, nullable=False),
        sa.Column("status", evidence_status, server_default="active", nullable=False),
        sa.Column("safe_summary", sa.Text(), nullable=False),
        sa.Column("proof_hash", sa.String(64), nullable=True),
        sa.Column("freshness_expires_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("tenant_id", "control_id", "finding_id", "mapping_id", "source_type", name="uq_evidence_items_mapping_source"),
    )
    op.create_index("idx_evidence_items_tenant", "evidence_items", ["tenant_id"])
    op.create_index("idx_evidence_items_tenant_control", "evidence_items", ["tenant_id", "control_id"])
    op.create_index("idx_evidence_items_tenant_status", "evidence_items", ["tenant_id", "status"])
    op.create_index("idx_evidence_items_tenant_finding", "evidence_items", ["tenant_id", "finding_id"])
    op.create_index("idx_evidence_items_tenant_mapping", "evidence_items", ["tenant_id", "mapping_id"])
    op.create_index("idx_evidence_items_freshness", "evidence_items", ["tenant_id", "freshness_expires_at"])

    op.create_table(
        "compliance_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", assessment_status, server_default="running", nullable=False),
        sa.Column("score", sa.Float(), server_default="0", nullable=False),
        sa.Column("score_band", score_band, server_default="high_risk", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("inputs_hash", sa.String(64), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.CheckConstraint("score >= 0.0 AND score <= 100.0", name="ck_compliance_assessments_score_bounds"),
    )
    op.create_index("idx_compliance_assessments_tenant", "compliance_assessments", ["tenant_id"])
    op.create_index("idx_compliance_assessments_tenant_framework", "compliance_assessments", ["tenant_id", "framework_id"])
    op.create_index("idx_compliance_assessments_tenant_status", "compliance_assessments", ["tenant_id", "status"])
    op.create_index("idx_compliance_assessments_started", "compliance_assessments", ["tenant_id", "started_at"])

    op.create_table(
        "control_assessment_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("score_band", score_band, nullable=False),
        sa.Column("evidence_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("gap_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("assessment_id", "control_id", name="uq_control_assessment_results_assessment_control"),
        sa.CheckConstraint("score >= 0.0 AND score <= 100.0", name="ck_control_assessment_results_score_bounds"),
    )
    op.create_index("idx_control_results_tenant", "control_assessment_results", ["tenant_id"])
    op.create_index("idx_control_results_assessment", "control_assessment_results", ["assessment_id"])
    op.create_index("idx_control_results_control", "control_assessment_results", ["tenant_id", "control_id"])
    op.create_index("idx_control_results_band", "control_assessment_results", ["tenant_id", "score_band"])

    op.create_table(
        "compliance_gaps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mapping_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("finding_control_mappings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("security_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("gap_type", gap_type, nullable=False),
        sa.Column("severity", gap_severity, nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_status", sa.String(50), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_compliance_gaps_tenant", "compliance_gaps", ["tenant_id"])
    op.create_index("idx_compliance_gaps_assessment", "compliance_gaps", ["tenant_id", "assessment_id"])
    op.create_index("idx_compliance_gaps_control", "compliance_gaps", ["tenant_id", "control_id"])
    op.create_index("idx_compliance_gaps_type", "compliance_gaps", ["tenant_id", "gap_type"])
    op.create_index("idx_compliance_gaps_severity", "compliance_gaps", ["tenant_id", "severity"])

    for table in TENANT_TABLES:
        _tenant_policy(table)

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON
                    evidence_items,
                    compliance_assessments,
                    control_assessment_results,
                    compliance_gaps
                TO authclaw_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")

    op.drop_index("idx_compliance_gaps_severity", table_name="compliance_gaps")
    op.drop_index("idx_compliance_gaps_type", table_name="compliance_gaps")
    op.drop_index("idx_compliance_gaps_control", table_name="compliance_gaps")
    op.drop_index("idx_compliance_gaps_assessment", table_name="compliance_gaps")
    op.drop_index("idx_compliance_gaps_tenant", table_name="compliance_gaps")
    op.drop_table("compliance_gaps")

    op.drop_index("idx_control_results_band", table_name="control_assessment_results")
    op.drop_index("idx_control_results_control", table_name="control_assessment_results")
    op.drop_index("idx_control_results_assessment", table_name="control_assessment_results")
    op.drop_index("idx_control_results_tenant", table_name="control_assessment_results")
    op.drop_table("control_assessment_results")

    op.drop_index("idx_compliance_assessments_started", table_name="compliance_assessments")
    op.drop_index("idx_compliance_assessments_tenant_status", table_name="compliance_assessments")
    op.drop_index("idx_compliance_assessments_tenant_framework", table_name="compliance_assessments")
    op.drop_index("idx_compliance_assessments_tenant", table_name="compliance_assessments")
    op.drop_table("compliance_assessments")

    op.drop_index("idx_evidence_items_freshness", table_name="evidence_items")
    op.drop_index("idx_evidence_items_tenant_mapping", table_name="evidence_items")
    op.drop_index("idx_evidence_items_tenant_finding", table_name="evidence_items")
    op.drop_index("idx_evidence_items_tenant_status", table_name="evidence_items")
    op.drop_index("idx_evidence_items_tenant_control", table_name="evidence_items")
    op.drop_index("idx_evidence_items_tenant", table_name="evidence_items")
    op.drop_table("evidence_items")

    op.execute("DROP TYPE IF EXISTS compliance_gap_severity")
    op.execute("DROP TYPE IF EXISTS compliance_gap_type")
    op.execute("DROP TYPE IF EXISTS compliance_score_band")
    op.execute("DROP TYPE IF EXISTS compliance_assessment_status")
    op.execute("DROP TYPE IF EXISTS evidence_status")
    op.execute("DROP TYPE IF EXISTS evidence_source_type")
