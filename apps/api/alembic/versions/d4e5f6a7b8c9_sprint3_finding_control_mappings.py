"""Sprint 3 Phase 2: finding-to-control mappings

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-06-21 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    mapping_source = postgresql.ENUM(
        "deterministic",
        "heuristic",
        "manual",
        "imported",
        name="mapping_source",
        create_type=False,
    )
    mapping_review_status = postgresql.ENUM(
        "auto_approved",
        "needs_review",
        "approved",
        "rejected",
        "overridden",
        name="mapping_review_status",
        create_type=False,
    )
    mapping_source.create(op.get_bind(), checkfirst=True)
    mapping_review_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "finding_control_mappings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("security_findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "control_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(120), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "mapping_source",
            mapping_source,
            nullable=False,
            server_default="deterministic",
        ),
        sa.Column(
            "review_status",
            mapping_review_status,
            nullable=False,
            server_default="needs_review",
        ),
        sa.Column("override_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=False),
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "finding_id",
            "control_id",
            "rule_id",
            name="uq_finding_control_mappings_rule",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_finding_control_mappings_confidence_bounds",
        ),
    )
    op.create_index("idx_finding_control_mappings_tenant", "finding_control_mappings", ["tenant_id"])
    op.create_index("idx_finding_control_mappings_finding", "finding_control_mappings", ["finding_id"])
    op.create_index("idx_finding_control_mappings_control", "finding_control_mappings", ["control_id"])
    op.create_index(
        "idx_finding_control_mappings_tenant_control",
        "finding_control_mappings",
        ["tenant_id", "control_id"],
    )
    op.create_index(
        "idx_finding_control_mappings_tenant_finding",
        "finding_control_mappings",
        ["tenant_id", "finding_id"],
    )
    op.create_index("idx_finding_control_mappings_review", "finding_control_mappings", ["review_status"])
    op.create_index("idx_finding_control_mappings_confidence", "finding_control_mappings", ["confidence"])

    op.execute("ALTER TABLE finding_control_mappings ENABLE ROW LEVEL SECURITY;")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_control_mappings;")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON finding_control_mappings
        FOR ALL
        TO authclaw_app
        USING (
            tenant_id = NULLIF(
                current_setting('app.current_tenant_id', TRUE), ''
            )::uuid
        );
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON finding_control_mappings TO authclaw_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_control_mappings;")
    op.drop_index("idx_finding_control_mappings_confidence", table_name="finding_control_mappings")
    op.drop_index("idx_finding_control_mappings_review", table_name="finding_control_mappings")
    op.drop_index("idx_finding_control_mappings_tenant_finding", table_name="finding_control_mappings")
    op.drop_index("idx_finding_control_mappings_tenant_control", table_name="finding_control_mappings")
    op.drop_index("idx_finding_control_mappings_control", table_name="finding_control_mappings")
    op.drop_index("idx_finding_control_mappings_finding", table_name="finding_control_mappings")
    op.drop_index("idx_finding_control_mappings_tenant", table_name="finding_control_mappings")
    op.drop_table("finding_control_mappings")
    op.execute("DROP TYPE IF EXISTS mapping_review_status")
    op.execute("DROP TYPE IF EXISTS mapping_source")
