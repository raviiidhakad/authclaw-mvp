"""Sprint 3 Phase 1: compliance catalog

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-21 09:00:00.000000

Adds global compliance framework/control catalog tables and seed tracking.
Tenant-scoped assessment/evidence/mapping tables are intentionally deferred.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_frameworks",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("key", sa.String(100), nullable=False),
        sa.Column("version", sa.String(100), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_url", sa.String(1024), nullable=True),
        sa.Column("license_note", sa.Text(), nullable=False),
        sa.Column("status", sa.String(50), server_default="active", nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
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
        sa.UniqueConstraint("key", "version", name="uq_compliance_frameworks_key_version"),
    )
    op.create_index("idx_compliance_frameworks_key", "compliance_frameworks", ["key"])
    op.create_index("idx_compliance_frameworks_status", "compliance_frameworks", ["status"])

    op.create_table(
        "compliance_controls",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "framework_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_code", sa.String(100), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(120), nullable=False),
        sa.Column("category", sa.String(120), nullable=True),
        sa.Column("severity_weight", sa.Integer(), server_default="1", nullable=False),
        sa.Column("requires_review", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("sort_order", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
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
        sa.UniqueConstraint("framework_id", "control_code", name="uq_compliance_controls_framework_code"),
    )
    op.create_index("idx_compliance_controls_framework", "compliance_controls", ["framework_id"])
    op.create_index("idx_compliance_controls_domain", "compliance_controls", ["framework_id", "domain"])
    op.create_index(
        "idx_compliance_controls_requires_review",
        "compliance_controls",
        ["framework_id", "requires_review"],
    )

    op.create_table(
        "control_requirements",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "control_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("requirement_key", sa.String(100), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence_expectation", sa.Text(), nullable=True),
        sa.Column("sort_order", sa.Integer(), server_default="0", nullable=False),
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
        sa.UniqueConstraint("control_id", "requirement_key", name="uq_control_requirements_control_key"),
    )
    op.create_index("idx_control_requirements_control", "control_requirements", ["control_id"])

    op.create_table(
        "framework_seed_versions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("seed_key", sa.String(255), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("framework_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("control_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("requirement_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "applied_at",
            sa.DateTime(timezone=False),
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.UniqueConstraint("seed_key", name="uq_framework_seed_versions_seed_key"),
    )
    op.create_index("idx_framework_seed_versions_applied", "framework_seed_versions", ["applied_at"])

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON
                    compliance_frameworks,
                    compliance_controls,
                    control_requirements,
                    framework_seed_versions
                TO authclaw_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.drop_index("idx_framework_seed_versions_applied", table_name="framework_seed_versions")
    op.drop_table("framework_seed_versions")
    op.drop_index("idx_control_requirements_control", table_name="control_requirements")
    op.drop_table("control_requirements")
    op.drop_index("idx_compliance_controls_requires_review", table_name="compliance_controls")
    op.drop_index("idx_compliance_controls_domain", table_name="compliance_controls")
    op.drop_index("idx_compliance_controls_framework", table_name="compliance_controls")
    op.drop_table("compliance_controls")
    op.drop_index("idx_compliance_frameworks_status", table_name="compliance_frameworks")
    op.drop_index("idx_compliance_frameworks_key", table_name="compliance_frameworks")
    op.drop_table("compliance_frameworks")
