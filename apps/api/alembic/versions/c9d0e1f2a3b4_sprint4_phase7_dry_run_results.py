"""Sprint 4 Phase 7: dry-run result foundation

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-06-22 12:00:00.000000

Creates sanitized dry-run result storage only. No real execution, cloud
mutation, Terraform apply, GitHub mutation, or credential access is introduced.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c9d0e1f2a3b4"
down_revision: Union[str, None] = "b8c9d0e1f2a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


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
    dry_run_status = postgresql.ENUM(
        "queued",
        "running",
        "succeeded",
        "failed",
        "rejected",
        name="remediation_dry_run_status",
        create_type=False,
    )
    dry_run_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "remediation_dry_run_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_execution_jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_artifacts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_approvals.id", ondelete="SET NULL"), nullable=True),
        sa.Column("sandbox_id", sa.String(120), nullable=False),
        sa.Column("dry_run_type", sa.String(80), nullable=False),
        sa.Column("status", dry_run_status, server_default="queued", nullable=False),
        sa.Column("output_summary", sa.Text(), nullable=False),
        sa.Column("warnings", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("blocking_reasons", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_remediation_dry_run_results_tenant", "remediation_dry_run_results", ["tenant_id"])
    op.create_index("idx_remediation_dry_run_results_plan", "remediation_dry_run_results", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_dry_run_results_artifact", "remediation_dry_run_results", ["tenant_id", "artifact_id"])
    op.create_index("idx_remediation_dry_run_results_job", "remediation_dry_run_results", ["tenant_id", "job_id"])
    op.create_index("idx_remediation_dry_run_results_status", "remediation_dry_run_results", ["tenant_id", "status"])
    _tenant_policy("remediation_dry_run_results")


def downgrade() -> None:
    op.drop_index("idx_remediation_dry_run_results_status", table_name="remediation_dry_run_results")
    op.drop_index("idx_remediation_dry_run_results_job", table_name="remediation_dry_run_results")
    op.drop_index("idx_remediation_dry_run_results_artifact", table_name="remediation_dry_run_results")
    op.drop_index("idx_remediation_dry_run_results_plan", table_name="remediation_dry_run_results")
    op.drop_index("idx_remediation_dry_run_results_tenant", table_name="remediation_dry_run_results")
    op.drop_table("remediation_dry_run_results")
    postgresql.ENUM(name="remediation_dry_run_status").drop(op.get_bind(), checkfirst=True)
