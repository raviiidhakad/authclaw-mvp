"""Phase 9 risk red teaming completion

Revision ID: e0f1a2b3c4d5
Revises: 703d9ca8e480
Create Date: 2026-07-01 10:00:00.000000

Adds tenant-scoped red-team probe result rows and metadata needed for the
vulnerability register. This does not introduce external attack execution.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e0f1a2b3c4d5"
down_revision: Union[str, None] = "703d9ca8e480"
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
    op.execute("ALTER TYPE adversarial_probe_category ADD VALUE IF NOT EXISTS 'policy_bypass'")
    op.execute("ALTER TYPE adversarial_probe_category ADD VALUE IF NOT EXISTS 'report_export_leakage'")

    vulnerability_severity = postgresql.ENUM(
        "low",
        "medium",
        "high",
        "critical",
        name="vulnerability_severity",
        create_type=False,
    )
    probe_category = postgresql.ENUM(
        "prompt_injection",
        "data_disclosure",
        "credential_leakage",
        "harmful_content",
        "sycophancy_policy_bypass",
        "policy_bypass",
        "report_export_leakage",
        name="adversarial_probe_category",
        create_type=False,
    )

    op.create_table(
        "red_team_probe_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("probe_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("adversarial_probe_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", probe_category, nullable=False),
        sa.Column("target_surface", sa.String(120), nullable=False),
        sa.Column("status", sa.String(40), server_default="blocked", nullable=False),
        sa.Column("severity", vulnerability_severity, server_default="low", nullable=False),
        sa.Column("confidence", sa.Integer(), server_default=sa.text("80"), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("sanitized_input_summary", sa.Text(), nullable=False),
        sa.Column("sanitized_output_summary", sa.Text(), nullable=False),
        sa.Column("linked_finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("linked_remediation_plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("linked_control_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("linked_report_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("raw_payload_stored", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_red_team_probe_results_tenant", "red_team_probe_results", ["tenant_id"])
    op.create_index("idx_red_team_probe_results_run", "red_team_probe_results", ["tenant_id", "probe_run_id"])
    op.create_index("idx_red_team_probe_results_category", "red_team_probe_results", ["tenant_id", "category"])
    op.create_index("idx_red_team_probe_results_surface", "red_team_probe_results", ["tenant_id", "target_surface"])
    op.create_index("idx_red_team_probe_results_status", "red_team_probe_results", ["tenant_id", "status"])
    op.create_index("idx_red_team_probe_results_severity", "red_team_probe_results", ["tenant_id", "severity"])
    _tenant_policy("red_team_probe_results")

    op.add_column("vulnerability_register_items", sa.Column("confidence", sa.Integer(), server_default=sa.text("80"), nullable=False))
    op.add_column("vulnerability_register_items", sa.Column("due_date", sa.DateTime(), nullable=True))
    op.add_column("vulnerability_register_items", sa.Column("linked_finding_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("vulnerability_register_items", sa.Column("linked_control_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("vulnerability_register_items", sa.Column("linked_report_artifact_id", postgresql.UUID(as_uuid=True), nullable=True))


def downgrade() -> None:
    op.drop_column("vulnerability_register_items", "linked_report_artifact_id")
    op.drop_column("vulnerability_register_items", "linked_control_id")
    op.drop_column("vulnerability_register_items", "linked_finding_id")
    op.drop_column("vulnerability_register_items", "due_date")
    op.drop_column("vulnerability_register_items", "confidence")

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON red_team_probe_results;")
    op.drop_index("idx_red_team_probe_results_severity", table_name="red_team_probe_results")
    op.drop_index("idx_red_team_probe_results_status", table_name="red_team_probe_results")
    op.drop_index("idx_red_team_probe_results_surface", table_name="red_team_probe_results")
    op.drop_index("idx_red_team_probe_results_category", table_name="red_team_probe_results")
    op.drop_index("idx_red_team_probe_results_run", table_name="red_team_probe_results")
    op.drop_index("idx_red_team_probe_results_tenant", table_name="red_team_probe_results")
    op.drop_table("red_team_probe_results")
