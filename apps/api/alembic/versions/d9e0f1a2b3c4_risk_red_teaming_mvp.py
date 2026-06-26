"""Risk and red teaming MVP

Revision ID: d9e0f1a2b3c4
Revises: d8e9f0a1b2c3
Create Date: 2026-06-24 12:20:00.000000

Adds tenant-scoped simulated adversarial probe runs, vulnerability register
items, and go/no-go posture snapshots. No external attack execution is
introduced.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d9e0f1a2b3c4"
down_revision: Union[str, None] = "d8e9f0a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "adversarial_probe_runs",
    "vulnerability_register_items",
    "risk_posture_snapshots",
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
    probe_category = postgresql.ENUM(
        "prompt_injection",
        "data_disclosure",
        "credential_leakage",
        "harmful_content",
        "sycophancy_policy_bypass",
        name="adversarial_probe_category",
        create_type=False,
    )
    probe_status = postgresql.ENUM(
        "queued",
        "running",
        "completed",
        "failed",
        "blocked",
        name="adversarial_probe_status",
        create_type=False,
    )
    vulnerability_severity = postgresql.ENUM("low", "medium", "high", "critical", name="vulnerability_severity", create_type=False)
    vulnerability_status = postgresql.ENUM(
        "open",
        "triaged",
        "remediating",
        "accepted_risk",
        "resolved",
        "false_positive",
        name="vulnerability_status",
        create_type=False,
    )
    go_no_go_verdict = postgresql.ENUM("go", "needs_review", "no_go", name="go_no_go_verdict", create_type=False)

    for enum_type in (probe_category, probe_status, vulnerability_severity, vulnerability_status, go_no_go_verdict):
        enum_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "adversarial_probe_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(180), nullable=False),
        sa.Column("category", probe_category, nullable=False),
        sa.Column("status", probe_status, server_default="queued", nullable=False),
        sa.Column("target_surface", sa.String(120), server_default="gateway", nullable=False),
        sa.Column("model_target", sa.String(160), nullable=True),
        sa.Column("execution_mode", sa.String(40), server_default="simulated", nullable=False),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("safe_prompt_preview", sa.Text(), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("probes_total", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("blocked_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("allowed_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("vulnerability_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("raw_payload_stored", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_adversarial_probe_runs_tenant", "adversarial_probe_runs", ["tenant_id"])
    op.create_index("idx_adversarial_probe_runs_category", "adversarial_probe_runs", ["tenant_id", "category"])
    op.create_index("idx_adversarial_probe_runs_status", "adversarial_probe_runs", ["tenant_id", "status"])
    op.create_index("idx_adversarial_probe_runs_owner", "adversarial_probe_runs", ["tenant_id", "owner_user_id"])
    op.create_index("idx_adversarial_probe_runs_completed", "adversarial_probe_runs", ["tenant_id", "completed_at"])

    op.create_table(
        "vulnerability_register_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("probe_run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("adversarial_probe_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("remediation_plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("category", probe_category, nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", vulnerability_severity, server_default="medium", nullable=False),
        sa.Column("status", vulnerability_status, server_default="open", nullable=False),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("remediation_summary", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_vulnerability_register_tenant", "vulnerability_register_items", ["tenant_id"])
    op.create_index("idx_vulnerability_register_probe", "vulnerability_register_items", ["tenant_id", "probe_run_id"])
    op.create_index("idx_vulnerability_register_category", "vulnerability_register_items", ["tenant_id", "category"])
    op.create_index("idx_vulnerability_register_severity", "vulnerability_register_items", ["tenant_id", "severity"])
    op.create_index("idx_vulnerability_register_status", "vulnerability_register_items", ["tenant_id", "status"])
    op.create_index("idx_vulnerability_register_owner", "vulnerability_register_items", ["tenant_id", "owner_user_id"])
    op.create_index("idx_vulnerability_register_remediation", "vulnerability_register_items", ["tenant_id", "remediation_plan_id"])

    op.create_table(
        "risk_posture_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("verdict", go_no_go_verdict, server_default="needs_review", nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("counts", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("blockers", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("recommendations", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_risk_posture_snapshots_tenant", "risk_posture_snapshots", ["tenant_id"])
    op.create_index("idx_risk_posture_snapshots_verdict", "risk_posture_snapshots", ["tenant_id", "verdict"])
    op.create_index("idx_risk_posture_snapshots_generated", "risk_posture_snapshots", ["tenant_id", "generated_at"])

    for table in TENANT_TABLES:
        _tenant_policy(table)


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")

    op.drop_index("idx_risk_posture_snapshots_generated", table_name="risk_posture_snapshots")
    op.drop_index("idx_risk_posture_snapshots_verdict", table_name="risk_posture_snapshots")
    op.drop_index("idx_risk_posture_snapshots_tenant", table_name="risk_posture_snapshots")
    op.drop_table("risk_posture_snapshots")

    op.drop_index("idx_vulnerability_register_remediation", table_name="vulnerability_register_items")
    op.drop_index("idx_vulnerability_register_owner", table_name="vulnerability_register_items")
    op.drop_index("idx_vulnerability_register_status", table_name="vulnerability_register_items")
    op.drop_index("idx_vulnerability_register_severity", table_name="vulnerability_register_items")
    op.drop_index("idx_vulnerability_register_category", table_name="vulnerability_register_items")
    op.drop_index("idx_vulnerability_register_probe", table_name="vulnerability_register_items")
    op.drop_index("idx_vulnerability_register_tenant", table_name="vulnerability_register_items")
    op.drop_table("vulnerability_register_items")

    op.drop_index("idx_adversarial_probe_runs_completed", table_name="adversarial_probe_runs")
    op.drop_index("idx_adversarial_probe_runs_owner", table_name="adversarial_probe_runs")
    op.drop_index("idx_adversarial_probe_runs_status", table_name="adversarial_probe_runs")
    op.drop_index("idx_adversarial_probe_runs_category", table_name="adversarial_probe_runs")
    op.drop_index("idx_adversarial_probe_runs_tenant", table_name="adversarial_probe_runs")
    op.drop_table("adversarial_probe_runs")

    for enum_name in (
        "go_no_go_verdict",
        "vulnerability_status",
        "vulnerability_severity",
        "adversarial_probe_status",
        "adversarial_probe_category",
    ):
        postgresql.ENUM(name=enum_name).drop(op.get_bind(), checkfirst=True)
