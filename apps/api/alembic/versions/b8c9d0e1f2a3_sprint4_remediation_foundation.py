"""Sprint 4 Phase 1: remediation domain foundation

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-06-21 18:00:00.000000

Creates remediation models only. No execution, dry-run, cloud mutation, or
GitHub mutation paths are introduced by this migration.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "remediation_plans",
    "remediation_artifacts",
    "remediation_rollback_plans",
    "remediation_policy_checks",
    "remediation_approvals",
    "remediation_execution_jobs",
    "remediation_verification_results",
    "remediation_audit_links",
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
    remediation_plan_status = postgresql.ENUM(
        "detected",
        "recommendation_created",
        "plan_drafted",
        "plan_validated",
        "approval_requested",
        "approved",
        "rejected",
        "expired",
        "queued_for_execution",
        "executing",
        "succeeded",
        "failed",
        "rollback_required",
        "rolled_back",
        "verified",
        name="remediation_plan_status",
        create_type=False,
    )
    remediation_artifact_type = postgresql.ENUM(
        "terraform_plan_draft",
        "aws_cli_command_draft",
        "github_pr_patch_draft",
        "iam_policy_diff",
        "documentation_only",
        name="remediation_artifact_type",
        create_type=False,
    )
    remediation_artifact_status = postgresql.ENUM(
        "draft",
        "active",
        "superseded",
        "rejected",
        "archived",
        name="remediation_artifact_status",
        create_type=False,
    )
    remediation_risk_level = postgresql.ENUM(
        "low",
        "medium",
        "high",
        "critical",
        name="remediation_risk_level",
        create_type=False,
    )
    remediation_approval_status = postgresql.ENUM(
        "pending",
        "approved",
        "rejected",
        "expired",
        "revoked",
        "used",
        name="remediation_approval_status",
        create_type=False,
    )
    remediation_execution_status = postgresql.ENUM(
        "disabled",
        "queued",
        "dry_run_requested",
        "dry_run_succeeded",
        "dry_run_failed",
        "executing",
        "succeeded",
        "failed",
        "rollback_required",
        "rolled_back",
        name="remediation_execution_status",
        create_type=False,
    )
    remediation_approval_level = postgresql.ENUM(
        "operator",
        "admin",
        "owner",
        "security_admin",
        name="remediation_approval_level",
        create_type=False,
    )
    remediation_verification_status = postgresql.ENUM(
        "pending",
        "verified",
        "failed",
        "inconclusive",
        name="remediation_verification_status",
        create_type=False,
    )

    for enum_type in (
        remediation_plan_status,
        remediation_artifact_type,
        remediation_artifact_status,
        remediation_risk_level,
        remediation_approval_status,
        remediation_execution_status,
        remediation_approval_level,
        remediation_verification_status,
    ):
        enum_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "remediation_plans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("security_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("gap_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_gaps.id", ondelete="SET NULL"), nullable=True),
        sa.Column("recommendation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cloud_integrations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("provider", sa.String(80), nullable=True),
        sa.Column("resource_ref", sa.String(1024), nullable=True),
        sa.Column("risk_level", remediation_risk_level, server_default="medium", nullable=False),
        sa.Column("status", remediation_plan_status, server_default="detected", nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("expected_impact", sa.Text(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_remediation_plans_tenant", "remediation_plans", ["tenant_id"])
    op.create_index("idx_remediation_plans_status", "remediation_plans", ["tenant_id", "status"])
    op.create_index("idx_remediation_plans_risk", "remediation_plans", ["tenant_id", "risk_level"])
    op.create_index("idx_remediation_plans_finding", "remediation_plans", ["tenant_id", "finding_id"])
    op.create_index("idx_remediation_plans_gap", "remediation_plans", ["tenant_id", "gap_id"])
    op.create_index("idx_remediation_plans_integration", "remediation_plans", ["tenant_id", "integration_id"])

    op.create_table(
        "remediation_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_type", remediation_artifact_type, nullable=False),
        sa.Column("content_redacted", sa.Text(), nullable=False),
        sa.Column("diff_summary", sa.Text(), nullable=True),
        sa.Column("artifact_hash", sa.String(64), nullable=False),
        sa.Column("risk_flags", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("status", remediation_artifact_status, server_default="draft", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("plan_id", "artifact_hash", name="uq_remediation_artifacts_plan_hash"),
    )
    op.create_index("idx_remediation_artifacts_tenant", "remediation_artifacts", ["tenant_id"])
    op.create_index("idx_remediation_artifacts_plan", "remediation_artifacts", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_artifacts_status", "remediation_artifacts", ["tenant_id", "status"])

    op.create_table(
        "remediation_rollback_plans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rollback_steps", sa.Text(), nullable=False),
        sa.Column("rollback_artifact_hash", sa.String(64), nullable=True),
        sa.Column("risk_level", remediation_risk_level, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("plan_id", name="uq_remediation_rollback_plans_plan"),
    )
    op.create_index("idx_remediation_rollback_plans_tenant", "remediation_rollback_plans", ["tenant_id"])
    op.create_index("idx_remediation_rollback_plans_plan", "remediation_rollback_plans", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_rollback_plans_risk", "remediation_rollback_plans", ["tenant_id", "risk_level"])

    op.create_table(
        "remediation_policy_checks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_artifacts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("passed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("warnings", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("blocking_reasons", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("required_approval_level", remediation_approval_level, server_default="admin", nullable=False),
        sa.Column("policy_check_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("plan_id", "policy_check_hash", name="uq_remediation_policy_checks_plan_hash"),
    )
    op.create_index("idx_remediation_policy_checks_tenant", "remediation_policy_checks", ["tenant_id"])
    op.create_index("idx_remediation_policy_checks_plan", "remediation_policy_checks", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_policy_checks_artifact", "remediation_policy_checks", ["tenant_id", "artifact_id"])

    op.create_table(
        "remediation_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_hash", sa.String(64), nullable=False),
        sa.Column("policy_check_hash", sa.String(64), nullable=False),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", remediation_approval_status, server_default="pending", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=False), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("mfa_verified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("nonce", sa.String(120), nullable=False),
        sa.Column("approval_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("nonce", name="uq_remediation_approvals_nonce"),
    )
    op.create_index("idx_remediation_approvals_tenant", "remediation_approvals", ["tenant_id"])
    op.create_index("idx_remediation_approvals_plan", "remediation_approvals", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_approvals_status", "remediation_approvals", ["tenant_id", "status"])
    op.create_index("idx_remediation_approvals_expires", "remediation_approvals", ["tenant_id", "expires_at"])

    op.create_table(
        "remediation_execution_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_approvals.id", ondelete="SET NULL"), nullable=True),
        sa.Column("sandbox_id", sa.String(120), nullable=True),
        sa.Column("dry_run_result_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", remediation_execution_status, server_default="disabled", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_remediation_execution_jobs_tenant", "remediation_execution_jobs", ["tenant_id"])
    op.create_index("idx_remediation_execution_jobs_plan", "remediation_execution_jobs", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_execution_jobs_status", "remediation_execution_jobs", ["tenant_id", "status"])

    op.create_table(
        "remediation_verification_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_execution_jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_status_before", sa.String(80), nullable=True),
        sa.Column("finding_status_after", sa.String(80), nullable=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True),
        sa.Column("verified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("verification_summary", sa.Text(), nullable=False),
        sa.Column("status", remediation_verification_status, server_default="pending", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_remediation_verification_results_tenant", "remediation_verification_results", ["tenant_id"])
    op.create_index("idx_remediation_verification_results_plan", "remediation_verification_results", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_verification_results_verified", "remediation_verification_results", ["tenant_id", "verified"])

    op.create_table(
        "remediation_audit_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_artifacts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_approvals.id", ondelete="CASCADE"), nullable=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_execution_jobs.id", ondelete="CASCADE"), nullable=True),
        sa.Column("audit_event_id", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_remediation_audit_links_tenant", "remediation_audit_links", ["tenant_id"])
    op.create_index("idx_remediation_audit_links_plan", "remediation_audit_links", ["tenant_id", "plan_id"])
    op.create_index("idx_remediation_audit_links_approval", "remediation_audit_links", ["tenant_id", "approval_id"])
    op.create_index("idx_remediation_audit_links_job", "remediation_audit_links", ["tenant_id", "job_id"])
    op.create_index("idx_remediation_audit_links_event", "remediation_audit_links", ["tenant_id", "audit_event_id"])

    for table in TENANT_TABLES:
        _tenant_policy(table)

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON
                    remediation_plans,
                    remediation_artifacts,
                    remediation_rollback_plans,
                    remediation_policy_checks,
                    remediation_approvals,
                    remediation_execution_jobs,
                    remediation_verification_results,
                    remediation_audit_links
                TO authclaw_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")

    op.drop_index("idx_remediation_audit_links_event", table_name="remediation_audit_links")
    op.drop_index("idx_remediation_audit_links_job", table_name="remediation_audit_links")
    op.drop_index("idx_remediation_audit_links_approval", table_name="remediation_audit_links")
    op.drop_index("idx_remediation_audit_links_plan", table_name="remediation_audit_links")
    op.drop_index("idx_remediation_audit_links_tenant", table_name="remediation_audit_links")
    op.drop_table("remediation_audit_links")

    op.drop_index("idx_remediation_verification_results_verified", table_name="remediation_verification_results")
    op.drop_index("idx_remediation_verification_results_plan", table_name="remediation_verification_results")
    op.drop_index("idx_remediation_verification_results_tenant", table_name="remediation_verification_results")
    op.drop_table("remediation_verification_results")

    op.drop_index("idx_remediation_execution_jobs_status", table_name="remediation_execution_jobs")
    op.drop_index("idx_remediation_execution_jobs_plan", table_name="remediation_execution_jobs")
    op.drop_index("idx_remediation_execution_jobs_tenant", table_name="remediation_execution_jobs")
    op.drop_table("remediation_execution_jobs")

    op.drop_index("idx_remediation_approvals_expires", table_name="remediation_approvals")
    op.drop_index("idx_remediation_approvals_status", table_name="remediation_approvals")
    op.drop_index("idx_remediation_approvals_plan", table_name="remediation_approvals")
    op.drop_index("idx_remediation_approvals_tenant", table_name="remediation_approvals")
    op.drop_table("remediation_approvals")

    op.drop_index("idx_remediation_policy_checks_artifact", table_name="remediation_policy_checks")
    op.drop_index("idx_remediation_policy_checks_plan", table_name="remediation_policy_checks")
    op.drop_index("idx_remediation_policy_checks_tenant", table_name="remediation_policy_checks")
    op.drop_table("remediation_policy_checks")

    op.drop_index("idx_remediation_rollback_plans_risk", table_name="remediation_rollback_plans")
    op.drop_index("idx_remediation_rollback_plans_plan", table_name="remediation_rollback_plans")
    op.drop_index("idx_remediation_rollback_plans_tenant", table_name="remediation_rollback_plans")
    op.drop_table("remediation_rollback_plans")

    op.drop_index("idx_remediation_artifacts_status", table_name="remediation_artifacts")
    op.drop_index("idx_remediation_artifacts_plan", table_name="remediation_artifacts")
    op.drop_index("idx_remediation_artifacts_tenant", table_name="remediation_artifacts")
    op.drop_table("remediation_artifacts")

    op.drop_index("idx_remediation_plans_integration", table_name="remediation_plans")
    op.drop_index("idx_remediation_plans_gap", table_name="remediation_plans")
    op.drop_index("idx_remediation_plans_finding", table_name="remediation_plans")
    op.drop_index("idx_remediation_plans_risk", table_name="remediation_plans")
    op.drop_index("idx_remediation_plans_status", table_name="remediation_plans")
    op.drop_index("idx_remediation_plans_tenant", table_name="remediation_plans")
    op.drop_table("remediation_plans")

    op.execute("DROP TYPE IF EXISTS remediation_verification_status")
    op.execute("DROP TYPE IF EXISTS remediation_approval_level")
    op.execute("DROP TYPE IF EXISTS remediation_execution_status")
    op.execute("DROP TYPE IF EXISTS remediation_approval_status")
    op.execute("DROP TYPE IF EXISTS remediation_artifact_status")
    op.execute("DROP TYPE IF EXISTS remediation_artifact_type")
    op.execute("DROP TYPE IF EXISTS remediation_plan_status")
    op.execute("DROP TYPE IF EXISTS remediation_risk_level")
