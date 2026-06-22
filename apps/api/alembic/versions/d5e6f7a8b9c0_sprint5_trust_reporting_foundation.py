"""Sprint 5 Phase 1: trust/reporting foundation

Revision ID: d5e6f7a8b9c0
Revises: c9d0e1f2a3b4
Create Date: 2026-06-22 18:00:00.000000

Creates tenant-scoped trust/report metadata only. No report generation,
download endpoint, public share behavior, cloud mutation, Terraform apply,
or remediation execution path is introduced.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c9d0e1f2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "report_templates",
    "report_runs",
    "report_artifacts",
    "export_manifests",
    "external_share_links",
    "report_access_logs",
    "trust_notifications",
)

ROLE_PERMISSIONS = {
    "viewer": {"view_trust_dashboard"},
    "member": {"view_trust_dashboard"},
    "analyst": {"view_trust_dashboard"},
    "auditor": {"view_trust_dashboard", "generate_report", "download_report", "view_report_access_logs"},
    "admin": {
        "view_trust_dashboard",
        "generate_report",
        "download_report",
        "view_report_access_logs",
        "manage_report_templates",
    },
    "owner": {
        "view_trust_dashboard",
        "generate_report",
        "download_report",
        "create_share_link",
        "revoke_share_link",
        "view_report_access_logs",
        "expire_report_artifact",
        "manage_report_templates",
    },
}


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


def _seed_roles_and_permissions() -> None:
    for role in ROLE_PERMISSIONS:
        op.execute(
            sa.text(
                """
                INSERT INTO roles (id, name, description, is_system, created_at)
                VALUES (
                    gen_random_uuid(),
                    :name,
                    :description,
                    true,
                    TIMEZONE('utc', CURRENT_TIMESTAMP)
                )
                ON CONFLICT (name) DO NOTHING
                """
            ).bindparams(name=role, description=f"System {role} role")
        )
    for role, actions in ROLE_PERMISSIONS.items():
        for action in sorted(actions):
            op.execute(
                sa.text(
                    """
                    INSERT INTO permissions (id, role_id, resource, action, created_at)
                    SELECT gen_random_uuid(), roles.id, 'trust_reporting', :action, TIMEZONE('utc', CURRENT_TIMESTAMP)
                    FROM roles
                    WHERE roles.name = :role
                    ON CONFLICT (role_id, resource, action) DO NOTHING
                    """
                ).bindparams(role=role, action=action)
            )


def upgrade() -> None:
    report_run_status = postgresql.ENUM(
        "queued",
        "running",
        "completed",
        "failed",
        "expired",
        name="report_run_status",
        create_type=False,
    )
    report_run_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "report_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("type", sa.String(80), nullable=False),
        sa.Column("format", sa.String(40), nullable=False),
        sa.Column("filters_schema", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("default_sections", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("is_system", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_report_templates_tenant_name"),
    )
    op.create_index("idx_report_templates_tenant", "report_templates", ["tenant_id"])
    op.create_index("idx_report_templates_type", "report_templates", ["tenant_id", "type"])

    op.create_table(
        "report_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("template_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("report_templates.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", report_run_status, server_default="queued", nullable=False),
        sa.Column("filters", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("failed_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_report_runs_tenant", "report_runs", ["tenant_id"])
    op.create_index("idx_report_runs_status", "report_runs", ["tenant_id", "status"])
    op.create_index("idx_report_runs_template", "report_runs", ["tenant_id", "template_id"])
    op.create_index("idx_report_runs_requested_by", "report_runs", ["tenant_id", "requested_by"])
    op.create_index("idx_report_runs_expires", "report_runs", ["tenant_id", "expires_at"])

    op.create_table(
        "report_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("report_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_type", sa.String(80), nullable=False),
        sa.Column("storage_key", sa.String(512), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("sanitization_version", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_report_artifacts_tenant", "report_artifacts", ["tenant_id"])
    op.create_index("idx_report_artifacts_run", "report_artifacts", ["tenant_id", "run_id"])
    op.create_index("idx_report_artifacts_type", "report_artifacts", ["tenant_id", "artifact_type"])
    op.create_index("idx_report_artifacts_expires", "report_artifacts", ["tenant_id", "expires_at"])

    op.create_table(
        "export_manifests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("report_artifacts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("manifest_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("hash_algorithm", sa.String(32), server_default="sha256", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("artifact_id", name="uq_export_manifests_artifact"),
    )
    op.create_index("idx_export_manifests_tenant", "export_manifests", ["tenant_id"])
    op.create_index("idx_export_manifests_artifact", "export_manifests", ["tenant_id", "artifact_id"])

    op.create_table(
        "external_share_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("report_artifacts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("max_downloads", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_external_share_links_token_hash"),
    )
    op.create_index("idx_external_share_links_tenant", "external_share_links", ["tenant_id"])
    op.create_index("idx_external_share_links_artifact", "external_share_links", ["tenant_id", "artifact_id"])
    op.create_index("idx_external_share_links_expires", "external_share_links", ["tenant_id", "expires_at"])
    op.create_index("idx_external_share_links_revoked", "external_share_links", ["tenant_id", "revoked_at"])

    op.create_table(
        "report_access_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("report_artifacts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("external_share_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("external_share_links.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("ip_hash", sa.String(64), nullable=True),
        sa.Column("user_agent_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_report_access_logs_tenant", "report_access_logs", ["tenant_id"])
    op.create_index("idx_report_access_logs_artifact", "report_access_logs", ["tenant_id", "artifact_id"])
    op.create_index("idx_report_access_logs_actor", "report_access_logs", ["tenant_id", "actor_user_id"])
    op.create_index("idx_report_access_logs_external_share", "report_access_logs", ["tenant_id", "external_share_id"])
    op.create_index("idx_report_access_logs_action", "report_access_logs", ["tenant_id", "action"])

    op.create_table(
        "trust_notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("recipient_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("type", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(40), server_default="info", nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("read_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_trust_notifications_tenant", "trust_notifications", ["tenant_id"])
    op.create_index("idx_trust_notifications_recipient", "trust_notifications", ["tenant_id", "recipient_user_id"])
    op.create_index("idx_trust_notifications_type", "trust_notifications", ["tenant_id", "type"])
    op.create_index("idx_trust_notifications_read", "trust_notifications", ["tenant_id", "read_at"])

    for table in TENANT_TABLES:
        _tenant_policy(table)
    _seed_roles_and_permissions()


def downgrade() -> None:
    op.execute("DELETE FROM permissions WHERE resource = 'trust_reporting'")
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")

    op.drop_index("idx_trust_notifications_read", table_name="trust_notifications")
    op.drop_index("idx_trust_notifications_type", table_name="trust_notifications")
    op.drop_index("idx_trust_notifications_recipient", table_name="trust_notifications")
    op.drop_index("idx_trust_notifications_tenant", table_name="trust_notifications")
    op.drop_table("trust_notifications")

    op.drop_index("idx_report_access_logs_action", table_name="report_access_logs")
    op.drop_index("idx_report_access_logs_external_share", table_name="report_access_logs")
    op.drop_index("idx_report_access_logs_actor", table_name="report_access_logs")
    op.drop_index("idx_report_access_logs_artifact", table_name="report_access_logs")
    op.drop_index("idx_report_access_logs_tenant", table_name="report_access_logs")
    op.drop_table("report_access_logs")

    op.drop_index("idx_external_share_links_revoked", table_name="external_share_links")
    op.drop_index("idx_external_share_links_expires", table_name="external_share_links")
    op.drop_index("idx_external_share_links_artifact", table_name="external_share_links")
    op.drop_index("idx_external_share_links_tenant", table_name="external_share_links")
    op.drop_table("external_share_links")

    op.drop_index("idx_export_manifests_artifact", table_name="export_manifests")
    op.drop_index("idx_export_manifests_tenant", table_name="export_manifests")
    op.drop_table("export_manifests")

    op.drop_index("idx_report_artifacts_expires", table_name="report_artifacts")
    op.drop_index("idx_report_artifacts_type", table_name="report_artifacts")
    op.drop_index("idx_report_artifacts_run", table_name="report_artifacts")
    op.drop_index("idx_report_artifacts_tenant", table_name="report_artifacts")
    op.drop_table("report_artifacts")

    op.drop_index("idx_report_runs_expires", table_name="report_runs")
    op.drop_index("idx_report_runs_requested_by", table_name="report_runs")
    op.drop_index("idx_report_runs_template", table_name="report_runs")
    op.drop_index("idx_report_runs_status", table_name="report_runs")
    op.drop_index("idx_report_runs_tenant", table_name="report_runs")
    op.drop_table("report_runs")

    op.drop_index("idx_report_templates_type", table_name="report_templates")
    op.drop_index("idx_report_templates_tenant", table_name="report_templates")
    op.drop_table("report_templates")

    postgresql.ENUM(name="report_run_status").drop(op.get_bind(), checkfirst=True)
