"""Sprint 3 Phase 5: compliance assistant sessions

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-06-21 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_compliance_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("normalized_question_hash", sa.String(64), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("citations", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("refusal_reason", sa.Text(), nullable=True),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_frameworks.id", ondelete="SET NULL"), nullable=True),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_controls.id", ondelete="SET NULL"), nullable=True),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_assessments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("retrieval_trace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("retrieval_traces.id", ondelete="SET NULL"), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_agent_compliance_sessions_tenant", "agent_compliance_sessions", ["tenant_id"])
    op.create_index("idx_agent_compliance_sessions_framework", "agent_compliance_sessions", ["tenant_id", "framework_id"])
    op.create_index("idx_agent_compliance_sessions_created", "agent_compliance_sessions", ["tenant_id", "created_at"])
    op.create_index(
        "idx_agent_compliance_sessions_question_hash",
        "agent_compliance_sessions",
        ["tenant_id", "normalized_question_hash"],
    )

    op.execute("ALTER TABLE agent_compliance_sessions ENABLE ROW LEVEL SECURITY;")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON agent_compliance_sessions;")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON agent_compliance_sessions
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
                GRANT SELECT, INSERT, UPDATE, DELETE ON agent_compliance_sessions TO authclaw_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON agent_compliance_sessions;")
    op.drop_index("idx_agent_compliance_sessions_question_hash", table_name="agent_compliance_sessions")
    op.drop_index("idx_agent_compliance_sessions_created", table_name="agent_compliance_sessions")
    op.drop_index("idx_agent_compliance_sessions_framework", table_name="agent_compliance_sessions")
    op.drop_index("idx_agent_compliance_sessions_tenant", table_name="agent_compliance_sessions")
    op.drop_table("agent_compliance_sessions")
