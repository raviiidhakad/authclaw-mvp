"""Sprint 3 Phase 4: compliance knowledge retrieval foundation

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-06-21 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


GLOBAL_OR_TENANT_TABLES = ("knowledge_documents", "knowledge_chunks")
TENANT_ONLY_TABLES = ("retrieval_traces",)


def _global_or_tenant_policy(table_name: str) -> None:
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table_name};")
    op.execute(
        f"""
        CREATE POLICY tenant_isolation ON {table_name}
        FOR ALL
        TO authclaw_app
        USING (
            tenant_id IS NULL OR tenant_id = NULLIF(
                current_setting('app.current_tenant_id', TRUE), ''
            )::uuid
        );
        """
    )


def _tenant_only_policy(table_name: str) -> None:
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
    document_status = postgresql.ENUM(
        "active",
        "archived",
        name="knowledge_document_status",
        create_type=False,
    )
    document_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "knowledge_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=True),
        sa.Column("source_type", sa.String(80), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("source_url", sa.String(1024), nullable=True),
        sa.Column("license_status", sa.String(120), nullable=False),
        sa.Column("trust_level", sa.String(80), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("status", document_status, server_default="active", nullable=False),
        sa.Column("ingested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("tenant_id", "checksum", name="uq_knowledge_documents_tenant_checksum"),
    )
    op.create_index("idx_knowledge_documents_tenant", "knowledge_documents", ["tenant_id"])
    op.create_index("idx_knowledge_documents_framework", "knowledge_documents", ["framework_id"])
    op.create_index("idx_knowledge_documents_status", "knowledge_documents", ["status"])
    op.create_index("idx_knowledge_documents_source", "knowledge_documents", ["source_type"])
    op.create_index(
        "uq_knowledge_documents_scope_checksum",
        "knowledge_documents",
        [sa.text("COALESCE(tenant_id::text, 'global')"), "checksum"],
        unique=True,
    )

    op.create_table(
        "knowledge_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("knowledge_documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=True),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("chunk_text", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("embedding", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("source_locator", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.UniqueConstraint("document_id", "chunk_index", name="uq_knowledge_chunks_document_index"),
    )
    op.create_index("idx_knowledge_chunks_document", "knowledge_chunks", ["document_id"])
    op.create_index("idx_knowledge_chunks_tenant", "knowledge_chunks", ["tenant_id"])
    op.create_index("idx_knowledge_chunks_framework", "knowledge_chunks", ["framework_id"])
    op.create_index("idx_knowledge_chunks_control", "knowledge_chunks", ["control_id"])

    op.create_table(
        "retrieval_traces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", sa.String(120), nullable=True),
        sa.Column("query_hash", sa.String(64), nullable=False),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_frameworks.id", ondelete="SET NULL"), nullable=True),
        sa.Column("filters", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("chunk_ids", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("scores", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("answer_confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
    )
    op.create_index("idx_retrieval_traces_tenant", "retrieval_traces", ["tenant_id"])
    op.create_index("idx_retrieval_traces_framework", "retrieval_traces", ["tenant_id", "framework_id"])
    op.create_index("idx_retrieval_traces_created", "retrieval_traces", ["tenant_id", "created_at"])

    for table in GLOBAL_OR_TENANT_TABLES:
        _global_or_tenant_policy(table)
    for table in TENANT_ONLY_TABLES:
        _tenant_only_policy(table)

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON
                    knowledge_documents,
                    knowledge_chunks,
                    retrieval_traces
                TO authclaw_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    for table in (*GLOBAL_OR_TENANT_TABLES, *TENANT_ONLY_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")

    op.drop_index("idx_retrieval_traces_created", table_name="retrieval_traces")
    op.drop_index("idx_retrieval_traces_framework", table_name="retrieval_traces")
    op.drop_index("idx_retrieval_traces_tenant", table_name="retrieval_traces")
    op.drop_table("retrieval_traces")

    op.drop_index("idx_knowledge_chunks_control", table_name="knowledge_chunks")
    op.drop_index("idx_knowledge_chunks_framework", table_name="knowledge_chunks")
    op.drop_index("idx_knowledge_chunks_tenant", table_name="knowledge_chunks")
    op.drop_index("idx_knowledge_chunks_document", table_name="knowledge_chunks")
    op.drop_table("knowledge_chunks")

    op.drop_index("uq_knowledge_documents_scope_checksum", table_name="knowledge_documents")
    op.drop_index("idx_knowledge_documents_source", table_name="knowledge_documents")
    op.drop_index("idx_knowledge_documents_status", table_name="knowledge_documents")
    op.drop_index("idx_knowledge_documents_framework", table_name="knowledge_documents")
    op.drop_index("idx_knowledge_documents_tenant", table_name="knowledge_documents")
    op.drop_table("knowledge_documents")

    op.execute("DROP TYPE IF EXISTS knowledge_document_status")
