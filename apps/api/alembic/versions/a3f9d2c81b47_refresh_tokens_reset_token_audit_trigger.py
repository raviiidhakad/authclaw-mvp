"""Add refresh_tokens table, users.reset_token, and audit immutability trigger

Revision ID: a3f9d2c81b47
Revises: d1b5cf1211e5
Create Date: 2026-06-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a3f9d2c81b47'
down_revision: Union[str, None] = 'd1b5cf1211e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add reset_token columns to users table
    op.add_column('users', sa.Column('reset_token_hash', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('reset_token_expires_at', sa.DateTime(), nullable=True))

    # 2. Create refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False),
        sa.Column('family', sa.String(length=255), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_refresh_tokens_user_id_users', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_refresh_tokens'),
        sa.UniqueConstraint('token_hash', name='uq_refresh_tokens_token_hash'),
    )
    op.create_index('ix_refresh_tokens_user_id', 'refresh_tokens', ['user_id'], unique=False)
    op.create_index('ix_refresh_tokens_family', 'refresh_tokens', ['family'], unique=False)
    op.create_index('ix_refresh_tokens_token_hash', 'refresh_tokens', ['token_hash'], unique=True)

    # 3. Audit log immutability: PostgreSQL trigger prevents UPDATE and DELETE
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_logs_immutable()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Audit logs are immutable. UPDATE and DELETE are not permitted on audit_logs.';
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trg_audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
    """)

    op.execute("""
        CREATE TRIGGER trg_audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
    """)


def downgrade() -> None:
    # Remove triggers and function
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_delete ON audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_immutable();")

    # Remove refresh_tokens table
    op.drop_index('ix_refresh_tokens_token_hash', table_name='refresh_tokens')
    op.drop_index('ix_refresh_tokens_family', table_name='refresh_tokens')
    op.drop_index('ix_refresh_tokens_user_id', table_name='refresh_tokens')
    op.drop_table('refresh_tokens')

    # Remove reset_token columns
    op.drop_column('users', 'reset_token_expires_at')
    op.drop_column('users', 'reset_token_hash')
