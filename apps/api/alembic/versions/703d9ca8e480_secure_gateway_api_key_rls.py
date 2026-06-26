"""secure_gateway_api_key_rls

Revision ID: 703d9ca8e480
Revises: d9e0f1a2b3c4
Create Date: 2026-06-26 14:47:55.853122

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '703d9ca8e480'
down_revision: Union[str, None] = 'd9e0f1a2b3c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;")
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies 
                WHERE tablename = 'api_keys' AND policyname = 'tenant_isolation'
            ) THEN
                CREATE POLICY tenant_isolation ON api_keys
                FOR ALL
                TO authclaw_app
                USING (
                    tenant_id = NULLIF(
                        current_setting('app.current_tenant_id', TRUE), ''
                    )::uuid
                );
            END IF;
        END
        $$;
    """)

    op.execute("""
        CREATE OR REPLACE FUNCTION gateway_lookup_api_key(p_key_hash TEXT)
        RETURNS TABLE (
            id UUID,
            tenant_id UUID,
            user_id UUID,
            key_hash VARCHAR(255),
            key_prefix VARCHAR(12),
            name VARCHAR(100),
            scope api_key_scope,
            is_active BOOLEAN,
            expires_at TIMESTAMP WITHOUT TIME ZONE,
            last_used_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public
        AS $$
        BEGIN
            RETURN QUERY
            SELECT 
                k.id, k.tenant_id, k.user_id, k.key_hash, k.key_prefix, k.name,
                k.scope, k.is_active, k.expires_at, k.last_used_at, k.created_at
            FROM api_keys k
            WHERE k.key_hash = p_key_hash
              AND k.is_active = true;
        END;
        $$;
    """)
    op.execute("GRANT EXECUTE ON FUNCTION gateway_lookup_api_key(TEXT) TO authclaw_app;")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP FUNCTION IF EXISTS gateway_lookup_api_key(TEXT);")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON api_keys;")
    op.execute("ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;")
