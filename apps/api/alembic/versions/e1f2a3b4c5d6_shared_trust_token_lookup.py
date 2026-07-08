"""shared_trust_token_lookup

Revision ID: e1f2a3b4c5d6
Revises: e0f1a2b3c4d5
Create Date: 2026-07-08 16:20:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, None] = "e0f1a2b3c4d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION shared_trust_lookup_link(p_token_hash TEXT)
        RETURNS TABLE (share_link_id UUID, tenant_id UUID)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public
        AS $$
        BEGIN
            RETURN QUERY
            SELECT s.id, s.tenant_id
            FROM external_share_links s
            WHERE s.token_hash = p_token_hash
              AND s.revoked_at IS NULL
              AND s.expires_at > (now() AT TIME ZONE 'UTC')
            LIMIT 1;
        END;
        $$;
        """
    )
    op.execute("GRANT EXECUTE ON FUNCTION shared_trust_lookup_link(TEXT) TO authclaw_app;")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS shared_trust_lookup_link(TEXT);")
