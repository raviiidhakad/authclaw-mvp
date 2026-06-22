"""remove_rls_from_api_keys

Revision ID: dcab0a7275f7
Revises: c8d6607bff04
Create Date: 2026-06-18 06:35:28.304481

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dcab0a7275f7'
down_revision: Union[str, None] = 'c8d6607bff04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON api_keys;")
    op.execute("ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY tenant_isolation ON api_keys
        FOR ALL
        TO authclaw_app
        USING (
            tenant_id = NULLIF(
                current_setting('app.current_tenant_id', TRUE), ''
            )::uuid
        );
    """)
