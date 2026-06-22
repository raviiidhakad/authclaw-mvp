"""strict rls enforcement

Revision ID: 432c525c958b
Revises: 545ff6da7862
Create Date: 2026-06-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '432c525c958b'
down_revision: Union[str, None] = '545ff6da7862'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_TABLES = ["api_keys", "gateway_routes"]

def upgrade() -> None:
    # 1. Enable RLS
    for table in NEW_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        
        # We use IF NOT EXISTS logic implicitly by DROP then CREATE
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {table}
            FOR ALL
            TO authclaw_app
            USING (
                tenant_id = NULLIF(
                    current_setting('app.current_tenant_id', TRUE), ''
                )::uuid
            );
        """)

def downgrade() -> None:
    for table in NEW_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        # Note: api_keys originally didn't have it, users and gateway_routes didn't either.
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
