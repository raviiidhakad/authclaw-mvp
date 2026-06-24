"""enforce_single_active_gateway_key

Revision ID: d8e9f0a1b2c3
Revises: d7e8f9a0b1c2
Create Date: 2026-06-24 09:25:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d8e9f0a1b2c3"
down_revision: Union[str, None] = "d7e8f9a0b1c2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        WITH ranked_keys AS (
            SELECT
                id,
                ROW_NUMBER() OVER (
                    PARTITION BY tenant_id
                    ORDER BY created_at DESC, id DESC
                ) AS row_number
            FROM api_keys
            WHERE is_active = TRUE
              AND scope IN ('full', 'gateway_only')
        )
        UPDATE api_keys
        SET is_active = FALSE
        WHERE id IN (
            SELECT id FROM ranked_keys WHERE row_number > 1
        );
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_one_active_gateway_per_tenant
        ON api_keys (tenant_id)
        WHERE is_active = TRUE
          AND scope IN ('full', 'gateway_only');
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_api_keys_one_active_gateway_per_tenant;")
