"""Add 'azure' value to cloud_provider enum

Revision ID: a9b0c1d2e3f4
Revises: e1f2a3b4c5d6
Create Date: 2026-07-09 09:00:00.000000

Note:
  ALTER TYPE ... ADD VALUE cannot be rolled back in PostgreSQL once committed.
  The downgrade() is intentionally a no-op — removing an enum value requires
  a full type replacement which is out-of-scope for a simple connector addition.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a9b0c1d2e3f4'
down_revision: Union[str, None] = 'e1f2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # IF NOT EXISTS prevents failure on repeated runs or partial migrations.
    op.execute("ALTER TYPE cloud_provider ADD VALUE IF NOT EXISTS 'azure'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values.
    # This migration is intentionally irreversible.
    pass
