"""add_pii_synthetic_rule_type

Revision ID: d6e7f8a9b0c1
Revises: d5e6f7a8b9c0
Create Date: 2026-06-24 07:05:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d6e7f8a9b0c1"
down_revision: Union[str, None] = "d5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE rule_type ADD VALUE IF NOT EXISTS 'pii_synthetic'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be safely removed without recreating the type.
    pass
