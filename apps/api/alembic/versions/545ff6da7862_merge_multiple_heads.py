"""merge multiple heads

Revision ID: 545ff6da7862
Revises: dcab0a7275f7, f3a4b5c6d7e8
Create Date: 2026-06-18 23:22:15.835199

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '545ff6da7862'
down_revision: Union[str, None] = ('dcab0a7275f7', 'f3a4b5c6d7e8')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
