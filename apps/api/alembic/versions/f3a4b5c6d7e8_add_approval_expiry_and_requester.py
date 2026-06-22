"""Add approval expires_at and requested_by_user_id

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-06-18 17:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'f3a4b5c6d7e8'
down_revision: Union[str, None] = 'e2f3a4b5c6d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # expires_at — 30-minute TTL, set at creation time by the agent node
    op.add_column(
        'approvals',
        sa.Column('expires_at', sa.DateTime(), nullable=True),
    )
    # requested_by_user_id — tracks who initiated the approval request.
    # Non-transferable: only the requesting user (or an Admin/Owner) can approve.
    op.add_column(
        'approvals',
        sa.Column(
            'requested_by_user_id',
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True,
        ),
    )
    # Composite index for the expiry cron job — quickly find all pending
    # approvals that have passed their TTL without a full-table scan.
    op.create_index(
        'idx_approvals_expires_pending',
        'approvals',
        ['expires_at', 'status'],
    )


def downgrade() -> None:
    op.drop_index('idx_approvals_expires_pending', table_name='approvals')
    op.drop_column('approvals', 'requested_by_user_id')
    op.drop_column('approvals', 'expires_at')
