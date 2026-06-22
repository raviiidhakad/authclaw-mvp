"""Sprint 1: Replace pii_detections JSONB with security_event_count integer

Revision ID: a1b2c3d4e5f6
Revises: fe8e1b8a3add
Create Date: 2026-06-20 08:00:00.000000

Design decision:
  Detailed PII/PHI detections are emitted exclusively to Kafka for storage
  in ClickHouse (the immutable audit chain). PostgreSQL operational tables
  store only a lightweight integer counter so that:
    1. Gateway tables remain small and query-fast.
    2. Sensitive entity metadata never lands in the transactional DB.
    3. ClickHouse JSONB audit records satisfy SOC2 / HIPAA evidence requirements.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'fe8e1b8a3add'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Replace pii_detections JSONB blob with lightweight integer counter on
    gateway_requests and gateway_responses tables.
    """
    # gateway_requests
    op.drop_column('gateway_requests', 'pii_detections')
    op.add_column(
        'gateway_requests',
        sa.Column(
            'security_event_count',
            sa.Integer(),
            nullable=False,
            server_default='0',
            comment='Number of security events (PII/PHI detections) on this request. '
                    'Detailed metadata is stored in ClickHouse audit events.',
        )
    )

    # gateway_responses
    op.drop_column('gateway_responses', 'pii_detections')
    op.add_column(
        'gateway_responses',
        sa.Column(
            'security_event_count',
            sa.Integer(),
            nullable=False,
            server_default='0',
            comment='Number of security events (PII/PHI detections) on this response. '
                    'Detailed metadata is stored in ClickHouse audit events.',
        )
    )


def downgrade() -> None:
    """
    Restore pii_detections JSONB blobs and remove security_event_count counters.
    NOTE: Historical detection data cannot be recovered from ClickHouse by this
    migration. Downgrade should only be performed in development environments.
    """
    # gateway_responses
    op.drop_column('gateway_responses', 'security_event_count')
    op.add_column(
        'gateway_responses',
        sa.Column(
            'pii_detections',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        )
    )

    # gateway_requests
    op.drop_column('gateway_requests', 'security_event_count')
    op.add_column(
        'gateway_requests',
        sa.Column(
            'pii_detections',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        )
    )
