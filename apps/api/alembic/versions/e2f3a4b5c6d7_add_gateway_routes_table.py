"""Add gateway_routes table

Revision ID: e2f3a4b5c6d7
Revises: a73bc3de0931
Create Date: 2026-06-18 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'e2f3a4b5c6d7'
down_revision: Union[str, None] = 'a73bc3de0931'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create redaction_strategy enum type before the table that uses it
    op.execute("CREATE TYPE redaction_strategy AS ENUM ('none', 'mask', 'hash', 'synthetic')")

    op.create_table(
        'gateway_routes',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_default', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column(
            'redaction',
            postgresql.ENUM(
                'none', 'mask', 'hash', 'synthetic',
                name='redaction_strategy',
                create_type=False,
            ),
            server_default='none',
            nullable=False,
        ),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.ForeignKeyConstraint(
            ['tenant_id'], ['tenants.id'],
            name=op.f('fk_gateway_routes_tenant_id_tenants'),
            ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['provider_id'], ['providers.id'],
            name=op.f('fk_gateway_routes_provider_id_providers'),
            ondelete='SET NULL',
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_gateway_routes')),
    )
    op.create_index(op.f('ix_gateway_routes_id'), 'gateway_routes', ['id'], unique=False)
    op.create_index('idx_gw_routes_tenant_active', 'gateway_routes', ['tenant_id', 'is_active'])
    op.create_index('idx_gw_routes_tenant_default', 'gateway_routes', ['tenant_id', 'is_default'])


def downgrade() -> None:
    op.drop_index('idx_gw_routes_tenant_default', table_name='gateway_routes')
    op.drop_index('idx_gw_routes_tenant_active', table_name='gateway_routes')
    op.drop_index(op.f('ix_gateway_routes_id'), table_name='gateway_routes')
    op.drop_table('gateway_routes')
    op.execute('DROP TYPE IF EXISTS redaction_strategy')
