"""Sprint 2: Add cloud_integrations and security_findings tables

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-20 11:00:00.000000

Design decisions:
  cloud_integrations:
    - vault_reference_id stores the Vault KV path ONLY — never raw credentials.
    - (tenant_id, provider_type, target_identifier) is UNIQUE — prevents
      duplicate integrations for the same cloud account per tenant.

  security_findings:
    - dedup_hash (SHA-256 hex, 64 chars) is UNIQUE — the ConnectorWorker
      upserts on this column; no duplicate findings are created.
    - Raw JSON payloads are NOT stored here — they go to ClickHouse keyed by id.
    - resolved_at is NULL until the finding transitions to RESOLVED.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Enum types ──────────────────────────────────────────────────────────
    cloud_provider_enum = postgresql.ENUM(
        'aws', 'github', 'gcp',
        name='cloud_provider',
        create_type=False,
    )
    integration_status_enum = postgresql.ENUM(
        'pending', 'active', 'error', 'syncing', 'disabled',
        name='integration_status',
        create_type=False,
    )
    finding_severity_enum = postgresql.ENUM(
        'low', 'medium', 'high', 'critical',
        name='finding_severity',
        create_type=False,
    )
    finding_status_enum = postgresql.ENUM(
        'new', 'active', 'remediating', 'resolved', 'suppressed',
        name='finding_status',
        create_type=False,
    )

    cloud_provider_enum.create(op.get_bind(), checkfirst=True)
    integration_status_enum.create(op.get_bind(), checkfirst=True)
    finding_severity_enum.create(op.get_bind(), checkfirst=True)
    finding_status_enum.create(op.get_bind(), checkfirst=True)

    # ── 2. cloud_integrations ─────────────────────────────────────────────────
    op.create_table(
        'cloud_integrations',
        sa.Column(
            'id',
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column(
            'tenant_id',
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey('tenants.id', ondelete='CASCADE'),
            nullable=False,
            comment='Owning tenant. Cascade-deleted when tenant is removed.',
        ),
        sa.Column(
            'provider_type',
            cloud_provider_enum,
            nullable=False,
            comment='Cloud provider type.',
        ),
        sa.Column(
            'target_identifier',
            sa.String(512),
            nullable=False,
            comment='AWS account ID / GitHub org / GCP project.',
        ),
        sa.Column(
            'display_name',
            sa.String(255),
            nullable=True,
            comment='Human-readable label for the UI.',
        ),
        sa.Column(
            'status',
            integration_status_enum,
            nullable=False,
            server_default='pending',
            comment='Integration lifecycle state.',
        ),
        sa.Column(
            'vault_reference_id',
            sa.String(1024),
            nullable=False,
            comment='Vault KV path. Raw credentials NEVER stored here.',
        ),
        sa.Column(
            'last_sync_at',
            sa.DateTime(timezone=False),
            nullable=True,
            comment='UTC timestamp of last successful sync.',
        ),
        sa.Column(
            'last_sync_finding_count',
            sa.Integer(),
            nullable=False,
            server_default='0',
            comment='Finding count from the last sync.',
        ),
        sa.Column(
            'error_message',
            sa.Text(),
            nullable=True,
            comment='Last error from validation or sync.',
        ),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        ),
    )

    # Indexes for cloud_integrations
    op.create_index(
        'idx_cloud_integrations_tenant_id',
        'cloud_integrations', ['tenant_id'],
    )
    op.create_index(
        'uq_cloud_integrations_tenant_provider_target',
        'cloud_integrations',
        ['tenant_id', 'provider_type', 'target_identifier'],
        unique=True,
    )

    # ── 3. security_findings ──────────────────────────────────────────────────
    op.create_table(
        'security_findings',
        sa.Column(
            'id',
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column(
            'integration_id',
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey('cloud_integrations.id', ondelete='CASCADE'),
            nullable=False,
            comment='Parent integration. Tenant chain: finding→integration→tenant.',
        ),
        sa.Column(
            'dedup_hash',
            sa.String(64),
            nullable=False,
            comment='SHA-256(integration_id:external_id:resource_id). Unique.',
        ),
        sa.Column(
            'external_id',
            sa.String(1024),
            nullable=False,
            comment='Provider-native finding ID.',
        ),
        sa.Column(
            'resource_id',
            sa.String(1024),
            nullable=False,
            comment='Affected resource identifier.',
        ),
        sa.Column(
            'title',
            sa.String(1024),
            nullable=False,
            comment='Short description of the finding.',
        ),
        sa.Column(
            'description',
            sa.Text(),
            nullable=True,
            comment='Detailed description.',
        ),
        sa.Column(
            'remediation_instructions',
            sa.Text(),
            nullable=True,
            comment='Provider remediation guidance.',
        ),
        sa.Column(
            'severity',
            finding_severity_enum,
            nullable=False,
            comment='Normalized severity.',
        ),
        sa.Column(
            'status',
            finding_status_enum,
            nullable=False,
            server_default='new',
            comment='Finding lifecycle state.',
        ),
        sa.Column(
            'resolved_at',
            sa.DateTime(timezone=False),
            nullable=True,
            comment='UTC timestamp when finding resolved.',
        ),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("TIMEZONE('utc', CURRENT_TIMESTAMP)"),
        ),
    )

    # Indexes for security_findings
    op.create_index(
        'idx_security_findings_integration_id',
        'security_findings', ['integration_id'],
    )
    op.create_index(
        'idx_security_findings_status_severity',
        'security_findings', ['status', 'severity'],
    )
    op.create_index(
        'uq_security_findings_dedup_hash',
        'security_findings', ['dedup_hash'],
        unique=True,
    )


def downgrade() -> None:
    # Drop tables first (reverse of creation)
    op.drop_table('security_findings')
    op.drop_table('cloud_integrations')

    # Drop enum types (must be after tables using them are dropped)
    op.execute('DROP TYPE IF EXISTS finding_status')
    op.execute('DROP TYPE IF EXISTS finding_severity')
    op.execute('DROP TYPE IF EXISTS integration_status')
    op.execute('DROP TYPE IF EXISTS cloud_provider')
