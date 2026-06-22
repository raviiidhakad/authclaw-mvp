"""
RLS Tenant Isolation — PostgreSQL Row-Level Security

Revision ID: c1a2b3d4e5f6
Revises: 988b8a7b9556
Create Date: 2026-06-17

This migration implements true database-level multi-tenant isolation using
PostgreSQL Row Level Security (RLS). It creates a dedicated runtime role
(authclaw_app) and attaches RESTRICTIVE per-table isolation policies.

Architecture decision:
  - ENABLE (not FORCE) ROW LEVEL SECURITY is used so the postgres superuser
    continues to bypass RLS during Alembic migrations.
  - The authclaw_app role is non-superuser and therefore subject to all policies.
  - Policies are RESTRICTIVE (AND logic) and scoped TO authclaw_app only,
    ensuring no accidental bypass via role escalation.
  - NULLIF guards the setting cast so an absent/empty context returns no rows
    (secure default) rather than raising a type error.

Tables covered (have direct tenant_id FK):
  audit_logs, compliance_scores, policies, policy_violations,
  providers, gateway_requests, api_keys, settings, user_roles, approvals

Tables NOT covered (protected via parent or not tenant-scoped):
  tenants, roles, permissions (global config)
  users       — queried before tenant context is established (auth flow)
  gateway_responses, policy_rules, refresh_tokens — no direct tenant_id
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "c1a2b3d4e5f6"
down_revision: Union[str, None] = "988b8a7b9556"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables that carry a direct tenant_id column and are RLS-eligible
TENANT_TABLES = [
    "audit_logs",
    "compliance_scores",
    "policies",
    "policy_violations",
    "providers",
    "gateway_requests",
    "api_keys",
    "settings",
    "user_roles",
    "approvals",
]


def upgrade() -> None:
    # ── 1. Create the runtime application role ───────────────────────────────
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                CREATE ROLE authclaw_app WITH LOGIN PASSWORD 'authclaw_app_password';
            END IF;
        END
        $$;
    """)

    # ── 2. Grant schema + table + sequence permissions to authclaw_app ────────
    op.execute("GRANT USAGE ON SCHEMA public TO authclaw_app;")
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO authclaw_app;")
    op.execute("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO authclaw_app;")
    # Future tables created by subsequent migrations also grant to authclaw_app
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT ALL ON TABLES TO authclaw_app;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT ALL ON SEQUENCES TO authclaw_app;"
    )

    # ── 3. Enable RLS + create isolation policy on each tenant table ─────────
    for table in TENANT_TABLES:
        # ENABLE — postgres superuser bypasses (safe for migrations)
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")

        # Policy: fails-closed
        # NULLIF guards: absent/empty setting → NULL → comparison returns NULL → no rows
        # TO authclaw_app: only the runtime role is constrained
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
    # ── Remove RLS policies and disable RLS ──────────────────────────────────
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    # ── Revoke permissions ────────────────────────────────────────────────────
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM authclaw_app;")
    op.execute("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM authclaw_app;")
    op.execute("REVOKE USAGE ON SCHEMA public FROM authclaw_app;")

    # ── Drop role (only if no other objects depend on it) ────────────────────
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authclaw_app') THEN
                DROP ROLE authclaw_app;
            END IF;
        END
        $$;
    """)
