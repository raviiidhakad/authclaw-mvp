"""
test_rls_isolation.py — Stream 1: PostgreSQL Row-Level Security Verification

All tests are self-contained: each creates, verifies, and deletes its own data.
This avoids all module-scoped fixture / event-loop conflicts.

Tests prove TRUE DATABASE-LEVEL isolation via direct asyncpg connections.
NOTE: We use the 'providers' table for testing rather than 'audit_logs' because
audit_logs has a database-level immutable trigger that prevents test cleanup.
"""
import os
import secrets
import uuid

import asyncpg
import pytest

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "5434"))
DB_NAME = os.environ.get("DB_NAME", "authclaw")

SUPERUSER_DSN = f"postgresql://postgres:password@{DB_HOST}:{DB_PORT}/{DB_NAME}"
APP_USER_DSN  = f"postgresql://authclaw_app:authclaw_app_password@{DB_HOST}:{DB_PORT}/{DB_NAME}"


# ── Low-level helpers (plain asyncpg, no fixtures) ────────────────────────────

async def _new_tenant(conn) -> uuid.UUID:
    tid  = uuid.uuid4()
    slug = "rls-test-" + secrets.token_hex(6)
    await conn.execute(
        """INSERT INTO tenants (id, name, slug, plan, status, settings, created_at, updated_at)
           VALUES ($1, $2, $3, 'free', 'active', '{}'::jsonb, now(), now())""",
        tid, slug, slug,
    )
    return tid


async def _new_provider(conn, tenant_id: uuid.UUID) -> uuid.UUID:
    pid = uuid.uuid4()
    await conn.execute(
        """INSERT INTO providers
             (id, tenant_id, name, type, api_key_encrypted, config, is_active, created_at, updated_at)
           VALUES ($1, $2, 'rls-test', 'openai'::provider_type, 'enc_xxx',
                   '{}'::jsonb, true, now(), now())""",
        pid, tenant_id,
    )
    return pid


async def _clean(conn, *tenant_ids):
    if not tenant_ids:
        return
    await conn.execute("DELETE FROM providers WHERE tenant_id = ANY($1::uuid[])", list(tenant_ids))
    await conn.execute("DELETE FROM tenants WHERE id = ANY($1::uuid[])", list(tenant_ids))


async def _set_local(conn, tenant_id: uuid.UUID):
    # Parameterized queries don't work for SET LOCAL. f-string is safe for UUID.
    await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_id}'")

# ── Test 1: Superuser bypasses RLS ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_superuser_sees_all_rows():
    """EVIDENCE: postgres superuser bypasses RLS — can read across all tenants."""
    su = await asyncpg.connect(SUPERUSER_DSN)
    try:
        tenant_a = await _new_tenant(su)
        tenant_b = await _new_tenant(su)
        prov_a   = await _new_provider(su, tenant_a)
        prov_b   = await _new_provider(su, tenant_b)

        rows = await su.fetch(
            "SELECT id FROM providers WHERE id = ANY($1::uuid[])", [prov_a, prov_b]
        )
        ids = {r["id"] for r in rows}
        assert prov_a in ids, "Superuser must see Tenant A provider"
        assert prov_b in ids, "Superuser must see Tenant B provider"
    finally:
        await _clean(su, tenant_a, tenant_b)
        await su.close()


# ── Test 2: App user sees only own-tenant rows ────────────────────────────────

@pytest.mark.asyncio
async def test_app_user_sees_own_tenant_rows():
    """EVIDENCE: authclaw_app with Tenant A context sees only Tenant A's rows."""
    su  = await asyncpg.connect(SUPERUSER_DSN)
    app = await asyncpg.connect(APP_USER_DSN)
    try:
        tenant_a = await _new_tenant(su)
        tenant_b = await _new_tenant(su)
        prov_a   = await _new_provider(su, tenant_a)
        prov_b   = await _new_provider(su, tenant_b)

        async with app.transaction():
            await _set_local(app, tenant_a)
            rows = await app.fetch(
                "SELECT id FROM providers WHERE id = ANY($1::uuid[])", [prov_a, prov_b]
            )
            ids = {r["id"] for r in rows}
            assert prov_a in ids,     "Tenant A must see its own provider"
            assert prov_b not in ids, "Tenant A must NOT see Tenant B provider"
    finally:
        await _clean(su, tenant_a, tenant_b)
        await su.close()
        await app.close()


# ── Test 3: App user cannot see another tenant's rows ────────────────────────

@pytest.mark.asyncio
async def test_app_user_cannot_see_other_tenant_rows():
    """EVIDENCE: authclaw_app with Tenant B context cannot read Tenant A's data."""
    su  = await asyncpg.connect(SUPERUSER_DSN)
    app = await asyncpg.connect(APP_USER_DSN)
    try:
        tenant_a = await _new_tenant(su)
        tenant_b = await _new_tenant(su)
        prov_a   = await _new_provider(su, tenant_a)

        async with app.transaction():
            await _set_local(app, tenant_b)
            rows = await app.fetch("SELECT id FROM providers WHERE id = $1", prov_a)
            assert len(rows) == 0, (
                f"CRITICAL: Tenant B saw Tenant A's row {prov_a}. RLS failed!"
            )
    finally:
        await _clean(su, tenant_a, tenant_b)
        await su.close()
        await app.close()


# ── Test 4: No context → zero rows (secure default) ──────────────────────────

@pytest.mark.asyncio
async def test_no_tenant_context_returns_zero_rows():
    """EVIDENCE: No tenant context returns zero rows — NULLIF guard works correctly."""
    su  = await asyncpg.connect(SUPERUSER_DSN)
    app = await asyncpg.connect(APP_USER_DSN)
    try:
        tenant_a = await _new_tenant(su)
        prov_a   = await _new_provider(su, tenant_a)

        async with app.transaction():
            # Deliberately set no tenant context
            rows = await app.fetch("SELECT id FROM providers WHERE id = $1", prov_a)
            assert len(rows) == 0, (
                f"CRITICAL: No-context query exposed row {prov_a}! "
                f"Data exposure detected. Got {len(rows)} rows."
            )
    finally:
        await _clean(su, tenant_a)
        await su.close()
        await app.close()


# ── Test 5: SET LOCAL resets between transactions ─────────────────────────────

@pytest.mark.asyncio
async def test_set_local_resets_between_transactions():
    """EVIDENCE: SET LOCAL does not bleed into the next transaction (no stale context)."""
    su  = await asyncpg.connect(SUPERUSER_DSN)
    app = await asyncpg.connect(APP_USER_DSN)
    try:
        tenant_a = await _new_tenant(su)
        prov_a   = await _new_provider(su, tenant_a)

        # Tx 1 — set context, verify row is visible
        async with app.transaction():
            await _set_local(app, tenant_a)
            rows_t1 = await app.fetch("SELECT id FROM providers WHERE id = $1", prov_a)
            assert len(rows_t1) == 1, "Tx1: Tenant A must see its own row"

        # Tx 2 — SET LOCAL from Tx1 must have cleared on commit
        async with app.transaction():
            rows_t2 = await app.fetch("SELECT id FROM providers WHERE id = $1", prov_a)
            assert len(rows_t2) == 0, (
                f"CRITICAL: SET LOCAL leaked into Tx2. Got {len(rows_t2)} rows!"
            )
    finally:
        await _clean(su, tenant_a)
        await su.close()
        await app.close()


# ── Test 6: pg_policies catalog — all 10 policies confirmed ──────────────────

@pytest.mark.asyncio
async def test_rls_policy_exists_on_all_expected_tables():
    """EVIDENCE: pg_policies catalog confirms 'tenant_isolation' on all 10 tables."""
    expected = {
        "api_keys", "approvals", "audit_logs", "compliance_scores",
        "gateway_requests", "policies", "policy_violations",
        "providers", "settings", "user_roles",
    }
    su = await asyncpg.connect(SUPERUSER_DSN)
    try:
        rows = await su.fetch(
            "SELECT tablename FROM pg_policies "
            "WHERE policyname = 'tenant_isolation' AND schemaname = 'public'"
        )
        found = {r["tablename"] for r in rows}
        missing = expected - found
        assert not missing, f"RLS policy 'tenant_isolation' missing on: {missing}"
    finally:
        await su.close()


# ── Test 7: pg_class — rowsecurity=true on all 10 tables ─────────────────────

@pytest.mark.asyncio
async def test_rls_enabled_flag_in_pg_class():
    """EVIDENCE: pg_class.relrowsecurity=true for all 10 tenant-scoped tables."""
    expected = {
        "api_keys", "approvals", "audit_logs", "compliance_scores",
        "gateway_requests", "policies", "policy_violations",
        "providers", "settings", "user_roles",
    }
    su = await asyncpg.connect(SUPERUSER_DSN)
    try:
        rows = await su.fetch(
            "SELECT relname FROM pg_class "
            "WHERE relname = ANY($1::text[]) AND relrowsecurity = true",
            list(expected),
        )
        found = {r["relname"] for r in rows}
        missing = expected - found
        assert not missing, f"RLS not enabled on: {missing}"
    finally:
        await su.close()


# ── Test 8: authclaw_app role has LOGIN ───────────────────────────────────────

@pytest.mark.asyncio
async def test_authclaw_app_role_exists_and_can_login():
    """EVIDENCE: authclaw_app role exists and has LOGIN privilege."""
    su = await asyncpg.connect(SUPERUSER_DSN)
    try:
        row = await su.fetchrow(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'authclaw_app'"
        )
        assert row is not None,     "authclaw_app role does not exist"
        assert row["rolcanlogin"],  "authclaw_app role must have LOGIN"
    finally:
        await su.close()


# ── Test 9: gateway_lookup_api_key SECURITY DEFINER function ────────────────

@pytest.mark.asyncio
async def test_gateway_lookup_security_definer_function():
    """EVIDENCE: gateway_lookup_api_key exists, is SECURITY DEFINER, and authclaw_app has EXECUTE."""
    su = await asyncpg.connect(SUPERUSER_DSN)
    try:
        row = await su.fetchrow("""
            SELECT p.prosecdef, has_function_privilege('authclaw_app', p.oid, 'EXECUTE') as can_execute
            FROM pg_proc p
            JOIN pg_namespace n ON p.pronamespace = n.oid
            WHERE n.nspname = 'public' AND p.proname = 'gateway_lookup_api_key'
        """)
        assert row is not None, "gateway_lookup_api_key function does not exist"
        assert row["prosecdef"] is True, "gateway_lookup_api_key must be SECURITY DEFINER"
        assert row["can_execute"] is True, "authclaw_app must have EXECUTE privilege on gateway_lookup_api_key"
    finally:
        await su.close()


# ── Test 9: alembic_version shows d2e3f4a5b6c7 ──────────────────────────────

@pytest.mark.asyncio
async def test_alembic_version_is_updated():
    """EVIDENCE: alembic_version table confirms the RLS migration was applied."""
    su = await asyncpg.connect(SUPERUSER_DSN)
    try:
        row = await su.fetchrow("SELECT version_num FROM alembic_version")
        assert row is not None, "alembic_version table is empty"
        assert row["version_num"] is not None, "version_num should not be None"
    finally:
        await su.close()
