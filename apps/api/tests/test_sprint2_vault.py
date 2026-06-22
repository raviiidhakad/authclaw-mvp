"""
AuthClaw Sprint 2 — Vault Credential Service Tests
----------------------------------------------------
Tests VaultCredentialService using unittest.mock to patch hvac.Client,
avoiding any dependency on a live Vault instance.

Test coverage:
  - store() writes to the correct tenant-scoped path
  - retrieve() returns the credential dict
  - delete() calls delete_metadata_and_all_versions
  - path_exists() returns True/False correctly
  - _assert_tenant_scope() blocks cross-tenant access (critical isolation test)
  - is_healthy() returns True on Vault 200, False on exception
  - Vault write failure raises RuntimeError (not raw hvac exception)
  - Vault retrieve failure raises RuntimeError
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from app.services.vault_credentials import VaultCredentialService


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tenant_id() -> uuid.UUID:
    return uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


@pytest.fixture
def integration_id() -> uuid.UUID:
    return uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


@pytest.fixture
def other_tenant_id() -> uuid.UUID:
    return uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")


@pytest.fixture
def sample_credentials() -> dict:
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_region": "us-east-1",
    }


@pytest.fixture
def svc() -> VaultCredentialService:
    """Return a VaultCredentialService with a fully mocked hvac.Client."""
    with patch("app.services.vault_credentials.hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        # Suppress _ensure_kv_mount side effects in unit tests
        mock_client.sys.list_mounted_secrets_engines.return_value = {
            "data": {"secret/": {}}
        }

        service = VaultCredentialService()
        service._client = mock_client
        yield service


# ── Path construction ──────────────────────────────────────────────────────────

class TestPathConstruction:
    def test_make_path_format(self, svc, tenant_id, integration_id):
        path = svc._make_path(tenant_id, integration_id)
        assert path == (
            f"authclaw/tenants/{tenant_id}/integrations/{integration_id}"
        )

    def test_tenant_prefix_format(self, svc, tenant_id):
        prefix = svc._tenant_path_prefix(tenant_id)
        assert prefix == f"authclaw/tenants/{tenant_id}/"

    def test_path_starts_with_tenant_prefix(self, svc, tenant_id, integration_id):
        path = svc._make_path(tenant_id, integration_id)
        assert path.startswith(svc._tenant_path_prefix(tenant_id))


# ── Tenant isolation: _assert_tenant_scope ────────────────────────────────────

class TestTenantIsolation:
    """
    CRITICAL: Every retrieve/delete/path_exists call must be rejected
    if the vault_reference_id does not belong to the requesting tenant.
    """

    def test_valid_path_does_not_raise(self, svc, tenant_id, integration_id):
        valid_path = svc._make_path(tenant_id, integration_id)
        # Should not raise
        svc._assert_tenant_scope(tenant_id, valid_path)

    def test_wrong_tenant_raises_permission_error(
        self, svc, tenant_id, other_tenant_id, integration_id
    ):
        """Path built for tenant A must be rejected when queried as tenant B."""
        path_for_other_tenant = svc._make_path(other_tenant_id, integration_id)
        with pytest.raises(PermissionError, match="does not belong to tenant"):
            svc._assert_tenant_scope(tenant_id, path_for_other_tenant)

    def test_arbitrary_path_raises_permission_error(self, svc, tenant_id):
        """A completely arbitrary path must be rejected."""
        with pytest.raises(PermissionError):
            svc._assert_tenant_scope(tenant_id, "some/arbitrary/path")

    def test_path_with_tenant_id_in_leaf_raises(self, svc, tenant_id, other_tenant_id):
        """tenant_id appearing in leaf (not prefix) must still be rejected."""
        tricky_path = f"authclaw/tenants/{other_tenant_id}/integrations/{tenant_id}"
        with pytest.raises(PermissionError):
            svc._assert_tenant_scope(tenant_id, tricky_path)


# ── store() ───────────────────────────────────────────────────────────────────

class TestStore:
    @pytest.mark.asyncio
    async def test_store_writes_to_correct_path(
        self, svc, tenant_id, integration_id, sample_credentials
    ):
        ref = await svc.store(tenant_id, integration_id, sample_credentials)

        expected_path = svc._make_path(tenant_id, integration_id)
        assert ref == expected_path

        svc._client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
            path=expected_path,
            secret=sample_credentials,
            mount_point=svc._mount,
        )

    @pytest.mark.asyncio
    async def test_store_returns_vault_reference_id(
        self, svc, tenant_id, integration_id, sample_credentials
    ):
        ref = await svc.store(tenant_id, integration_id, sample_credentials)
        # The returned string must be usable as vault_reference_id in Postgres
        assert isinstance(ref, str)
        assert str(tenant_id) in ref
        assert str(integration_id) in ref

    @pytest.mark.asyncio
    async def test_store_vault_failure_raises_runtime_error(
        self, svc, tenant_id, integration_id, sample_credentials
    ):
        svc._client.secrets.kv.v2.create_or_update_secret.side_effect = (
            Exception("Vault connection refused")
        )
        with pytest.raises(RuntimeError, match="Failed to store integration credentials"):
            await svc.store(tenant_id, integration_id, sample_credentials)


# ── retrieve() ────────────────────────────────────────────────────────────────

class TestRetrieve:
    @pytest.fixture
    def valid_ref(self, svc, tenant_id, integration_id) -> str:
        return svc._make_path(tenant_id, integration_id)

    @pytest.mark.asyncio
    async def test_retrieve_returns_credentials(
        self, svc, tenant_id, valid_ref, sample_credentials
    ):
        svc._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": sample_credentials}
        }
        result = await svc.retrieve(tenant_id, valid_ref)
        assert result == sample_credentials

    @pytest.mark.asyncio
    async def test_retrieve_calls_correct_path(
        self, svc, tenant_id, valid_ref, sample_credentials
    ):
        svc._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": sample_credentials}
        }
        await svc.retrieve(tenant_id, valid_ref)
        svc._client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path=valid_ref,
            mount_point=svc._mount,
            raise_on_deleted_version=True,
        )

    @pytest.mark.asyncio
    async def test_retrieve_cross_tenant_blocked(
        self, svc, tenant_id, other_tenant_id, integration_id
    ):
        """retrieve() must block before touching Vault if tenant mismatch."""
        other_ref = svc._make_path(other_tenant_id, integration_id)
        with pytest.raises(PermissionError):
            await svc.retrieve(tenant_id, other_ref)
        # Vault must NOT have been called
        svc._client.secrets.kv.v2.read_secret_version.assert_not_called()

    @pytest.mark.asyncio
    async def test_retrieve_invalid_path_raises_runtime_error(
        self, svc, tenant_id, valid_ref
    ):
        import hvac.exceptions
        svc._client.secrets.kv.v2.read_secret_version.side_effect = (
            hvac.exceptions.InvalidPath("not found")
        )
        with pytest.raises(RuntimeError, match="Vault path not found"):
            await svc.retrieve(tenant_id, valid_ref)


# ── delete() ──────────────────────────────────────────────────────────────────

class TestDelete:
    @pytest.fixture
    def valid_ref(self, svc, tenant_id, integration_id) -> str:
        return svc._make_path(tenant_id, integration_id)

    @pytest.mark.asyncio
    async def test_delete_calls_delete_metadata(self, svc, tenant_id, valid_ref):
        await svc.delete(tenant_id, valid_ref)
        svc._client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
            path=valid_ref,
            mount_point=svc._mount,
        )

    @pytest.mark.asyncio
    async def test_delete_cross_tenant_blocked(
        self, svc, tenant_id, other_tenant_id, integration_id
    ):
        other_ref = svc._make_path(other_tenant_id, integration_id)
        with pytest.raises(PermissionError):
            await svc.delete(tenant_id, other_ref)
        svc._client.secrets.kv.v2.delete_metadata_and_all_versions.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_vault_failure_raises_runtime_error(
        self, svc, tenant_id, valid_ref
    ):
        svc._client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = (
            Exception("Vault timeout")
        )
        with pytest.raises(RuntimeError, match="Failed to delete integration credentials"):
            await svc.delete(tenant_id, valid_ref)


# ── path_exists() ─────────────────────────────────────────────────────────────

class TestPathExists:
    @pytest.fixture
    def valid_ref(self, svc, tenant_id, integration_id) -> str:
        return svc._make_path(tenant_id, integration_id)

    @pytest.mark.asyncio
    async def test_path_exists_true_when_readable(self, svc, tenant_id, valid_ref, sample_credentials):
        svc._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": sample_credentials}
        }
        assert await svc.path_exists(tenant_id, valid_ref) is True

    @pytest.mark.asyncio
    async def test_path_exists_false_when_not_found(self, svc, tenant_id, valid_ref):
        import hvac.exceptions
        svc._client.secrets.kv.v2.read_secret_version.side_effect = (
            hvac.exceptions.InvalidPath("not found")
        )
        assert await svc.path_exists(tenant_id, valid_ref) is False

    @pytest.mark.asyncio
    async def test_path_exists_cross_tenant_blocked(
        self, svc, tenant_id, other_tenant_id, integration_id
    ):
        other_ref = svc._make_path(other_tenant_id, integration_id)
        with pytest.raises(PermissionError):
            await svc.path_exists(tenant_id, other_ref)


# ── is_healthy() ──────────────────────────────────────────────────────────────

class TestIsHealthy:
    @pytest.mark.asyncio
    async def test_healthy_vault_returns_true(self, svc):
        svc._client.sys.read_health_status.return_value = {
            "initialized": True,
            "sealed": False,
        }
        assert await svc.is_healthy() is True

    @pytest.mark.asyncio
    async def test_sealed_vault_returns_false(self, svc):
        svc._client.sys.read_health_status.return_value = {
            "initialized": True,
            "sealed": True,
        }
        assert await svc.is_healthy() is False

    @pytest.mark.asyncio
    async def test_vault_exception_returns_false(self, svc):
        svc._client.sys.read_health_status.side_effect = Exception("Connection refused")
        assert await svc.is_healthy() is False
