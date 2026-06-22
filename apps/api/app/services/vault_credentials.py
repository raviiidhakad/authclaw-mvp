"""
AuthClaw Sprint 2 — Vault Credential Service
---------------------------------------------
Stores and retrieves cloud integration credentials (AWS keys, GitHub PATs,
GCP service account JSON) in HashiCorp Vault KV v2.

Design principles:
  • Raw credentials NEVER touch PostgreSQL. The only Postgres column is
    `vault_reference_id`, which contains the KV path returned by `store()`.
  • Path structure enforces tenant isolation at the Vault level:
        {mount}/data/{prefix}/{tenant_id}/integrations/{integration_id}
    A credential can only be retrieved if the caller supplies the matching
    tenant_id — `_assert_tenant_scope()` enforces this before every read.
  • `hvac` is synchronous; all blocking calls are wrapped in
    `asyncio.to_thread()` so the FastAPI event loop is never blocked.
  • DEL path uses `delete_metadata_and_all_versions` — ensures no version
    history of credentials remains in Vault after integration deletion.
  • KV v2 is auto-enabled in non-production environments (mirrors the
    Transit auto-enable pattern in app/core/encryption/vault.py).

Vault path format:
    mount  : settings.VAULT_INTEGRATION_MOUNT   (default: "secret")
    path   : {VAULT_INTEGRATION_PATH_PREFIX}/{tenant_id}/integrations/{integration_id}
             e.g. "authclaw/tenants/abc-123/integrations/def-456"

Cross-tenant isolation proof:
    - `store(tenant_id, integration_id, ...)` writes to path containing tenant_id.
    - `retrieve(tenant_id, vault_reference_id)` calls _assert_tenant_scope(),
      which verifies vault_reference_id starts with the expected tenant prefix.
    - If a caller supplies a vault_reference_id belonging to a different tenant,
      _assert_tenant_scope() raises PermissionError before any Vault API call.
    - Even if _assert_tenant_scope() were bypassed, the Vault policy layer
      (in production) would reject the read via ACL path matching.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any, Dict, Optional

import hvac
import hvac.exceptions

from app.core.config import settings

logger = logging.getLogger(__name__)


class VaultCredentialService:
    """
    Manages cloud integration credentials in Vault KV v2.

    Usage:
        svc = VaultCredentialService()

        # Store credentials — returns vault_reference_id for Postgres
        ref = await svc.store(tenant_id, integration_id, {"aws_access_key_id": "...", ...})

        # Retrieve credentials — enforces tenant isolation
        creds = await svc.retrieve(tenant_id, ref)

        # Delete on integration removal
        await svc.delete(tenant_id, ref)

        # Validate credentials path belongs to tenant (read-only check)
        is_valid = await svc.path_exists(tenant_id, ref)
    """

    def __init__(self) -> None:
        vault_url = settings.VAULT_ADDR
        vault_token = settings.VAULT_TOKEN
        self._mount = settings.VAULT_INTEGRATION_MOUNT
        self._prefix = settings.VAULT_INTEGRATION_PATH_PREFIX
        self._client = hvac.Client(url=vault_url, token=vault_token)
        self._ensure_kv_mount()

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _ensure_kv_mount(self) -> None:
        """
        Auto-enable KV v2 mount in development environments.
        Mirrors the Transit auto-enable in VaultEncryptionProvider.
        Silently skips if already enabled or in a production environment.
        """
        if os.getenv("APP_ENV", "development") == "production":
            return
        try:
            backends = self._client.sys.list_mounted_secrets_engines()["data"]
            mount_key = f"{self._mount}/"
            if mount_key not in backends:
                self._client.sys.enable_secrets_engine(
                    backend_type="kv",
                    path=self._mount,
                    options={"version": "2"},
                )
                logger.info(
                    "VaultCredentialService: enabled KV v2 at mount '%s'.",
                    self._mount,
                )
        except Exception as exc:
            # Non-fatal in dev — Vault may not be running
            logger.warning("VaultCredentialService: could not ensure KV mount: %s", exc)

    def _make_path(self, tenant_id: uuid.UUID, integration_id: uuid.UUID) -> str:
        """
        Build the canonical Vault KV path for an integration credential.

        Format: {prefix}/{tenant_id}/integrations/{integration_id}
        Example: authclaw/tenants/abc-123/integrations/def-456
        """
        return f"{self._prefix}/{tenant_id}/integrations/{integration_id}"

    def _tenant_path_prefix(self, tenant_id: uuid.UUID) -> str:
        """Return the expected path prefix for all integrations of a tenant."""
        return f"{self._prefix}/{tenant_id}/"

    def _assert_tenant_scope(
        self, tenant_id: uuid.UUID, vault_reference_id: str
    ) -> None:
        """
        Verify vault_reference_id belongs to the given tenant before any Vault call.

        This is the application-layer guard for cross-tenant isolation.
        Even if Vault ACLs are misconfigured, this check prevents accidental
        cross-tenant credential access.

        Raises:
            PermissionError: If the path does not start with the tenant's prefix.
        """
        expected_prefix = self._tenant_path_prefix(tenant_id)
        if not vault_reference_id.startswith(expected_prefix):
            logger.error(
                "Cross-tenant Vault access attempt blocked. "
                "tenant_id=%s vault_reference_id=%s expected_prefix=%s",
                tenant_id,
                vault_reference_id,
                expected_prefix,
            )
            raise PermissionError(
                f"vault_reference_id does not belong to tenant {tenant_id}. "
                "Access denied."
            )

    # ── Sync helpers (called inside asyncio.to_thread) ────────────────────────

    def _sync_store(
        self,
        path: str,
        credentials: Dict[str, Any],
    ) -> None:
        """Write credentials dict to Vault KV v2."""
        self._client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=credentials,
            mount_point=self._mount,
        )
        logger.info("VaultCredentialService: stored credentials at path '%s'.", path)

    def _sync_retrieve(self, path: str) -> Dict[str, Any]:
        """Read credentials dict from Vault KV v2 (latest version)."""
        response = self._client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=self._mount,
            raise_on_deleted_version=True,
        )
        return response["data"]["data"]

    def _sync_delete(self, path: str) -> None:
        """Permanently delete all versions + metadata for a KV path."""
        self._client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=path,
            mount_point=self._mount,
        )
        logger.info("VaultCredentialService: deleted all versions at path '%s'.", path)

    def _sync_path_exists(self, path: str) -> bool:
        """Return True if the KV path has at least one non-deleted version."""
        try:
            self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._mount,
                raise_on_deleted_version=True,
            )
            return True
        except hvac.exceptions.InvalidPath:
            return False

    # ── Public async API ───────────────────────────────────────────────────────

    async def store(
        self,
        tenant_id: uuid.UUID,
        integration_id: uuid.UUID,
        credentials: Dict[str, Any],
    ) -> str:
        """
        Write credentials to Vault KV v2 under the tenant-scoped path.

        Args:
            tenant_id:       Owning tenant UUID.
            integration_id:  CloudIntegration UUID (used as the KV leaf path).
            credentials:     Provider-specific credential dict. Never logged.

        Returns:
            vault_reference_id (str): The KV path. Store this in Postgres.

        Raises:
            RuntimeError: If the Vault write fails after the call.
        """
        path = self._make_path(tenant_id, integration_id)
        try:
            await asyncio.to_thread(self._sync_store, path, credentials)
            return path
        except Exception as exc:
            logger.error(
                "VaultCredentialService.store failed for tenant=%s integration=%s: %s",
                tenant_id, integration_id, exc,
            )
            raise RuntimeError(
                f"Failed to store integration credentials in Vault: {exc}"
            ) from exc

    async def retrieve(
        self,
        tenant_id: uuid.UUID,
        vault_reference_id: str,
    ) -> Dict[str, Any]:
        """
        Retrieve credentials from Vault KV v2.

        Enforces tenant isolation by asserting the path prefix before
        making any Vault API call.

        Args:
            tenant_id:          Owning tenant UUID (used for isolation check).
            vault_reference_id: KV path returned by `store()`.

        Returns:
            credentials dict.

        Raises:
            PermissionError:  If vault_reference_id does not belong to tenant_id.
            RuntimeError:     If the Vault read fails.
        """
        self._assert_tenant_scope(tenant_id, vault_reference_id)
        try:
            return await asyncio.to_thread(self._sync_retrieve, vault_reference_id)
        except hvac.exceptions.InvalidPath as exc:
            raise RuntimeError(
                f"Vault path not found: {vault_reference_id}"
            ) from exc
        except Exception as exc:
            logger.error(
                "VaultCredentialService.retrieve failed for tenant=%s path=%s: %s",
                tenant_id, vault_reference_id, exc,
            )
            raise RuntimeError(
                f"Failed to retrieve integration credentials from Vault: {exc}"
            ) from exc

    async def delete(
        self,
        tenant_id: uuid.UUID,
        vault_reference_id: str,
    ) -> None:
        """
        Permanently delete all credential versions from Vault.
        Called when a CloudIntegration is deleted by a tenant.

        Raises:
            PermissionError:  If vault_reference_id does not belong to tenant_id.
            RuntimeError:     If the Vault delete fails.
        """
        self._assert_tenant_scope(tenant_id, vault_reference_id)
        try:
            await asyncio.to_thread(self._sync_delete, vault_reference_id)
        except Exception as exc:
            logger.error(
                "VaultCredentialService.delete failed for tenant=%s path=%s: %s",
                tenant_id, vault_reference_id, exc,
            )
            raise RuntimeError(
                f"Failed to delete integration credentials from Vault: {exc}"
            ) from exc

    async def path_exists(
        self,
        tenant_id: uuid.UUID,
        vault_reference_id: str,
    ) -> bool:
        """
        Return True if the path exists and has a readable version.
        Used by the integration validation flow to confirm credentials
        were written successfully before marking the integration ACTIVE.

        Raises:
            PermissionError: If vault_reference_id does not belong to tenant_id.
        """
        self._assert_tenant_scope(tenant_id, vault_reference_id)
        return await asyncio.to_thread(self._sync_path_exists, vault_reference_id)

    async def is_healthy(self) -> bool:
        """
        Ping the Vault server and verify authentication.
        Used by GET /health/connectors.
        Returns False instead of raising — health checks must never crash.
        """
        try:
            result = await asyncio.to_thread(self._client.sys.read_health_status)
            # hvac returns a response object or dict depending on version
            if isinstance(result, dict):
                return result.get("initialized", False) and not result.get("sealed", True)
            # requests.Response
            return result.status_code in (200, 429)  # 429 = standby (still healthy)
        except Exception as exc:
            logger.warning("VaultCredentialService health check failed: %s", exc)
            return False


# ── Module-level singleton ──────────────────────────────────────────────────
# Instantiated once; reused by ConnectorFactory and integration endpoints.
vault_credential_service = VaultCredentialService()
