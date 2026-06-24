from __future__ import annotations

import uuid

from app.core.encryption import decrypt_value
from app.models.provider import Provider
from app.services.vault_credentials import vault_credential_service


def is_vault_provider_reference(value: str | None) -> bool:
    return bool(value and value.startswith("authclaw/tenants/") and "/integrations/" in value)


async def store_provider_api_key(
    tenant_id: uuid.UUID,
    provider_id: uuid.UUID,
    api_key: str,
) -> str:
    return await vault_credential_service.store(
        tenant_id=tenant_id,
        integration_id=provider_id,
        credentials={"api_key": api_key},
    )


async def retrieve_provider_api_key(provider: Provider) -> str:
    stored_value = provider.api_key_encrypted
    if is_vault_provider_reference(stored_value):
        credentials = await vault_credential_service.retrieve(provider.tenant_id, stored_value)
        api_key = credentials.get("api_key")
        if not isinstance(api_key, str) or not api_key:
            raise RuntimeError("Provider credential is missing from Vault.")
        return api_key
    return decrypt_value(stored_value)


async def delete_provider_api_key(tenant_id: uuid.UUID, stored_value: str | None) -> None:
    if is_vault_provider_reference(stored_value):
        await vault_credential_service.delete(tenant_id, stored_value)
