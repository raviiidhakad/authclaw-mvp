"""
Provider CRUD endpoints.
All operations are tenant-scoped — only providers belonging to the
current user's tenant are visible.
"""
import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.api.dependencies import get_db, get_current_user, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException, BadRequestException
from app.models.provider import Provider, ProviderType
from app.models.user import User
from app.models.tenant import Tenant
from app.core.providers.factory import ProviderAdapterFactory
from app.services.provider_credentials import (
    delete_provider_api_key,
    retrieve_provider_api_key,
    store_provider_api_key,
)
from app.schemas.provider import (
    ProviderCreate,
    ProviderUpdate,
    ProviderResponse,
    ProviderListResponse,
)

router = APIRouter()

GROQ_OPENAI_BASE_URL = "https://api.groq.com/openai/v1"


# ── helpers ──────────────────────────────────────────────────────
async def _get_provider_or_404(
    provider_id: uuid.UUID,
    tenant_id: uuid.UUID,
    db: AsyncSession,
) -> Provider:
    result = await db.execute(
        select(Provider).where(
            Provider.id == provider_id,
            Provider.tenant_id == tenant_id,
        )
    )
    provider = result.scalars().first()
    if not provider:
        raise NotFoundException(detail="Provider not found")
    return provider


# ── routes ───────────────────────────────────────────────────────
@router.get("", response_model=ProviderListResponse)
async def list_providers(
    skip: int = 0,
    limit: int = 50,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    """List all providers for the current tenant."""
    count_q = select(func.count()).select_from(Provider).where(Provider.tenant_id == tenant.id)
    total = (await db.execute(count_q)).scalar() or 0

    items_q = (
        select(Provider)
        .where(Provider.tenant_id == tenant.id)
        .order_by(Provider.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    items = (await db.execute(items_q)).scalars().all()
    return ProviderListResponse(items=items, total=total)


@router.post("", response_model=ProviderResponse, status_code=201)
async def create_provider(
    body: ProviderCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"])),
):
    """Create a new AI provider configuration."""
    provider = Provider(
        tenant_id=tenant.id,
        name=body.name,
        type=body.type,
        api_key_encrypted="__pending_vault_reference__",
        config=_provider_config_with_defaults(body.type, body.config),
        is_active=body.is_active,
    )
    db.add(provider)
    await db.flush()
    provider.api_key_encrypted = await store_provider_api_key(tenant.id, provider.id, body.api_key)
    await db.flush()
    await db.refresh(provider)
    await db.commit()
    return provider


def _provider_config_with_defaults(provider_type: ProviderType, config: dict | None) -> dict:
    normalized = dict(config or {})
    if provider_type == ProviderType.groq:
        normalized.setdefault("base_url", GROQ_OPENAI_BASE_URL)
        normalized.setdefault("model", "llama3-8b-8192")
    return normalized


@router.post("/{provider_id}/validate")
async def validate_provider(
    provider_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"])),
):
    """Validate stored provider credentials without returning secret material."""
    provider = await _get_provider_or_404(provider_id, tenant.id, db)
    if not provider.is_active:
        return {"provider_id": str(provider.id), "valid": False, "error_code": "provider_disabled"}

    try:
        adapter = ProviderAdapterFactory.get_adapter(provider.type)
        await retrieve_provider_api_key(provider)
        url, headers = await adapter.get_connection_details(provider)
        request_payload = adapter.transform_request(
            {
                "model": (provider.config or {}).get("model", "llama3-8b-8192"),
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            }
        )

        import httpx

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=request_payload, headers=headers)

        if 200 <= response.status_code < 300:
            return {"provider_id": str(provider.id), "valid": True, "provider_type": provider.type.value}
        if response.status_code == 401:
            return {
                "provider_id": str(provider.id),
                "valid": False,
                "provider_type": provider.type.value,
                "error_code": "invalid_provider_credentials",
            }
        return {
            "provider_id": str(provider.id),
            "valid": False,
            "provider_type": provider.type.value,
            "error_code": f"provider_http_{response.status_code}",
        }
    except Exception:
        return {
            "provider_id": str(provider.id),
            "valid": False,
            "provider_type": provider.type.value,
            "error_code": "provider_validation_failed",
        }


@router.get("/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator"])),
):
    """Get a specific provider by ID."""
    return await _get_provider_or_404(provider_id, tenant.id, db)


@router.patch("/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: uuid.UUID,
    body: ProviderUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"])),
):
    """Update a provider's config, name, or rotate its API key."""
    provider = await _get_provider_or_404(provider_id, tenant.id, db)

    if body.name is not None:
        provider.name = body.name
    if body.api_key is not None:
        old_reference = provider.api_key_encrypted
        provider.api_key_encrypted = await store_provider_api_key(tenant.id, provider.id, body.api_key)
        await delete_provider_api_key(tenant.id, old_reference)
    if body.config is not None:
        provider.config = _provider_config_with_defaults(provider.type, body.config)
    if body.is_active is not None:
        provider.is_active = body.is_active

    await db.flush()
    await db.refresh(provider)
    await db.commit()
    return provider


@router.delete("/{provider_id}", status_code=204)
async def delete_provider(
    provider_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"])),
):
    """Delete a provider."""
    provider = await _get_provider_or_404(provider_id, tenant.id, db)
    await delete_provider_api_key(tenant.id, provider.api_key_encrypted)
    await db.delete(provider)
    await db.commit()
