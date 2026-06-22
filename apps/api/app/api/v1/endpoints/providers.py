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
from app.core.encryption import encrypt_value
from app.core.exceptions import NotFoundException, BadRequestException
from app.models.provider import Provider
from app.models.user import User
from app.models.tenant import Tenant
from app.schemas.provider import (
    ProviderCreate,
    ProviderUpdate,
    ProviderResponse,
    ProviderListResponse,
)

router = APIRouter()


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
        api_key_encrypted=encrypt_value(body.api_key),
        config=body.config,
        is_active=body.is_active,
    )
    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    await db.commit()
    return provider


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
        provider.api_key_encrypted = encrypt_value(body.api_key)
    if body.config is not None:
        provider.config = body.config
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
    await db.delete(provider)
    await db.commit()
