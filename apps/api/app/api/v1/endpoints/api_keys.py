import secrets
import hashlib
import uuid
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.dependencies import get_db, get_current_tenant, get_current_user, require_roles
from app.core.exceptions import NotFoundException
from app.models.api_key import ApiKey
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.api_key import ApiKeyCreate, ApiKeyResponse, ApiKeyCreateResponse

router = APIRouter()

@router.get("", response_model=List[ApiKeyResponse])
async def list_api_keys(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"]))
):
    """
    List all API keys for the current tenant.
    """
    result = await db.execute(
        select(ApiKey).where(ApiKey.tenant_id == tenant.id).order_by(ApiKey.created_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=ApiKeyCreateResponse, status_code=201)
async def create_api_key(
    body: ApiKeyCreate,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _check_role: User = Depends(require_roles(["owner", "admin"]))
):
    """
    Create a new API key. The raw key is returned ONLY once in the response.
    """
    raw_key = f"ac_{secrets.token_hex(24)}"
    key_prefix = raw_key[:12]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    api_key = ApiKey(
        tenant_id=tenant.id,
        user_id=current_user.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=body.name,
        scope=body.scope,
        expires_at=body.expires_at,
        is_active=True
    )
    
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    # Inject the raw key into the response model
    response_data = ApiKeyCreateResponse.model_validate(api_key)
    response_data.raw_key = raw_key
    
    return response_data


@router.delete("/{api_key_id}", status_code=204)
async def delete_api_key(
    api_key_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"]))
):
    """
    Delete (revoke) an API key.
    """
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == api_key_id, ApiKey.tenant_id == tenant.id)
    )
    api_key = result.scalars().first()
    
    if not api_key:
        raise NotFoundException(detail="API key not found")
        
    await db.delete(api_key)
    await db.commit()
