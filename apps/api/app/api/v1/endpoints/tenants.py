import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException
from app.models.tenant import Tenant
from app.models.user import User
from app.models.policy import Policy
from app.models.api_key import ApiKey
from app.models.gateway import GatewayRequest, RequestStatus
from app.schemas.tenant import TenantResponse, TenantUpdate, TenantStats

router = APIRouter()

@router.get("", response_model=TenantResponse)
async def get_tenant_details(
    tenant: Tenant = Depends(get_current_tenant),
    _user: User = Depends(require_roles(["owner", "admin", "analyst", "auditor", "viewer"]))
):
    """
    Retrieve the current tenant's details.
    """
    return tenant


@router.patch("", response_model=TenantResponse)
async def update_tenant_details(
    body: TenantUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"]))
):
    """
    Update tenant details.
    """
    if body.name is not None:
        tenant.name = body.name
    if body.status is not None:
        tenant.status = body.status

    await db.flush()
    await db.refresh(tenant)
    await db.commit()

    # Sprint 1: Invalidate Redis policy cache for this tenant on any status change.
    # (Covers tenant deactivation, rename, and future policy-affecting tenant changes.)
    from app.core.policy.cache import policy_cache
    await policy_cache.invalidate(tenant.id)

    return tenant



@router.get("/stats", response_model=TenantStats)
async def get_tenant_stats(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "analyst", "auditor", "viewer"]))
):
    """
    Retrieve statistics for the tenant.
    """
    # Count Users
    user_count_q = select(func.count(User.id)).where(User.tenant_id == tenant.id)
    user_count = (await db.execute(user_count_q)).scalar() or 0
    
    # Count Policies
    policy_count_q = select(func.count(Policy.id)).where(Policy.tenant_id == tenant.id)
    policy_count = (await db.execute(policy_count_q)).scalar() or 0
    
    # Count API Keys
    api_key_count_q = select(func.count(ApiKey.id)).where(ApiKey.tenant_id == tenant.id)
    api_key_count = (await db.execute(api_key_count_q)).scalar() or 0
    
    # Count Gateway Requests
    total_requests_q = select(func.count(GatewayRequest.id)).where(GatewayRequest.tenant_id == tenant.id)
    total_requests = (await db.execute(total_requests_q)).scalar() or 0
    
    # Count Blocked Requests
    blocked_requests_q = select(func.count(GatewayRequest.id)).where(
        GatewayRequest.tenant_id == tenant.id,
        GatewayRequest.status == RequestStatus.blocked
    )
    blocked_requests = (await db.execute(blocked_requests_q)).scalar() or 0
    
    return TenantStats(
        user_count=user_count,
        policy_count=policy_count,
        api_key_count=api_key_count,
        total_requests=total_requests,
        blocked_requests=blocked_requests
    )
