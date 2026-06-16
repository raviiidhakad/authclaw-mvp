from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.models.tenant import Tenant
from app.models.setting import Setting

router = APIRouter()

@router.get("/")
async def get_settings(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve tenant settings."""
    result = await db.execute(
        select(Setting)
        .where(Setting.tenant_id == tenant.id)
    )
    settings = result.scalars().all()
    
    return {s.key: s.value for s in settings}

@router.put("/{key}")
async def update_setting(
    key: str,
    value: str,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Update a specific tenant setting."""
    result = await db.execute(
        select(Setting)
        .where(Setting.tenant_id == tenant.id, Setting.key == key)
    )
    setting = result.scalars().first()
    
    if setting:
        setting.value = value
    else:
        setting = Setting(tenant_id=tenant.id, key=key, value=value)
        db.add(setting)
        
    await db.commit()
    return {"key": key, "value": value}
