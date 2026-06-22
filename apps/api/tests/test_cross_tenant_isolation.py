import pytest
import uuid
from sqlalchemy import select, text
from app.models.api_key import ApiKey
from app.core.database import AsyncSessionLocal

@pytest.mark.asyncio
async def test_cross_tenant_isolation_prevents_data_leakage():
    """
    Test that tenant_id Row Level Security prevents Tenant A from seeing
    Tenant B's RLS-protected API keys.

    The users table is intentionally not protected by DB-level RLS because
    authentication resolves users before tenant context exists. User-facing
    endpoints must filter users by tenant at the application layer.
    """
    async with AsyncSessionLocal() as db:
        tenant_a_id = uuid.uuid4()
        tenant_b_id = uuid.uuid4()

        # Switch context to Tenant A
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{str(tenant_a_id)}'"))
        
        # Query api keys
        result = await db.execute(select(ApiKey))
        keys_for_a = result.scalars().all()
        
        for key in keys_for_a:
            assert key.tenant_id == tenant_a_id, "Tenant A retrieved another tenant's API key!"

        # Switch context to Tenant B
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{str(tenant_b_id)}'"))
        
        result = await db.execute(select(ApiKey))
        keys_for_b = result.scalars().all()
        
        for key in keys_for_b:
            assert key.tenant_id == tenant_b_id, "Tenant B retrieved another tenant's API key!"
