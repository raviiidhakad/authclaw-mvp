import asyncio
from app.core.database import AsyncSessionLocal
from app.models.tenant import Tenant
from app.models.user import User
from app.api.v1.endpoints.gateway_routes import create_gateway_route, GatewayRouteCreate
from sqlalchemy import text, select

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(User).limit(1))
        user = res.scalars().first()
        tenant_id = user.tenant_id
        
        # Set RLS
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tid, false)"), {"tid": str(tenant_id)})

        res2 = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = res2.scalars().first()

        body = GatewayRouteCreate(
            name="test route",
            description="desc",
            is_default=True,
            is_active=True,
            redaction="mask",
            provider_id=None
        )
        try:
            route = await create_gateway_route(body, tenant=tenant, db=db, current_user=user)
            print("SUCCESS", route.id)
        except Exception as e:
            print("FAILED:", str(e))

if __name__ == "__main__":
    asyncio.run(main())
