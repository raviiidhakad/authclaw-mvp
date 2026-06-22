import asyncio
from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.models.provider import Provider
from app.models.user import User

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(User).limit(1))
        user = res.scalars().first()
        if user:
            await db.execute(text("SELECT set_config('app.current_tenant_id', :tid, false)"), {"tid": str(user.tenant_id)})
            
        res = await db.execute(select(Provider))
        import pprint
        providers = res.scalars().all()
        for p in providers:
            print(f"ID: {p.id}, Tenant: {p.tenant_id}, Name: {p.name}, Type: {p.type}, Active: {p.is_active}, Config: {p.config}")

if __name__ == "__main__":
    asyncio.run(main())
