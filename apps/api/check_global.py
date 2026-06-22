import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal

async def main():
    async with AsyncSessionLocal() as db:
        res1 = await db.execute(text("SELECT id, name FROM tenants"))
        print("Tenants:", res1.fetchall())
        res2 = await db.execute(text("SELECT id, tenant_id, type FROM providers"))
        print("Providers:", res2.fetchall())

if __name__ == "__main__":
    asyncio.run(main())
