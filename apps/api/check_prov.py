import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.provider import Provider
async def run():
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(Provider))
        for p in res.scalars().all():
            print(p.is_active, p.type, str(p.tenant_id))
asyncio.run(run())
