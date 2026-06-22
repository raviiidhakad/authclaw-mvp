import asyncio
from app.core.database import SessionLocal
from app.core.engine.agent import run_security_scan_agent
from app.models.tenant import Tenant
from sqlalchemy import select

async def test_scan():
    async with SessionLocal() as session:
        result = await session.execute(select(Tenant))
        tenant = result.scalars().first()
        if not tenant:
            print("No tenant found.")
            return

        print(f"Testing scan for tenant {tenant.id}...")
        res = await run_security_scan_agent(str(tenant.id), "AWS", session)
        print("Agent Result:", res)

if __name__ == "__main__":
    asyncio.run(test_scan())
