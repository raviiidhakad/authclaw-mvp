import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.policy import PolicyRule

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(PolicyRule))
        for r in res.scalars().all():
            print(f"Rule ID: {r.id}, Type: {r.rule_type}, Conditions: {r.conditions}")

asyncio.run(main())
