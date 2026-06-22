import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.policy import PolicyRule

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(PolicyRule))
        rule = res.scalars().first()
        if rule:
            rule.conditions = {'pii_types': ['EMAIL', 'PASSWORD', 'SSN', 'CREDIT_CARD']}
            await db.commit()
            print("Updated PolicyRule to include PASSWORD!")

asyncio.run(main())
