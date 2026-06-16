import asyncio
import json
from app.core.database import AsyncSessionLocal
from app.core.engine.compliance import ComplianceRuleChecker

async def get_score():
    async with AsyncSessionLocal() as db:
        checker = ComplianceRuleChecker(db, '11111111-1111-1111-1111-111111111111')
        res = await checker.calculate_all()
        print(json.dumps(res, indent=2, default=str))

asyncio.run(get_score())
