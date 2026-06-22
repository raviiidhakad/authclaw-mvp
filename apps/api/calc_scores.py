import asyncio
import httpx
from app.core.database import AsyncSessionLocal
from app.models.user import User
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(User).limit(1))
        user = res.scalars().first()
        tenant_id = user.tenant_id

        # Since /calculate requires auth, let's just call the internal function
        from app.core.engine.compliance import ComplianceRuleChecker
        checker = ComplianceRuleChecker(db, tenant_id)
        results = await checker.calculate_all()

        from app.models.compliance import ComplianceScore
        from datetime import datetime
        persisted = {}
        for framework_name, result_data in results.items():
            score_record = ComplianceScore(
                tenant_id=tenant_id,
                framework=framework_name,
                score=result_data["score"],
                critical_violations=result_data["critical_violations_30d"],
                policy_failures=result_data["violations_30d"],
                security_findings=sum(1 for v in result_data["checks"].values() if not v),
                breakdown=result_data["checks"],
                calculated_at=datetime.utcnow(),
            )
            db.add(score_record)
        await db.commit()
        print("Calculated compliance scores!")

asyncio.run(main())
