import asyncio
import httpx
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
import jwt
from app.core.config import settings

async def main():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.tenant_id == '38aea89f-55e6-48d9-baf4-cf14b7090e4e'))
        user = result.scalars().first()
        
    token = jwt.encode(
        {"sub": str(user.id), "type": "access"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.get("/api/v1/approvals", headers={"Authorization": f"Bearer {token}"})
        data = response.json()
        if isinstance(data, list):
            print(f"Returned {len(data)} items")
            for item in data[:3]:
                print(f" - {item['id']} / {item['status']}")
        else:
            print(f"Returned {data}")

if __name__ == "__main__":
    asyncio.run(main())
