import asyncio
import httpx
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
import jwt
from app.core.config import settings

async def main():
    # 1. Get a user
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).limit(1))
        user = result.scalars().first()
        
    # 2. Generate token
    token = jwt.encode(
        {"sub": str(user.id), "type": "access"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    # 3. Hit the API 20 times
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        for i in range(20):
            response = await client.get("/api/v1/approvals", headers={"Authorization": f"Bearer {token}"})
            data = response.json()
            if isinstance(data, list):
                print(f"Request {i}: Returned {len(data)} items")
            else:
                print(f"Request {i}: Returned {data}")
            await asyncio.sleep(0.5)

if __name__ == "__main__":
    asyncio.run(main())
