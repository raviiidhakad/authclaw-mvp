import asyncio
import httpx
import jwt
from app.core.config import settings

async def main():
    token = jwt.encode({"sub": "9ca7ee58-c743-44a3-9bed-dfb3bf141a26", "type": "access"}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    async with httpx.AsyncClient() as client:
        for i in range(10):
            r = await client.get("http://localhost:8000/api/v1/approvals?_t=123", headers={"Authorization": f"Bearer {token}"})
            data = r.json()
            print(f"Request {i}: Status {r.status_code}, Items: {len(data) if isinstance(data, list) else data}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
