import asyncio
import httpx
import jwt
from app.core.config import settings

async def main():
    token = jwt.encode({"sub": "9ca7ee58-c743-44a3-9bed-dfb3bf141a26", "type": "access"}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    async with httpx.AsyncClient() as client:
        r = await client.post(
        "http://localhost:8000/api/v1/agent/scan", 
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "AWS"}
    )
        print(f"Status: {r.status_code}")
        print(f"Body: {r.text[:500]}")

if __name__ == "__main__":
    asyncio.run(main())
