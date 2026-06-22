import asyncio
import httpx
from sqlalchemy import text
from app.core.database import AsyncSessionLocal

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(text("SELECT id, status, model, provider_status_code, error_message FROM gateway_requests ORDER BY created_at DESC LIMIT 5"))
        print(res.fetchall())
        
asyncio.run(main())
