import asyncio
from app.core.database import AsyncSessionLocal
from sqlalchemy import text
async def main():
    async with AsyncSessionLocal() as db:
        await db.execute(text("SET row_security = off;"))
        res = await db.execute(text("SELECT id, name FROM api_keys"))
        print(res.fetchall())
asyncio.run(main())
