import asyncio
from app.core.database import AsyncSessionLocal
from sqlalchemy import text
async def main():
    async with AsyncSessionLocal() as db:
        await db.execute(text("ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;"))
        await db.execute(text("DROP POLICY IF EXISTS tenant_isolation ON api_keys;"))
        await db.commit()
        print("Dropped RLS on api_keys")
asyncio.run(main())
