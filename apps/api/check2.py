import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, text

async def run():
    engine = create_async_engine('postgresql+asyncpg://postgres:password@authclawproject-db-1:5432/authclaw')
    Session = sessionmaker(engine, class_=AsyncSession)
    async with Session() as session:
        res = await session.execute(text('SELECT tenant_id, type, is_active FROM providers'))
        print(res.fetchall())
asyncio.run(run())
