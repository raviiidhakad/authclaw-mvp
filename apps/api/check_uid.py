import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
async def run():
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(User).where(User.email == 'root.test1@gmail.com'))
        user = res.scalars().first()
        if user: print(user.id)
asyncio.run(run())
