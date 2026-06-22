import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import verify_password

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == 'root.test1@gmail.com'))
        user = result.scalars().first()
        if user:
            print(f"User found. Password hash matches: {verify_password('root@123', user.password_hash)}")
        else:
            print('User not found')

if __name__ == '__main__':
    asyncio.run(main())

if __name__ == '__main__':
    asyncio.run(main())
