import asyncio
from sqlalchemy import select, update
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import get_password_hash

async def main():
    async with AsyncSessionLocal() as db:
        hashed = get_password_hash('root@123')
        await db.execute(update(User).where(User.email == 'root.test1@gmail.com').values(password_hash=hashed))
        await db.commit()
        print('Password updated to root@123')

if __name__ == '__main__':
    asyncio.run(main())
