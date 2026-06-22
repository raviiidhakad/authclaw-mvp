import asyncio
import hashlib
import uuid
from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.api_key import ApiKey

async def main():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(User).limit(1))
        user = res.scalars().first()
        tenant_id = user.tenant_id
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tid, false)"), {"tid": str(tenant_id)})

        key_id = uuid.uuid4()
        test_key = "ac_test_supersecret_key_12345"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        
        # Insert key if not exists
        db.add(ApiKey(
            id=key_id,
            tenant_id=tenant_id,
            user_id=user.id,
            name="Developer Gateway Key",
            key_hash=key_hash,
            key_prefix="ac_test_",
            is_active=True
        ))
        await db.commit()
        print(f"\nAPI_KEY_GENERATED: {test_key}")

if __name__ == "__main__":
    asyncio.run(main())
