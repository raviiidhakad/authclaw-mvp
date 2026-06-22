import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.tenant import Tenant
from app.models.user import User
from app.models.provider import Provider

async def main():
    async with AsyncSessionLocal() as db:
        # Get tenant and user
        result = await db.execute(select(User).limit(1))
        user = result.scalars().first()
        tenant_id = user.tenant_id

        # Set RLS
        from sqlalchemy import text
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tid, false)"), {"tid": str(tenant_id)})

        # Create provider
        from app.core.encryption import encrypt_value
        provider = Provider(
            tenant_id=tenant_id,
            name="Direct DB Provider",
            type="openai",
            api_key_encrypted=encrypt_value("test_key"),
            config={"base_url": "https://api.openai.com/v1"},
            is_active=True
        )
        db.add(provider)
        await db.commit()

        # Try to refresh!
        try:
            await db.refresh(provider)
            print("Successfully refreshed! Provider ID:", provider.id)
        except Exception as e:
            print("Failed to refresh:", type(e).__name__, str(e))

if __name__ == "__main__":
    asyncio.run(main())
