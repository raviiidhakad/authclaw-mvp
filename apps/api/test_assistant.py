import asyncio
from app.core.database import AsyncSessionLocal
from app.models.user import User
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).limit(1))
        user = result.scalars().first()
        tenant_id = user.tenant_id
        
        # Set RLS
        from sqlalchemy import text
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tid, false)"), {"tid": str(tenant_id)})

        from app.core.engine.assistant import run_assistant_chat
        
        messages = [{"role": "user", "content": "What policies do we have?"}]
        try:
            reply = await run_assistant_chat(messages, tenant_id, db)
            print("REPLY:", reply)
        except Exception as e:
            print("ERROR:", str(e))

if __name__ == "__main__":
    asyncio.run(main())
