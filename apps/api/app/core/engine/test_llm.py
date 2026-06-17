import asyncio
import os
import json
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.engine.assistant import run_assistant_chat

async def main():
    engine = create_async_engine(os.environ["DATABASE_URL"])
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    tenant_id = uuid.UUID("38aea89f-55e6-48d9-baf4-cf14b7090e4e")
    
    messages = [
        {"role": "user", "content": "Please propose a terraform remediation for password sharing issue."}
    ]
    
    async with async_session() as db:
        response = await run_assistant_chat(messages, tenant_id, db)
        print(response)

asyncio.run(main())
