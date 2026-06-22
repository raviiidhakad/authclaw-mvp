import asyncio
import httpx
from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.tenant import Tenant
from app.models.api_key import ApiKey
from app.models.provider import Provider
from app.models.gateway_route import GatewayRoute
import uuid
import datetime

async def main():
    async with AsyncSessionLocal() as db:
        # Get first user
        res = await db.execute(select(User).limit(1))
        user = res.scalars().first()
        if not user:
            print("No user found")
            return
            
        tenant_id = user.tenant_id
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tid, false)"), {"tid": str(tenant_id)})

        # Create API key
        key_id = uuid.uuid4()
        test_key = f"ac_test_{uuid.uuid4().hex}"
        import hashlib
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        
        # Insert key if not exists
        db.add(ApiKey(
            id=key_id,
            tenant_id=tenant_id,
            user_id=user.id,
            name="Test Key for Traffic",
            key_hash=key_hash,
            key_prefix="ac_test_",
            is_active=True
        ))
        await db.commit()
        print(f"Created API Key: {test_key}")
        
    # Now simulate a request to the proxy
    async with httpx.AsyncClient() as client:
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is the capital of France?"}
            ]
        }
        headers = {
            "Authorization": f"Bearer {test_key}",
            "Content-Type": "application/json"
        }
        print("Sending request to Gateway...")
        resp = await client.post(
            "http://127.0.0.1:8000/api/v1/gateway/chat/completions",
            json=payload,
            headers=headers,
            timeout=30.0
        )
        print("Response Status:", resp.status_code)
        print("Response Body:", resp.text)

if __name__ == "__main__":
    asyncio.run(main())
