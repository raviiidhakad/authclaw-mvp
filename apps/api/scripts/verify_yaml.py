import asyncio
import uuid
import httpx
from datetime import timedelta
import os

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.security import create_access_token
from app.core.database import AsyncSessionLocal
from app.models.tenant import Tenant
from app.models.user import User
from app.models.api_key import ApiKey
from sqlalchemy.future import select

async def main():
    async with AsyncSessionLocal() as db:
        api_key_obj = (await db.execute(select(ApiKey).limit(1))).scalars().first()
        tenant = (await db.execute(select(Tenant).where(Tenant.id == api_key_obj.tenant_id))).scalars().first()
        user = (await db.execute(select(User).where(User.tenant_id == tenant.id).limit(1))).scalars().first()
        user_role = user.roles[0] if hasattr(user, 'roles') and user.roles else "owner"
        
    access_token = create_access_token(
        str(user.id),
        expires_delta=timedelta(minutes=15),
    )
    
    import hashlib
    import secrets
    new_raw_key = f"sk_test_{secrets.token_urlsafe(16)}"
    key_hash = hashlib.sha256(new_raw_key.encode()).hexdigest()
    
    async with AsyncSessionLocal() as db:
        from sqlalchemy import update
        await db.execute(update(ApiKey).where(ApiKey.id == api_key_obj.id).values(key_hash=key_hash))
        await db.commit()
    
    api_headers = {"Authorization": f"Bearer {access_token}"}
    gateway_headers = {"Authorization": f"Bearer {new_raw_key}", "Content-Type": "application/json"}
    
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # TEST 1: Block Keyword
        yaml_test1 = """
apiVersion: authclaw.policy/v1
kind: Policy
metadata:
  name: Block Confidential
  description: Block confidential keywords
spec:
  enabled: true
  priority: 100
  rules:
    - name: Block Confidential
      type: content_filter
      action: BLOCK
      conditions:
        regexes:
          - '(?i)confidential'
"""
        print("Importing Test 1 Policy...")
        res = await client.post(f"{base_url}/api/v1/policies/import-yaml", json={"yaml_source": yaml_test1}, headers=api_headers)
        print("Import status:", res.status_code)
        
        print("Running Test 1 Gateway...")
        res = await client.post(f"{base_url}/api/v1/gateway/chat/completions", json={
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "This document is confidential."}]
        }, headers=gateway_headers)
        print("Gateway status:", res.status_code)
        print("Gateway response:", res.json())
        
        # Test 2: PII Redact MASK
        yaml_test2 = """
apiVersion: authclaw.policy/v1
kind: Policy
metadata:
  name: Redact Email
spec:
  enabled: true
  priority: 200
  rules:
    - name: Redact Email
      type: pii_redact
      action: REDACT
      conditions:
        pii_types: [EMAIL_ADDRESS]
        redaction_mode: MASK
"""
        print("Importing Test 2 Policy...")
        await client.post(f"{base_url}/api/v1/policies/import-yaml", json={"yaml_source": yaml_test2}, headers=api_headers)
        
        print("Running Test 2 Gateway...")
        res = await client.post(f"{base_url}/api/v1/gateway/chat/completions", json={
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "My email is ravi@gmail.com"}]
        }, headers=gateway_headers)
        print("Gateway status:", res.status_code)
        
        # Look in DB for the request to see what reached the provider
        await asyncio.sleep(2)
        async with AsyncSessionLocal() as db:
            from sqlalchemy import text
            r = await db.execute(text("SELECT prompt_original, prompt_redacted FROM gateway_requests ORDER BY created_at DESC LIMIT 1"))
            row = r.fetchone()
            print("Test 2 DB Request:", row)
            
        # Test 3: PII BLOCK
        yaml_test3 = """
apiVersion: authclaw.policy/v1
kind: Policy
metadata:
  name: Block Email
spec:
  enabled: true
  priority: 300
  rules:
    - name: Block Email
      type: pii_block
      action: BLOCK
      conditions:
        pii_types: [EMAIL_ADDRESS]
"""
        print("Importing Test 3 Policy...")
        await client.post(f"{base_url}/api/v1/policies/import-yaml", json={"yaml_source": yaml_test3}, headers=api_headers)
        
        print("Running Test 3 Gateway...")
        res = await client.post(f"{base_url}/api/v1/gateway/chat/completions", json={
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "My email is ravi@gmail.com"}]
        }, headers=gateway_headers)
        print("Gateway status:", res.status_code)

if __name__ == "__main__":
    asyncio.run(main())
