import asyncio
import uuid
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from app.main import app
from app.api.dependencies import get_current_user, get_current_tenant
from app.models.user import User
from app.models.tenant import Tenant
from app.core.config import settings

client = TestClient(app)

async def main():
    engine = create_async_engine(str(settings.DATABASE_URL))
    AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    
    async with AsyncSessionLocal() as db:
        # Get a user and their tenant
        result = await db.execute(select(User).where(User.email == 'brutea963@example.com').limit(1))
        user = result.scalars().first()
        if not user:
            print("No user found in DB to run test")
            return
            
        result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = result.scalars().first()
        
    print(f"Using test user: {user.email}")
    
    # Generate token
    from app.core.security import create_access_token
    token = create_access_token(str(user.id))
    client.headers.update({"Authorization": f"Bearer {token}"})
    
    # 1. Test Provider Creation
    print("\n--- 1. Testing Provider Creation ---")
    provider_payload = {
        "name": "Evidence Test Provider",
        "type": "openai",
        "api_key": "sk-test-1234",
        "config": {
            "base_url": "https://api.openai.com/v1"
        }
    }
    # Remember prefix is /api/v1
    res = client.post("/api/v1/providers", json=provider_payload)
    print(f"Provider Create Status: {res.status_code}")
    assert res.status_code == 201, res.text
    provider_data = res.json()
    provider_id = provider_data["id"]
    print(f"Created Provider ID: {provider_id}")
    
    # 2. Test Gateway Route Creation
    print("\n--- 2. Testing Gateway Route Creation ---")
    route_payload = {
        "name": "Evidence Test Route",
        "description": "A route for contract evidence",
        "provider_id": provider_id,
        "is_default": False,
        "is_active": True,
        "redaction": "none"
    }
    res = client.post("/api/v1/gateway-routes", json=route_payload)
    print(f"Gateway Route Create Status: {res.status_code}")
    assert res.status_code == 201, res.text
    route_data = res.json()
    route_id = route_data["id"]
    print(f"Created Gateway Route ID: {route_id}")
    
    # 3. Test Gateway Route Edit
    print("\n--- 3. Testing Gateway Route Edit ---")
    edit_payload = {
        "name": "Edited Evidence Route",
        "redaction": "mask"
    }
    res = client.patch(f"/api/v1/gateway-routes/{route_id}", json=edit_payload)
    print(f"Gateway Route Edit Status: {res.status_code}")
    assert res.status_code == 200, res.text
    edited_route = res.json()
    print(f"Edited Name: {edited_route['name']} | Redaction: {edited_route['redaction']}")
    
    # 4. Test Gateway Route Deletion
    print("\n--- 4. Testing Gateway Route Deletion ---")
    res = client.delete(f"/api/v1/gateway-routes/{route_id}")
    print(f"Gateway Route Delete Status: {res.status_code}")
    assert res.status_code == 204, res.text
    print("Gateway Route Deleted Successfully.")
    
    print("\nExecution Evidence Complete.")

if __name__ == "__main__":
    asyncio.run(main())
