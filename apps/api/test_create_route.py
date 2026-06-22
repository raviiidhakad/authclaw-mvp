import asyncio
import httpx
from pydantic import BaseModel

async def main():
    # Login to get token
    async with httpx.AsyncClient() as client:
        # Get a token for an admin user
        res = await client.post("http://127.0.0.1:8000/api/v1/auth/login", json={
            "email": "root.test1@gmail.com",
            "password": "password123"
        })
        if res.status_code != 200:
            print("Login failed:", res.status_code, res.text)
            return
        token = res.json()["access_token"]
        
        # Try to create gateway route
        route_payload = {
            "name": "groq route",
            "description": "Optional description",
            "is_default": False,
            "is_active": True,
            "redaction": "mask",
            "provider_id": None
        }
        res2 = await client.post("http://127.0.0.1:8000/api/v1/gateway_routes", 
                                 json=route_payload,
                                 headers={"Authorization": f"Bearer {token}"})
        print("Create Gateway Route Response:", res2.status_code)
        print("Body:", res2.text)

if __name__ == "__main__":
    asyncio.run(main())
