import urllib.request
import urllib.parse
import json
import jwt
import uuid
import datetime

# We will use the user created earlier: evidence_user@example.com
# From previous output: User ID for evidence_user is unknown but we can query it via DB,
# or we can just create a script that runs inside the container and queries the DB to get the user id,
# then generates a token and makes requests.

import asyncio
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.tenant import Tenant
from sqlalchemy import select

BASE_URL = "http://localhost:8000/api/v1"
JWT_SECRET = "your-super-secret-jwt-key-change-this-in-production"

def make_request(method, endpoint, data=None, token=None):
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        
    req_data = json.dumps(data).encode('utf-8') if data else None
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    
    print(f"\n--- [REQUEST] {method} {url} ---")
    if headers: print("Headers:", json.dumps(headers))
    if data: print("Body:", json.dumps(data))
        
    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode('utf-8')
            print(f"--- [RESPONSE] {response.status} ---")
            try:
                print(json.dumps(json.loads(res_body), indent=2))
                return response.status, json.loads(res_body)
            except:
                print(res_body)
                return response.status, res_body
    except urllib.error.HTTPError as e:
        res_body = e.read().decode('utf-8')
        print(f"--- [RESPONSE ERROR] {e.code} ---")
        try:
            print(json.dumps(json.loads(res_body), indent=2))
        except:
            print(res_body)
        return e.code, None

async def main():
    async with AsyncSessionLocal() as session:
        # Get the evidence user
        result = await session.execute(select(User).limit(1))
        user = result.scalars().first()
        if not user:
            print("No users found at all!")
            return
            
        print(f"Using user: {user.id}")
        
        # Generate token
        token = jwt.encode(
            {
                "sub": str(user.id),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            },
            JWT_SECRET,
            algorithm="HS256"
        )
        
        # 1. POST /auth/refresh
        print("\n=== Testing Refresh Token ===")
        # We need a refresh token in the db or we can just hit the endpoint with a fake refresh token to see the 401
        # Let's hit /auth/refresh with a body.
        make_request("POST", "/auth/refresh", {"refresh_token": "some-invalid-token"})

        # 2. POST /auth/forgot-password
        print("\n=== Testing Forgot Password ===")
        make_request("POST", "/auth/forgot-password", {"email": "evidence_user@example.com"})

        # 3. GET /api-keys
        print("\n=== Testing API Keys ===")
        make_request("GET", "/api-keys", token=token)

        # 4. GET /gateway/requests
        print("\n=== Testing Gateway Logs ===")
        make_request("GET", "/gateway/requests", token=token)

        # 5. GET /compliance/scores
        print("\n=== Testing Compliance Scores ===")
        make_request("GET", "/compliance/scores", token=token)

if __name__ == "__main__":
    asyncio.run(main())
