import uuid
import httpx
import asyncio

API_BASE = "http://localhost:8000/api/v1"

async def create_tenant_and_key():
    async with httpx.AsyncClient() as client:
        # Create tenant
        t_id = str(uuid.uuid4())
        org_name = f"TestOrg_{t_id}"
        res = await client.post(f"{API_BASE}/auth/signup", json={
            "email": f"gateway_test_{t_id}@example.com",
            "password": "Password123!",
            "organization_name": org_name
        })
        res.raise_for_status()
        data = res.json()
        token = data["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Create an API Key for Gateway
        res = await client.post(f"{API_BASE}/api-keys", json={
            "name": "Gateway Test Key",
            "scope": "gateway_only"
        }, headers=headers)
        res.raise_for_status()
        api_key_data = res.json()
        raw_key = api_key_data["key"] # Store this to hit the gateway
        
        # We need a provider. For testing missing provider, we won't create one immediately.
        # But we will test missing provider first.
        
        return token, raw_key, headers

async def run_tests():
    print("Setting up test tenant...")
    admin_token, raw_gateway_key, admin_headers = await create_tenant_and_key()
    
    gw_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {raw_gateway_key}"})
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "Hello world"}]
    }
    
    # 1. Test invalid API key
    print("\n--- Test 1: Invalid API Key ---")
    bad_client = httpx.AsyncClient(headers={"Authorization": "Bearer sk_invalid_key"})
    r = await bad_client.post(f"{API_BASE}/gateway/chat/completions", json=payload)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    print("✅ Pass")

    # 2. Test missing provider
    print("\n--- Test 2: Missing Provider ---")
    r = await gw_client.post(f"{API_BASE}/gateway/chat/completions", json=payload)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")
    assert r.status_code == 500, f"Expected 500, got {r.status_code}"
    print("✅ Pass")

    # 3. Create a bad provider to test Provider error handling
    print("\nSetting up bad provider...")
    async with httpx.AsyncClient() as client:
        res = await client.post(f"{API_BASE}/providers", json={
            "name": "Bad OpenAI",
            "provider_type": "openai",
            "api_key": "sk-badkey123",
            "base_url": "https://api.openai.com/v1",
            "is_active": True
        }, headers=admin_headers)
        res.raise_for_status()

    # 4. Test provider error (Invalid Key from upstream)
    print("\n--- Test 3: Upstream Provider Error (401 from OpenAI mapped gracefully) ---")
    r = await gw_client.post(f"{API_BASE}/gateway/chat/completions", json=payload)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")
    # httpx.HTTPError is not caught as status_code because OpenAI returns a 200 with error JSON if we don't raise_for_status?
    # Wait, our code says: status_code = response.status_code. If OpenAI returns 401, status_code=401.
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    print("✅ Pass")

    # 5. Create a Policy to test block
    print("\nSetting up policy...")
    async with httpx.AsyncClient() as client:
        res = await client.post(f"{API_BASE}/policies", json={
            "name": "Block Secrets",
            "description": "Block AWS keys",
            "is_active": True,
            "rules": [
                {
                    "name": "Block AWS Key",
                    "description": "Block AWS Access Keys",
                    "rule_type": "regex_match",
                    "action": "block",
                    "conditions": {"pattern": "AKIA[0-9A-Z]{16}"}
                }
            ]
        }, headers=admin_headers)
        res.raise_for_status()

    # 6. Test Policy Block
    print("\n--- Test 4: Blocked by Policy ---")
    bad_payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "My key is AKIAIOSFODNN7EXAMPLE"}]
    }
    r = await gw_client.post(f"{API_BASE}/gateway/chat/completions", json=bad_payload)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")
    assert r.status_code == 403, f"Expected 403, got {r.status_code}"
    print("✅ Pass")

    print("\nAll automated tests passed successfully!")

if __name__ == "__main__":
    asyncio.run(run_tests())
