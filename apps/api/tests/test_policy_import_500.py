from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_import_yaml_500():
    res = client.post("/api/v1/auth/login", data={"username": "admin@authclaw.com", "password": "password"})
    token = res.json().get("access_token")
    if not token:
        print("LOGIN FAILED:", res.json())
        return

    yaml_payload = """
version: authclaw.policy/v1
name: test_policy
description: A test policy
enabled: true
priority: 0
rules:
  - type: custom
    action: block
    enabled: true
"""
    response = client.post(
        "/api/v1/policies/import-yaml",
        json={"yaml_source": yaml_payload},
        headers={"Authorization": f"Bearer {token}"}
    )
    print("STATUS:", response.status_code)
    print("RESPONSE:", response.json())
    assert response.status_code == 201
