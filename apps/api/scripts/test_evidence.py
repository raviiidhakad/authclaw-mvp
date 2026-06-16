import asyncio
import json
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import app
from app.api.dependencies import get_current_user, get_current_tenant
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.tenant import Tenant
from app.models.role import Role, UserRole

# Parse openapi.json
client = TestClient(app)
openapi = client.get("/api/v1/openapi.json").json()
print("--- OpenAPI Endpoints ---")
for path, methods in openapi["paths"].items():
    for method in methods.keys():
        print(f"{method.upper()} {path}")

async def async_main():
    async with AsyncSessionLocal() as session:
        # 1. Ensure Tenant exists
        result = await session.execute(select(Tenant).limit(1))
        tenant = result.scalars().first()
        if not tenant:
            tenant = Tenant(name="Evidence Tenant", slug=f"ev-{uuid.uuid4()}")
            session.add(tenant)
            await session.commit()
            await session.refresh(tenant)

        # 2. Ensure User exists
        result = await session.execute(select(User).limit(1))
        user = result.scalars().first()
        if not user:
            user = User(
                tenant_id=tenant.id,
                email="evidence_user@example.com",
                password_hash="test",
                first_name="Evidence",
                last_name="User",
                is_active=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

        # 3. Ensure 'viewer' role exists
        result = await session.execute(select(Role).where(Role.name == "viewer"))
        viewer_role = result.scalars().first()
        if not viewer_role:
            viewer_role = Role(name="viewer", description="Viewer role", is_system=True)
            session.add(viewer_role)
            await session.commit()
            await session.refresh(viewer_role)

        # 4. Assign 'viewer' role to user
        result = await session.execute(select(UserRole).where(UserRole.user_id == user.id))
        user_role = result.scalars().first()
        if not user_role:
            user_role = UserRole(user_id=user.id, role_id=viewer_role.id, tenant_id=tenant.id)
            session.add(user_role)
            await session.commit()

        # 5. Get Owner role for compliance calc later
        result = await session.execute(select(Role).where(Role.name == "owner"))
        owner_role = result.scalars().first()

        # Save for later
        return tenant, user, viewer_role, user_role, owner_role

tenant, user, viewer_role, user_role, owner_role = asyncio.run(async_main())

# Override dependencies
app.dependency_overrides[get_current_user] = lambda: user
app.dependency_overrides[get_current_tenant] = lambda: tenant

print("\n--- RBAC Denial Demonstration ---")
print("User Role:", viewer_role.name)
print("Attempting to access POST /api/v1/compliance/scores/calculate (requires owner/admin)...")
response = client.post("/api/v1/compliance/scores/calculate")
print("Status Code:", response.status_code)
print("Response:", response.json())

print("\n--- Compliance Calculation Demonstration ---")
# Upgrade user to owner
async def upgrade_to_owner():
    async with AsyncSessionLocal() as session:
        user_role_obj = await session.get(UserRole, user_role.id)
        user_role_obj.role_id = owner_role.id
        await session.commit()
asyncio.run(upgrade_to_owner())

print("User Role upgraded to: owner")
print("Attempting to access POST /api/v1/compliance/scores/calculate...")
response = client.post("/api/v1/compliance/scores/calculate")
print("Status Code:", response.status_code)
print("Response:", json.dumps(response.json(), indent=2))

