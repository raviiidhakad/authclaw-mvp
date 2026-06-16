import asyncio
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'apps', 'api'))

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.role import Role, Permission

ROLES_AND_PERMISSIONS = {
    "owner": [
        ("tenants", "read"), ("tenants", "update"),
        ("users", "create"), ("users", "read"), ("users", "update"), ("users", "delete"),
        ("roles", "read"), ("roles", "assign"),
        ("providers", "create"), ("providers", "read"), ("providers", "update"), ("providers", "delete"),
        ("api_keys", "create"), ("api_keys", "read"), ("api_keys", "delete"),
        ("policies", "create"), ("policies", "read"), ("policies", "update"), ("policies", "delete"),
        ("gateways", "read"),
        ("audit", "read"), ("audit", "export"),
        ("compliance", "read"), ("compliance", "calculate"),
        ("settings", "read"), ("settings", "update")
    ],
    "admin": [
        ("tenants", "read"),
        ("users", "create"), ("users", "read"), ("users", "update"),
        ("roles", "read"),
        ("providers", "create"), ("providers", "read"), ("providers", "update"),
        ("api_keys", "create"), ("api_keys", "read"), ("api_keys", "delete"),
        ("policies", "create"), ("policies", "read"), ("policies", "update"), ("policies", "delete"),
        ("gateways", "read"),
        ("audit", "read"),
        ("compliance", "read"), ("compliance", "calculate"),
        ("settings", "read")
    ],
    "analyst": [
        ("policies", "read"),
        ("gateways", "read"),
        ("compliance", "read")
    ],
    "auditor": [
        ("policies", "read"),
        ("gateways", "read"),
        ("audit", "read"), ("audit", "export"),
        ("compliance", "read")
    ],
    "viewer": [
        ("gateways", "read"),
        ("compliance", "read")
    ]
}

async def seed_data():
    async with AsyncSessionLocal() as session:
        print("Seeding roles and permissions...")
        
        for role_name, perms in ROLES_AND_PERMISSIONS.items():
            # Check if role exists
            result = await session.execute(select(Role).where(Role.name == role_name))
            role = result.scalars().first()
            
            if not role:
                print(f"Creating role: {role_name}")
                role = Role(name=role_name, is_system=True)
                session.add(role)
                await session.flush()
            
            # Create permissions
            for resource, action in perms:
                result = await session.execute(
                    select(Permission)
                    .where(Permission.role_id == role.id)
                    .where(Permission.resource == resource)
                    .where(Permission.action == action)
                )
                perm = result.scalars().first()
                if not perm:
                    perm = Permission(role_id=role.id, resource=resource, action=action)
                    session.add(perm)
                    
        await session.commit()
        print("Seed data successfully applied!")

if __name__ == "__main__":
    asyncio.run(seed_data())
