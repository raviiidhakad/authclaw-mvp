import asyncio
import sys
import os

# Add the app directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.role import Role, Permission

async def seed_roles():
    async with AsyncSessionLocal() as db:
        roles_data = [
            {"name": "owner", "description": "Full access to the tenant"},
            {"name": "admin", "description": "Administrative access to the tenant"},
            {"name": "auditor", "description": "Can view audit logs and compliance scores"},
            {"name": "analyst", "description": "Can view metrics and gateway logs"},
            {"name": "viewer", "description": "Read-only access to basic resources"},
            {"name": "developer", "description": "Can manage API keys and policies"},
        ]

        for role_data in roles_data:
            result = await db.execute(select(Role).where(Role.name == role_data["name"]))
            existing_role = result.scalars().first()
            if not existing_role:
                print(f"Creating role: {role_data['name']}")
                role = Role(
                    name=role_data["name"],
                    description=role_data["description"],
                    is_system=True
                )
                db.add(role)
        
        await db.commit()
        print("Roles seeded successfully.")

if __name__ == "__main__":
    asyncio.run(seed_roles())
