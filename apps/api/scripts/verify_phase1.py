import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import sys
import os

# Add the app directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.models.base import Base
from app.models.user import User
from app.models.token import RefreshToken
from app.models.audit import AuditLog, EventType, AuditAction

async def main():
    print("--- ORM Registration ---")
    print(f"Refresh tokens in Base.metadata.tables: {'refresh_tokens' in Base.metadata.tables}")
    
    async with AsyncSessionLocal() as session:
        # Get a tenant
        from app.models.tenant import Tenant
        result = await session.execute(select(Tenant).limit(1))
        tenant = result.scalars().first()
        if not tenant:
            tenant = Tenant(name="Test Tenant", slug=f"test-{uuid.uuid4()}")
            session.add(tenant)
            await session.commit()
            await session.refresh(tenant)

        # Get a user (since foreign key is required)
        result = await session.execute(select(User).limit(1))
        user = result.scalars().first()
        if not user:
            print("No users found. Creating a test user.")
            user = User(
                tenant_id=tenant.id,
                email="test_refresh@example.com",
                password_hash="test",
                first_name="Test",
                last_name="User",
                is_active=True,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

        print("\n--- Refresh Token Persistence Test ---")
        token_hash = f"test_hash_{uuid.uuid4()}"
        family = f"test_family_{uuid.uuid4()}"
        token = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            family=family,
            expires_at=datetime.utcnow() + timedelta(days=1)
        )
        session.add(token)
        await session.commit()
        await session.refresh(token)
        print(f"Successfully inserted RefreshToken: ID={token.id}, token_hash={token.token_hash}")

        result = await session.execute(select(RefreshToken).where(RefreshToken.id == token.id))
        fetched_token = result.scalars().first()
        print(f"Successfully retrieved RefreshToken: ID={fetched_token.id}, token_hash={fetched_token.token_hash}")

        print("\n--- Audit Insert Validation ---")
        audit = AuditLog(
            tenant_id=tenant.id,
            event_type=EventType.gateway_request,
            action=AuditAction.create,
            resource="test_resource",
            resource_id="test_id"
        )
        session.add(audit)
        await session.commit()
        await session.refresh(audit)
        print(f"Successfully inserted AuditLog: ID={audit.id}, event_type={audit.event_type.value}")

        print("Testing UPDATE on AuditLog...")
        try:
            audit.event_type = EventType.gateway_response
            session.add(audit)
            await session.commit()
            print("ERROR: UPDATE succeeded (should have failed!)")
        except Exception as e:
            await session.rollback()
            print(f"UPDATE failed as expected with error: {str(e)}")

        print("Testing DELETE on AuditLog...")
        try:
            await session.delete(audit)
            await session.commit()
            print("ERROR: DELETE succeeded (should have failed!)")
        except Exception as e:
            await session.rollback()
            print(f"DELETE failed as expected with error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
