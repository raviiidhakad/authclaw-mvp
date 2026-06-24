import uuid

import pytest
from sqlalchemy import delete, select, text

from app.api.v1.endpoints.api_keys import create_api_key
from app.api.v1.endpoints.gateway import verify_api_key
from app.core.database import AsyncSessionLocal
from app.core.exceptions import UnauthorizedException
from app.models.api_key import ApiKey, ApiKeyScope
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.api_key import ApiKeyCreate


@pytest.mark.asyncio
async def test_creating_new_gateway_key_revokes_previous_active_key():
    async with AsyncSessionLocal() as db:
        tenant = Tenant(
            id=uuid.uuid4(),
            name="API Key Singleton Test",
            slug=f"api-key-singleton-{uuid.uuid4().hex[:8]}",
            settings={},
        )
        tenant_id = tenant.id
        user = User(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            email=f"api-key-singleton-{uuid.uuid4().hex[:8]}@example.test",
            password_hash="test",
            first_name="API",
            last_name="Tester",
        )
        db.add_all([tenant, user])
        await db.commit()
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant.id)},
        )

        try:
            first = await create_api_key(
                ApiKeyCreate(name="first gateway key", scope=ApiKeyScope.gateway_only),
                tenant=tenant,
                current_user=user,
                db=db,
                _check_role=user,
            )
            await db.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
                {"tenant_id": str(tenant_id)},
            )
            second = await create_api_key(
                ApiKeyCreate(name="replacement gateway key", scope=ApiKeyScope.gateway_only),
                tenant=tenant,
                current_user=user,
                db=db,
                _check_role=user,
            )

            first_key = (
                await db.execute(select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.key_prefix == first.key_prefix))
            ).scalars().one()
            second_key = (
                await db.execute(select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.key_prefix == second.key_prefix))
            ).scalars().one()

            assert first.raw_key
            assert second.raw_key
            assert second.revoked_key_count == 1
            assert first_key.is_active is False
            assert second_key.is_active is True

            with pytest.raises(UnauthorizedException):
                await verify_api_key(authorization=None, x_api_key=first.raw_key, db=db)

            active = await verify_api_key(authorization=None, x_api_key=second.raw_key, db=db)
            assert active.id == second_key.id
        finally:
            await db.rollback()
            await db.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
                {"tenant_id": str(tenant_id)},
            )
            await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await db.commit()
