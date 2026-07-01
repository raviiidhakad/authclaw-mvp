import uuid
from datetime import datetime, timezone

import pytest

from app.api.v1.endpoints.tenants import get_rate_limit_tiers
from app.schemas.tenant import TenantResponse, TenantUpdate


@pytest.mark.asyncio
async def test_rate_limit_tiers_endpoint_exposes_plan_limits_for_console():
    tiers = await get_rate_limit_tiers()

    tier_names = {tier.plan_name for tier in tiers}
    assert {"free", "team", "enterprise"}.issubset(tier_names)
    enterprise = next(tier for tier in tiers if tier.plan_name == "enterprise")
    assert enterprise.requests_per_minute > 0
    assert enterprise.concurrent_gateway_requests > 0
    assert enterprise.report_generation_per_hour > 0


def test_tenant_contract_exposes_plan_and_settings_for_admin_console():
    payload = TenantResponse(
        id=uuid.uuid4(),
        name="Acme Security",
        slug="acme",
        plan="enterprise",
        status="active",
        settings={"rate_limits": {"requests_per_minute": 1200}},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    assert payload.plan == "enterprise"
    assert payload.settings["rate_limits"]["requests_per_minute"] == 1200


def test_tenant_update_contract_accepts_plan_and_settings():
    update = TenantUpdate(plan="enterprise", settings={"tier_override_reason": "admin console"})

    assert update.plan == "enterprise"
    assert update.settings == {"tier_override_reason": "admin console"}
