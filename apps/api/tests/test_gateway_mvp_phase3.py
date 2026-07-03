import hashlib
import os
import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, text

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.detection.presidio_engine import presidio_engine
from app.core.engine.gateway import GatewayService
from app.models.api_key import ApiKey, ApiKeyScope
from app.models.gateway import GatewayRequest
from app.models.gateway_route import GatewayRoute, RedactionStrategy
from app.models.provider import Provider, ProviderType
from app.models.tenant import Tenant
from app.models.user import User
from app.services.provider_credentials import store_provider_api_key
from tests.gateway_test_helpers import (
    FakeDb,
    FakeHttpResponse,
    FakeResult,
    FakeScanResult,
    fake_async_client_factory,
)


def _provider(provider_type=ProviderType.groq):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=f"{provider_type.value} api",
        type=provider_type,
        config={"base_url": "https://api.groq.com/openai/v1"},
        is_active=True,
    )


def _route(provider_id, redaction=RedactionStrategy.mask, model="llama3-8b-8192"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="groq",
        provider_id=provider_id,
        is_default=False,
        is_active=True,
        redaction=redaction,
        config={"model": model},
        created_at=datetime.utcnow(),
    )


def _payload(message="Email person@example.test should be protected."):
    return {
        "model": "client-selected-model",
        "route": "groq",
        "messages": [{"role": "user", "content": message}],
        "stream": False,
    }


def _service(db):
    service = GatewayService(db)
    service.audit_engine.log_request = AsyncMock()
    return service


def _enable_inbound_security(monkeypatch, action="MASK"):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_INBOUND_SCAN", True)
    monkeypatch.setattr("app.core.config.settings.FF_OUTBOUND_SCAN", False)
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_SHADOW_MODE", False)
    monkeypatch.setattr(
        "app.core.policy.cache.policy_cache.get",
        AsyncMock(return_value={"entity_actions": {"EMAIL_ADDRESS": action}}),
    )
    monkeypatch.setattr(
        "app.core.detection.presidio_engine.presidio_engine.scan",
        AsyncMock(side_effect=lambda text: FakeScanResult(text)),
    )


def _stub_upstream(monkeypatch, response):
    fake_client = fake_async_client_factory(response)
    monkeypatch.setattr("httpx.AsyncClient", fake_client)
    monkeypatch.setattr(
        "app.core.providers.adapters.openai.retrieve_provider_api_key",
        AsyncMock(return_value="provider-secret-not-real"),
    )
    return fake_client


@pytest.mark.asyncio
async def test_mocked_upstream_receives_redacted_payload_and_route_model(monkeypatch):
    _enable_inbound_security(monkeypatch, "MASK")
    fake_client = _stub_upstream(
        monkeypatch,
        FakeHttpResponse(
            200,
            {
                "id": "chatcmpl_test",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 1},
            },
        ),
    )
    provider = _provider()
    route = _route(provider.id, redaction=RedactionStrategy.mask, model="llama3-8b-8192")
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 200
    assert result["data"]["choices"][0]["message"]["content"] == "ok"
    call = fake_client.calls[0]
    assert call["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert call["headers"]["Authorization"].startswith("Bearer ")
    assert call["json"]["model"] == "llama3-8b-8192"
    assert "route" not in call["json"]
    egress_text = call["json"]["messages"][0]["content"]
    assert "person@example.test" not in egress_text
    assert "<EMAIL_ADDRESS>" in egress_text


@pytest.mark.asyncio
async def test_mocked_policy_block_does_not_call_upstream(monkeypatch):
    _enable_inbound_security(monkeypatch, "BLOCK")
    fake_client = _stub_upstream(monkeypatch, FakeHttpResponse(200, {"choices": []}))
    provider = _provider()
    route = _route(provider.id)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider)))

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 403
    assert result["data"]["error"]["type"] == "security_policy_violation"
    assert fake_client.calls == []


@pytest.mark.asyncio
async def test_mocked_provider_error_is_sanitized(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    fake_secret_message = "Incorrect API key " + "gsk_" + ("x" * 30)
    fake_client = _stub_upstream(monkeypatch, FakeHttpResponse(401, {"error": {"message": fake_secret_message}}))
    provider = _provider()
    route = _route(provider.id)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        _payload("Explain machine learning in simple terms."),
    )

    rendered = str(result["data"])
    assert result["status_code"] == 401
    assert result["data"]["error"]["code"] == "invalid_provider_credentials"
    assert "gsk_" not in rendered
    assert "Incorrect API key" not in rendered
    assert fake_client.calls


@pytest.mark.parametrize(
    ("strategy", "expected_marker"),
    [
        (RedactionStrategy.mask, "<EMAIL_ADDRESS>"),
        (RedactionStrategy.hash, "<HASHED_EMAIL_ADDRESS_"),
        (RedactionStrategy.synthetic, "synthetic-email_address-1"),
    ],
)
@pytest.mark.asyncio
async def test_mocked_redaction_modes_affect_upstream_egress(monkeypatch, strategy, expected_marker):
    _enable_inbound_security(monkeypatch, "MASK")
    fake_client = _stub_upstream(
        monkeypatch,
        FakeHttpResponse(200, {"choices": [{"message": {"content": "ok"}}], "usage": {}}),
    )
    provider = _provider()
    route = _route(provider.id, redaction=strategy)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 200
    egress_text = fake_client.calls[0]["json"]["messages"][0]["content"]
    assert "person@example.test" not in egress_text
    assert expected_marker in egress_text


@pytest.mark.asyncio
async def test_mocked_gateway_audit_metadata_is_safe(monkeypatch):
    _enable_inbound_security(monkeypatch, "HASH")
    fake_client = _stub_upstream(
        monkeypatch,
        FakeHttpResponse(
            200,
            {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 2},
            },
        ),
    )
    provider = _provider()
    route = _route(provider.id, redaction=RedactionStrategy.hash, model="llama-3.3-70b-versatile")
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 200
    audit_kwargs = service.audit_engine.log_request.await_args.kwargs
    rendered = str(audit_kwargs)
    assert audit_kwargs["provider_id"] == provider.id
    assert audit_kwargs["model"] == "llama-3.3-70b-versatile"
    assert audit_kwargs["status_code"] == 200
    assert audit_kwargs["latency_ms"] >= 0
    assert audit_kwargs["tokens_prompt"] == 7
    assert audit_kwargs["tokens_completion"] == 2
    assert "person@example.test" not in str(audit_kwargs["modified_payload"])
    assert "provider-secret-not-real" not in rendered
    assert "authclaw/tenants/" not in rendered
    assert fake_client.calls[0]["json"]["model"] == "llama-3.3-70b-versatile"


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_groq_gateway_e2e_is_gated():
    if not (
        settings.ENABLE_GATEWAY_LIVE_E2E
        and settings.ENABLE_PROVIDER_LIVE_VALIDATION
        and os.getenv("GROQ_API_KEY")
    ):
        pytest.skip("Live Groq gateway E2E requires ENABLE_GATEWAY_LIVE_E2E, ENABLE_PROVIDER_LIVE_VALIDATION, and GROQ_API_KEY.")

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    provider_id = uuid.uuid4()
    route_id = uuid.uuid4()
    api_key_id = uuid.uuid4()
    raw_gateway_key = "ac_" + uuid.uuid4().hex + uuid.uuid4().hex

    async with AsyncSessionLocal() as db:
        try:
            tenant = Tenant(id=tenant_id, name=f"Gateway Live E2E {tenant_id.hex[:8]}", slug=f"gateway-live-{tenant_id.hex[:8]}")
            user = User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"gateway-live-{tenant_id.hex[:8]}@example.test",
                password_hash="test",
                first_name="Gateway",
                last_name="Live",
            )
            provider = Provider(
                id=provider_id,
                tenant_id=tenant_id,
                name="Groq live validation",
                type=ProviderType.groq,
                api_key_encrypted="pending-live-vault-ref",
                config={"base_url": "https://api.groq.com/openai/v1"},
                is_active=True,
            )
            route = GatewayRoute(
                id=route_id,
                tenant_id=tenant_id,
                provider_id=provider_id,
                name="groq-live",
                is_default=True,
                is_active=True,
                redaction=RedactionStrategy.mask,
                config={"model": "llama-3.3-70b-versatile"},
            )
            api_key = ApiKey(
                id=api_key_id,
                tenant_id=tenant_id,
                user_id=user_id,
                name="Live E2E AuthClaw gateway key",
                key_hash=hashlib.sha256(raw_gateway_key.encode("utf-8")).hexdigest(),
                key_prefix=raw_gateway_key[:12],
                scope=ApiKeyScope.gateway_only,
                is_active=True,
            )
            await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})
            db.add_all([tenant, user, provider, route, api_key])
            await db.flush()
            provider.api_key_encrypted = await store_provider_api_key(tenant_id, provider_id, os.environ["GROQ_API_KEY"])
            await db.commit()
            await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})
            await presidio_engine.start()

            service = GatewayService(db)
            result = await service.process_chat_request(
                tenant_id,
                user_id,
                api_key_id,
                {
                    "model": "ignored-client-model",
                    "route": "groq-live",
                    "messages": [{"role": "user", "content": "Reply with one short sentence about safe gateway validation."}],
                    "stream": False,
                },
            )

            rendered = str(result)
            assert 200 <= result["status_code"] < 300
            assert result["data"].get("choices")
            assert os.environ["GROQ_API_KEY"] not in rendered
            assert raw_gateway_key not in rendered
        finally:
            await presidio_engine.stop()
            await db.rollback()
            await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})
            await db.execute(delete(GatewayRequest).where(GatewayRequest.tenant_id == tenant_id))
            await db.execute(delete(ApiKey).where(ApiKey.tenant_id == tenant_id))
            await db.execute(delete(GatewayRoute).where(GatewayRoute.tenant_id == tenant_id))
            await db.execute(delete(Provider).where(Provider.tenant_id == tenant_id))
            await db.commit()
