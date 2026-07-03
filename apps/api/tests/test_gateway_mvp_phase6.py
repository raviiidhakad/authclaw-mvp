import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Header
from fastapi.testclient import TestClient

from app.api.v1.endpoints.gateway import verify_api_key, rate_limit_dependency
from app.core.engine.gateway import GatewayService
from app.main import app
from app.models.api_key import ApiKeyScope
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
from app.models.provider import ProviderType
from tests.gateway_test_helpers import FakeDb, FakeHttpResponse, FakeResult, FakeScanResult


class FakeAsyncClient:
    calls = []
    response = FakeHttpResponse()

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url, json, headers):
        self.__class__.calls.append({"url": url, "json": json, "headers": headers})
        return self.__class__.response


def _provider(provider_type):
    config = {"base_url": "https://api.groq.com/openai/v1"} if provider_type == ProviderType.groq else {}
    if provider_type == ProviderType.azure_openai:
        config = {
            "auth_type": "api_key",
            "azure_resource_name": "authclaw-test",
            "azure_deployment_id": "gpt-4o-mini",
            "azure_api_version": "2024-02-01",
        }
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=f"{provider_type.value} provider",
        type=provider_type,
        config=config,
        is_active=True,
    )


def _route(provider_id, model, policy_id=None):
    config = {"model": model}
    if policy_id:
        config["policy_id"] = str(policy_id)
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="primary",
        provider_id=provider_id,
        is_default=True,
        is_active=True,
        redaction=RedactionStrategy.mask,
        config=config,
        created_at=datetime.utcnow(),
    )


def _policy(tenant_id):
    policy_id = uuid.uuid4()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        policy_id=policy_id,
        rule_type=RuleType.pii_redact,
        conditions={"pii_types": ["EMAIL_ADDRESS"], "redaction_mode": "MASK"},
        action=PolicyAction.warn,
        message="PII should be redacted.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=tenant_id,
        name="Route redaction policy",
        description="Test policy.",
        is_active=True,
        priority=10,
        rules=[rule],
    )


def _success_body(provider_type):
    if provider_type == ProviderType.anthropic:
        return {
            "id": "msg_test",
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": 8, "output_tokens": 2},
        }
    if provider_type == ProviderType.cohere:
        return {
            "generation_id": "gen_test",
            "text": "ok",
            "meta": {"billed_units": {"input_tokens": 8, "output_tokens": 2}},
        }
    return {
        "id": "chatcmpl_test",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 8, "completion_tokens": 2},
    }


def _payload():
    return {
        "model": "client-selected-model",
        "messages": [{"role": "user", "content": "Email person@example.test should be protected."}],
        "route": "primary",
        "stream": False,
    }


def _message_text(call_json):
    if "message" in call_json:
        return call_json["message"]
    return "\n".join(message.get("content", "") for message in call_json.get("messages", []))


def _patch_provider_keys(monkeypatch):
    for module in (
        "app.core.providers.adapters.openai.retrieve_provider_api_key",
        "app.core.providers.adapters.anthropic.retrieve_provider_api_key",
        "app.core.providers.adapters.cohere.retrieve_provider_api_key",
        "app.core.providers.adapters.azure.retrieve_provider_api_key",
    ):
        monkeypatch.setattr(module, AsyncMock(return_value="provider-credential-placeholder"))


def _enable_fake_security(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_INBOUND_SCAN", True)
    monkeypatch.setattr("app.core.config.settings.FF_OUTBOUND_SCAN", False)
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_SHADOW_MODE", False)
    monkeypatch.setattr("app.core.detection.presidio_engine.presidio_engine.is_healthy", lambda: True)
    monkeypatch.setattr(
        "app.core.detection.presidio_engine.presidio_engine.scan",
        AsyncMock(side_effect=lambda text: FakeScanResult(text)),
    )
    monkeypatch.setattr("app.core.events.producer.producer.publish_security_event", AsyncMock())


@pytest.mark.parametrize(
    ("provider_type", "route_model"),
    [
        (ProviderType.groq, "llama3-8b-8192"),
        (ProviderType.openai, "gpt-4o-mini"),
        (ProviderType.anthropic, "claude-3-haiku-20240307"),
        (ProviderType.cohere, "command-r"),
        (ProviderType.azure_openai, "gpt-4o-mini"),
    ],
)
@pytest.mark.asyncio
async def test_phase6_provider_contracts_route_override_redaction_and_normalized_response(monkeypatch, provider_type, route_model):
    _patch_provider_keys(monkeypatch)
    _enable_fake_security(monkeypatch)
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeHttpResponse(200, _success_body(provider_type))
    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    tenant_id = uuid.uuid4()
    provider = _provider(provider_type)
    policy = _policy(tenant_id)
    route = _route(provider.id, route_model, policy.id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.audit_engine.log_request = AsyncMock()

    result = await service.process_chat_request(tenant_id, uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 200
    assert result["data"]["choices"][0]["message"]["content"] == "ok"
    call = FakeAsyncClient.calls[0]
    assert route_model in str(call["json"])
    assert "person@example.test" not in str(call["json"])
    assert "<EMAIL_ADDRESS>" in _message_text(call["json"])
    rendered = f"{result} {service.audit_engine.log_request.await_args.kwargs}"
    assert "provider-credential-placeholder" not in rendered
    assert "vault://" not in rendered
    assert "provider-credential-placeholder" in str(call["headers"])


@pytest.mark.parametrize("provider_type", [ProviderType.groq, ProviderType.openai, ProviderType.anthropic, ProviderType.cohere, ProviderType.azure_openai])
@pytest.mark.asyncio
async def test_phase6_provider_errors_are_sanitized(monkeypatch, provider_type):
    _patch_provider_keys(monkeypatch)
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeHttpResponse(
        401,
        {"error": {"message": "bad provider credential placeholder", "type": "auth_error"}},
    )
    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    provider = _provider(provider_type)
    route = _route(provider.id, "command-r" if provider_type == ProviderType.cohere else "gpt-4o-mini")
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))
    service.audit_engine.log_request = AsyncMock()

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    rendered = str(result)
    assert result["status_code"] == 401
    assert "provider credential placeholder" not in rendered
    assert result["data"]["error"]["code"] == "invalid_provider_credentials"


@pytest.mark.asyncio
async def test_phase6_policy_block_prevents_upstream_call(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider(ProviderType.groq)
    policy_id = uuid.uuid4()
    blocking_policy = SimpleNamespace(
        id=policy_id,
        tenant_id=uuid.uuid4(),
        name="Block credentials",
        is_active=True,
        priority=10,
        rules=[
            SimpleNamespace(
                id=uuid.uuid4(),
                policy_id=policy_id,
                rule_type=RuleType.content_filter,
                conditions={"keywords": ["token="]},
                action=PolicyAction.block,
                message="Credential marker blocked.",
                is_active=True,
            )
        ],
    )
    route = _route(provider.id, "llama3-8b-8192", policy_id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(blocking_policy)))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock()

    payload = {**_payload(), "messages": [{"role": "user", "content": "token=demo-secret"}]}
    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), payload)

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_called()


def test_phase6_external_agent_openai_compatible_smoke(monkeypatch):
    captured = {}

    async def fake_rate_limit_dependency(authorization: str | None = Header(None)):
        captured["authorization"] = authorization
        return SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            scope=ApiKeyScope.gateway_only,
        )

    async def fake_get_db():
        class SmokeDb:
            async def execute(self, *_args, **_kwargs):
                return FakeResult()

            async def commit(self):
                return None

            async def rollback(self):
                return None

        return SmokeDb()

    async def fake_process(self, tenant_id, user_id, api_key_id, payload):
        captured["payload"] = payload
        return {
            "status_code": 200,
            "data": {
                "id": "chatcmpl_authclaw_smoke",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 1},
                "authclaw": {
                    "route": "primary",
                    "provider": "groq",
                    "redaction": "mask",
                    "audit": "sanitized_preview",
                },
            },
        }

    from app.core.database import get_db

    app.dependency_overrides[rate_limit_dependency] = fake_rate_limit_dependency
    app.dependency_overrides[get_db] = fake_get_db
    monkeypatch.setattr("app.api.v1.endpoints.gateway.GatewayService.process_chat_request", fake_process)
    try:
        client = TestClient(app)
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer ac_external_agent_placeholder"},
            json={"model": "primary", "messages": [{"role": "user", "content": "hello"}]},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["content"] == "ok"
    assert captured["authorization"] == "Bearer ac_external_agent_placeholder"
    assert captured["payload"]["messages"][0]["content"] == "hello"
    assert body["authclaw"]["audit"] == "sanitized_preview"


@pytest.mark.asyncio
async def test_phase6_revoked_expired_and_disabled_route_are_rejected():
    missing_key_db = FakeDb(FakeResult(None))
    with pytest.raises(Exception):
        await verify_api_key(authorization="Bearer ac_revoked_placeholder", x_api_key=None, db=missing_key_db)

    expired_key = SimpleNamespace(
        key_hash="unused",
        is_active=True,
        scope=ApiKeyScope.gateway_only,
        expires_at=datetime.utcnow() - timedelta(minutes=1),
        last_used_at=None,
    )
    expired_key_db = FakeDb(FakeResult(expired_key))
    with pytest.raises(Exception):
        await verify_api_key(authorization="Bearer ac_expired_placeholder", x_api_key=None, db=expired_key_db)

    provider = _provider(ProviderType.groq)
    disabled_route = _route(provider.id, "llama3-8b-8192")
    disabled_route.is_active = False
    service = GatewayService(FakeDb(FakeResult(disabled_route)))
    service.audit_engine.log_request = AsyncMock()

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 403
    assert result["data"]["error"]["code"] == "route_disabled"
