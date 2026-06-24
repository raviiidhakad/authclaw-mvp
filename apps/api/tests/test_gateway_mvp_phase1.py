import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.api.v1.endpoints.api_keys import _revoke_existing_gateway_keys
from app.api.v1.endpoints.gateway import verify_api_key
from app.core.engine.gateway import GatewayService, ProviderResponse
from app.core.exceptions import UnauthorizedException
from app.models.api_key import ApiKeyScope
from app.models.gateway_route import RedactionStrategy
from app.models.provider import ProviderType


class FakeScalarResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._all_items = all_items if all_items is not None else ([] if first is None else [first])

    def first(self):
        return self._first

    def all(self):
        return self._all_items


class FakeResult:
    def __init__(self, first=None, all_items=None):
        self._scalars = FakeScalarResult(first=first, all_items=all_items)

    def scalars(self):
        return self._scalars


class FakeDb:
    def __init__(self, *results):
        self.results = list(results)

    async def execute(self, _stmt):
        if not self.results:
            raise AssertionError("Unexpected DB query in gateway test")
        return self.results.pop(0)

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def flush(self):
        return None


class FakeScanResult:
    def __init__(self, text, detected=True):
        start = text.find("person@example.test")
        self.detections = []
        self.sanitized_text = text
        self.latency_ms = 1
        if detected and start >= 0:
            self.detections = [
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": start,
                    "end": start + len("person@example.test"),
                    "score": 0.99,
                }
            ]
            self.sanitized_text = text.replace("person@example.test", "<EMAIL_ADDRESS>")

    @property
    def has_detections(self):
        return bool(self.detections)

    @property
    def entity_types(self):
        return [detection["entity_type"] for detection in self.detections]


def _provider(provider_type=ProviderType.groq, provider_id=None, active=True):
    return SimpleNamespace(
        id=provider_id or uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=f"{provider_type.value} provider",
        type=provider_type,
        config={},
        is_active=active,
    )


def _route(provider_id, name="groq", redaction=RedactionStrategy.mask, config=None, active=True, default=False):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=name,
        provider_id=provider_id,
        is_default=default,
        is_active=active,
        redaction=redaction,
        config=config or {},
        created_at=datetime.utcnow(),
    )


def _payload(route="groq", message="Explain machine learning in simple terms.", stream=False):
    return {
        "model": "client-requested-model",
        "route": route,
        "messages": [{"role": "user", "content": message}],
        "stream": stream,
    }


def _service(db):
    service = GatewayService(db)
    service.audit_engine.log_request = AsyncMock()
    return service


@pytest.mark.asyncio
async def test_gateway_key_revoke_helper_deactivates_existing_gateway_keys():
    active_keys = [
        SimpleNamespace(is_active=True),
        SimpleNamespace(is_active=True),
    ]

    revoked_count = await _revoke_existing_gateway_keys(
        FakeDb(FakeResult(all_items=active_keys)),
        uuid.uuid4(),
    )

    assert revoked_count == 2
    assert all(existing_key.is_active is False for existing_key in active_keys)


@pytest.mark.asyncio
async def test_gateway_key_verification_rejects_revoked_or_expired_keys():
    with pytest.raises(UnauthorizedException):
        await verify_api_key(authorization="Bearer ac_revoked", x_api_key=None, db=FakeDb(FakeResult(None)))

    expired_key = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        scope=ApiKeyScope.gateway_only,
        expires_at=datetime.utcnow() - timedelta(days=1),
        last_used_at=None,
    )

    with pytest.raises(UnauthorizedException):
        await verify_api_key(authorization="Bearer ac_expired", x_api_key=None, db=FakeDb(FakeResult(expired_key)))


@pytest.mark.asyncio
async def test_gateway_uses_selected_route_provider_and_model(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    groq_provider = _provider(ProviderType.groq)
    openai_provider = _provider(ProviderType.openai)
    groq_route = _route(
        groq_provider.id,
        name="groq",
        redaction=RedactionStrategy.mask,
        config={"model": "llama-3.3-70b-versatile"},
    )
    openai_route = _route(
        openai_provider.id,
        name="openai",
        redaction=RedactionStrategy.mask,
        config={"model": "gpt-4o-mini"},
    )
    service = _service(
        FakeDb(
            FakeResult(groq_route),
            FakeResult(groq_provider),
            FakeResult(all_items=[]),
            FakeResult(openai_route),
            FakeResult(openai_provider),
            FakeResult(all_items=[]),
        )
    )
    calls = []

    async def fake_chat(provider, payload):
        calls.append((provider.type, payload["model"], dict(payload)))
        return ProviderResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "ok"}}], "usage": {}},
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=5,
        )

    service.ai_client.chat_completion = fake_chat

    await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload(route="groq"))
    await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload(route="openai"))

    assert calls[0][0] == ProviderType.groq
    assert calls[0][1] == "llama-3.3-70b-versatile"
    assert calls[1][0] == ProviderType.openai
    assert calls[1][1] == "gpt-4o-mini"
    assert "route" not in calls[0][2]


@pytest.mark.asyncio
async def test_gateway_missing_default_route_fails_closed_without_provider_call():
    service = _service(FakeDb(FakeResult(None)))
    service.ai_client.chat_completion = AsyncMock()

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        _payload(route=None),
    )

    assert result["status_code"] == 503
    assert result["data"]["error"]["code"] == "no_default_route"
    service.ai_client.chat_completion.assert_not_called()


@pytest.mark.asyncio
async def test_gateway_inbound_security_failure_fails_closed(monkeypatch):
    provider = _provider()
    route = _route(provider.id)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider)))
    service.ai_client.chat_completion = AsyncMock()

    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_INBOUND_SCAN", True)
    monkeypatch.setattr("app.core.policy.cache.policy_cache.get", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "app.core.detection.presidio_engine.presidio_engine.scan",
        AsyncMock(side_effect=RuntimeError("scanner down")),
    )

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 503
    assert result["data"]["error"]["code"] == "inbound_security_failed"
    service.ai_client.chat_completion.assert_not_called()


@pytest.mark.asyncio
async def test_gateway_hash_redaction_mode_changes_provider_egress(monkeypatch):
    provider = _provider()
    route = _route(provider.id, redaction=RedactionStrategy.hash)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))
    captured_payload = {}

    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_INBOUND_SCAN", True)
    monkeypatch.setattr("app.core.config.settings.FF_OUTBOUND_SCAN", True)
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_SHADOW_MODE", False)
    monkeypatch.setattr(
        "app.core.policy.cache.policy_cache.get",
        AsyncMock(return_value={"entity_actions": {"EMAIL_ADDRESS": "HASH"}}),
    )
    monkeypatch.setattr(
        "app.core.detection.presidio_engine.presidio_engine.scan",
        AsyncMock(side_effect=lambda text: FakeScanResult(text)),
    )

    async def fake_chat(_provider, payload):
        captured_payload.update(payload)
        return ProviderResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "no sensitive output"}}], "usage": {}},
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=5,
        )

    service.ai_client.chat_completion = fake_chat

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        _payload(message="Email person@example.test should be protected."),
    )

    assert result["status_code"] == 200
    egress_text = captured_payload["messages"][0]["content"]
    assert "person@example.test" not in egress_text
    assert "<HASHED_EMAIL_ADDRESS_" in egress_text


@pytest.mark.asyncio
async def test_gateway_outbound_security_failure_does_not_release_provider_body(monkeypatch):
    provider = _provider()
    route = _route(provider.id)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))

    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_INBOUND_SCAN", False)
    monkeypatch.setattr("app.core.config.settings.FF_OUTBOUND_SCAN", True)
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_SHADOW_MODE", False)
    monkeypatch.setattr("app.core.policy.cache.policy_cache.get", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "app.core.detection.presidio_engine.presidio_engine.scan",
        AsyncMock(side_effect=RuntimeError("outbound scanner down")),
    )

    async def fake_chat(_provider, _payload):
        return ProviderResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "Contact person@example.test"}}], "usage": {}},
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=5,
        )

    service.ai_client.chat_completion = fake_chat

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload())

    assert result["status_code"] == 502
    assert result["data"]["error"]["code"] == "outbound_security_failed"
    assert "person@example.test" not in str(result["data"])
