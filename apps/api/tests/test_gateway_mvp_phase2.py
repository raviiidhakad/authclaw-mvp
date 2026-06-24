import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.api.v1.endpoints.gateway_routes import (
    _ensure_tenant_provider,
    _serialize,
    _validate_redaction,
)
from app.api.v1.endpoints.providers import validate_provider
from app.core.exceptions import BadRequestException
from app.models.gateway_route import RedactionStrategy
from app.models.provider import ProviderType
from app.schemas.gateway import GatewayRequestDetail, GatewayRequestResponseBrief
from app.schemas.provider import ProviderResponse


class FakeScalarResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._all = all_items if all_items is not None else ([] if first is None else [first])

    def first(self):
        return self._first

    def all(self):
        return self._all


class FakeResult:
    def __init__(self, first=None, all_items=None):
        self._scalars = FakeScalarResult(first, all_items)

    def scalars(self):
        return self._scalars


class FakeDb:
    def __init__(self, *results):
        self.results = list(results)

    async def execute(self, _stmt):
        if not self.results:
            raise AssertionError("Unexpected DB query in phase 2 test")
        return self.results.pop(0)


def _provider():
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="Groq metadata provider",
        type=ProviderType.groq,
        config={
            "base_url": "https://api.groq.com/openai/v1",
            "model": "llama3-8b-8192",
            "api_key": "gsk_should_not_render",
            "vault_reference_id": "vault://provider/ref",
            "raw_provider_payload": {"authorization": "Bearer gsk_hidden"},
        },
        is_active=True,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


def test_provider_response_sanitizes_config_metadata_only():
    provider = _provider()
    body = ProviderResponse.model_validate(provider).model_dump()

    assert body["config"] == {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama3-8b-8192",
    }
    assert "gsk_" not in str(body)
    assert "vault://" not in str(body).lower()
    assert "raw_provider_payload" not in str(body)


@pytest.mark.asyncio
async def test_provider_validation_is_metadata_only_by_default(monkeypatch):
    provider = _provider()
    tenant = SimpleNamespace(id=provider.tenant_id)

    async def fake_retrieve(_provider):
        return "gsk_not_printed"

    class FakeAdapter:
        def validate_configuration(self, _config):
            return None

        async def get_connection_details(self, _provider):
            raise AssertionError("Live provider validation should be disabled by default")

    monkeypatch.setattr("app.api.v1.endpoints.providers.retrieve_provider_api_key", fake_retrieve)
    monkeypatch.setattr("app.api.v1.endpoints.providers.ProviderAdapterFactory.get_adapter", lambda _type: FakeAdapter())
    monkeypatch.setattr("app.api.v1.endpoints.providers.settings.ENABLE_PROVIDER_LIVE_VALIDATION", False)

    result = await validate_provider(provider.id, tenant=tenant, db=FakeDb(FakeResult(provider)), _user=SimpleNamespace())

    assert result == {
        "provider_id": str(provider.id),
        "valid": True,
        "provider_type": "groq",
        "validation_mode": "metadata_only",
    }


@pytest.mark.asyncio
async def test_route_provider_must_be_tenant_scoped():
    with pytest.raises(BadRequestException):
        await _ensure_tenant_provider(uuid.uuid4(), uuid.uuid4(), FakeDb(FakeResult(None)))


def test_route_redaction_rejects_none_and_route_config_is_sanitized():
    with pytest.raises(BadRequestException):
        _validate_redaction(RedactionStrategy.none)

    route = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        provider_id=uuid.uuid4(),
        name="safe-route",
        description=None,
        is_default=True,
        is_active=True,
        redaction=RedactionStrategy.hash,
        config={
            "model": "llama3-8b-8192",
            "api_key": "gsk_should_not_render",
            "raw_provider_payload": {"token": "secret"},
        },
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        __table__=SimpleNamespace(
            columns=[
                SimpleNamespace(key=key)
                for key in (
                    "id",
                    "tenant_id",
                    "provider_id",
                    "name",
                    "description",
                    "is_default",
                    "is_active",
                    "redaction",
                    "config",
                )
            ]
        ),
    )

    body = _serialize(route).model_dump()

    assert body["config"] == {"model": "llama3-8b-8192"}
    assert "gsk_" not in str(body)
    assert "raw_provider_payload" not in str(body)


def test_gateway_traffic_schemas_sanitize_secret_like_errors_and_prompts():
    brief = GatewayRequestResponseBrief.model_validate(
        SimpleNamespace(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            model="llama3-8b-8192",
            status="error",
            token_count_prompt=0,
            latency_ms=0,
            provider_status_code=401,
            error_message="Incorrect key gsk_supersecret12345 token=demo-secret vault://provider/ref",
            error_type="provider_auth_error",
            error_code="invalid_provider_credentials",
            created_at=datetime.utcnow(),
        )
    ).model_dump()
    detail = GatewayRequestDetail.model_validate(
        SimpleNamespace(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            model="llama3-8b-8192",
            prompt_original="email person@example.test token=demo-secret",
            prompt_redacted=None,
            status="error",
            token_count_prompt=0,
            latency_ms=0,
            provider_status_code=401,
            error_message="sk-provider-secret-demo",
            error_type="provider_auth_error",
            error_code="invalid_provider_credentials",
            created_at=datetime.utcnow(),
            response=None,
            violations=[],
        )
    ).model_dump()

    rendered = f"{brief} {detail}"
    assert "gsk_" not in rendered
    assert "sk-provider" not in rendered
    assert "demo-secret" not in rendered
    assert "person@example.test" not in rendered
