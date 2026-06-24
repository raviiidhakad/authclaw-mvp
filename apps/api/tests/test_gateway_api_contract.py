import uuid
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api.v1.endpoints.gateway import _extract_gateway_token, _sanitize_trace_text
from app.core.exceptions import UnauthorizedException
from app.core.providers.adapters.openai import OpenAIAdapter
from app.main import app
from app.models.gateway import RequestStatus
from app.models.provider import ProviderType
from app.schemas.gateway import GatewayRequestDetail
from app.services.api_safety import sanitize_text
from app.services.provider_credentials import is_vault_provider_reference


def test_gateway_token_extraction_accepts_bearer_and_x_api_key():
    assert _extract_gateway_token("Bearer ac_full_key", None) == "ac_full_key"
    assert _extract_gateway_token("bearer ac_lowercase_scheme", None) == "ac_lowercase_scheme"
    assert _extract_gateway_token("Bearer wrong", "ac_header_key") == "ac_header_key"


def test_gateway_token_extraction_rejects_missing_key():
    with pytest.raises(UnauthorizedException):
        _extract_gateway_token(None, None)


def test_gateway_trace_schema_tolerates_legacy_rows_without_detection_lists():
    request_id = uuid.uuid4()
    detail = GatewayRequestDetail.model_validate(
        SimpleNamespace(
            id=request_id,
            user_id=uuid.uuid4(),
            provider_id=None,
            model="llama-3.3-70b-versatile",
            prompt_original="A fake user email is person@example.test",
            prompt_redacted=None,
            status=RequestStatus.blocked,
            token_count_prompt=0,
            latency_ms=0,
            provider_status_code=403,
            error_message="Blocked by policy",
            error_type="policy_violation",
            error_code="blocked",
            created_at=datetime.utcnow(),
            response=None,
            violations=[],
        )
    )

    assert detail.id == request_id
    assert detail.pii_detections == []
    assert detail.violations == []


def test_gateway_trace_preview_redacts_sensitive_patterns():
    text = _sanitize_trace_text(
        "email person@example.test token=secret-value card 4111 1111 1111 1111"
    )

    assert "person@example.test" not in text
    assert "secret-value" not in text
    assert "4111 1111 1111 1111" not in text
    assert "[redacted-email]" in text
    assert "token=[redacted]" in text


def test_provider_auth_error_does_not_expose_provider_key_fragments():
    raw_error = (
        '{"error":{"message":"Incorrect API key provided: '
        'gsk_sIF7***************************************hBBJ. You can find your API key '
        'at https://platform.openai.com/account/api-keys.","type":"invalid_request_error"}}'
    )

    normalized = OpenAIAdapter().normalize_error(401, raw_error)

    assert normalized["error"]["type"] == "provider_auth_error"
    assert normalized["error"]["code"] == "invalid_provider_credentials"
    assert "gsk_" not in normalized["error"]["message"]
    assert "sIF7" not in normalized["error"]["message"]
    assert "hBBJ" not in normalized["error"]["message"]


def test_sanitize_text_redacts_openai_and_groq_key_fragments():
    sanitized = sanitize_text("bad keys sk-proj-abc1234567890 and gsk_sIF7********hBBJ")

    assert "sk-proj" not in sanitized
    assert "gsk_" not in sanitized
    assert sanitized.count("[redacted]") >= 2


def test_provider_credential_reference_detection():
    assert is_vault_provider_reference(
        "authclaw/tenants/tenant-id/integrations/provider-id"
    )
    assert not is_vault_provider_reference("encrypted-fernet-or-envelope-value")


@pytest.mark.asyncio
async def test_openai_compatible_adapter_retrieves_provider_key_without_db_secret(monkeypatch):
    async def fake_retrieve(_provider):
        return "provider-secret"

    monkeypatch.setattr("app.core.providers.adapters.openai.retrieve_provider_api_key", fake_retrieve)
    provider = SimpleNamespace(
        name="Groq Provider",
        type=ProviderType.groq,
        config={"base_url": "https://api.groq.com/openai/v1"},
        api_key_encrypted="authclaw/tenants/t/integrations/p",
    )

    url, headers = await OpenAIAdapter().get_connection_details(provider)

    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert headers["Authorization"] == "Bearer provider-secret"


@pytest.mark.asyncio
async def test_openai_compatible_adapter_defaults_groq_named_provider_to_groq_url(monkeypatch):
    async def fake_retrieve(_provider):
        return "provider-secret"

    monkeypatch.setattr("app.core.providers.adapters.openai.retrieve_provider_api_key", fake_retrieve)
    provider = SimpleNamespace(
        name="Groq API",
        type=ProviderType.openai,
        config={},
        api_key_encrypted="authclaw/tenants/t/integrations/p",
    )

    url, headers = await OpenAIAdapter().get_connection_details(provider)

    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert headers["Authorization"] == "Bearer provider-secret"


def test_gateway_mvp_routes_are_registered():
    paths = {route.path for route in app.routes}

    assert "/v1/chat/completions" in paths
    assert "/api/v1/gateway/providers" in paths
    assert "/api/v1/gateway/routes" in paths
    assert "/api/v1/gateway/api-keys" in paths
