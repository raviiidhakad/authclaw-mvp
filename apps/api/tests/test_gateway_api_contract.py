import uuid
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api.v1.endpoints.gateway import _extract_gateway_token, _sanitize_trace_text
from app.core.exceptions import UnauthorizedException
from app.models.gateway import RequestStatus
from app.schemas.gateway import GatewayRequestDetail


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
