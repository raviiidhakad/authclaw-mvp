import json

import httpx
import pytest

from app.core.policy.opa_input import OpaInputBuilder, OpaInputContext
from app.core.policy.opa_runtime import OpaErrorCategory, OpaFailureMode, OpaRuntimeEvaluator, OpaRuntimeStatus


def _input_document():
    return OpaInputBuilder().build(
        OpaInputContext(
            tenant_id="tenant-a",
            route_id="route-a",
            provider="groq",
            provider_type="groq",
            model="llama3-8b-8192",
            entity_types=["EMAIL_ADDRESS"],
            request_metadata={"stream": False},
        )
    )


def _client(body=None, *, status_code=200, exc=None, text=None, capture=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(json.loads(request.content.decode("utf-8")))
        if exc is not None:
            raise exc("mock failure token=demo-secret", request=request)
        if text is not None:
            return httpx.Response(status_code, text=text, request=request)
        return httpx.Response(status_code, json=body, request=request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_opa_runtime_successful_allow_decision():
    captured = []
    async with _client(
        {
            "result": {
                "allow": True,
                "action": "allow",
                "reason": "policy allowed",
                "matched_rules": [{"id": "allow-default"}],
                "redaction_required": False,
                "metadata": {"policy_version": "v1"},
            }
        },
        capture=captured,
    ) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    assert captured[0]["input"]["sanitization_version"] == "opa-input/v1"
    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.reason == "policy allowed"
    assert decision.matched_rules == [{"id": "allow-default"}]
    assert decision.runtime_status == OpaRuntimeStatus.OK
    assert decision.error_category is None
    assert decision.http_status == 200
    assert decision.as_dict()["metadata"] == {"failure_mode": "fail_closed", "policy_version": "v1", "source": "opa"}


@pytest.mark.asyncio
async def test_opa_runtime_successful_deny_decision():
    async with _client({"result": {"allow": False, "deny": ["pii blocked"], "matched_rules": ["pii_email"]}}) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    assert decision.allowed is False
    assert decision.action == "deny"
    assert decision.reason == "pii blocked"
    assert decision.matched_rules == [{"id": "pii_email"}]
    assert decision.runtime_status == OpaRuntimeStatus.OK


@pytest.mark.asyncio
async def test_opa_runtime_missing_decision_fields_fail_closed():
    async with _client({"result": {"reason": "missing allow"}}) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    assert decision.allowed is False
    assert decision.action == "deny"
    assert decision.runtime_status == OpaRuntimeStatus.ERROR
    assert decision.error_category == OpaErrorCategory.MISSING_DECISION_FIELDS
    assert decision.http_status == 200


@pytest.mark.asyncio
async def test_opa_runtime_malformed_json_fail_closed():
    async with _client(text="not-json token=demo-secret") as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    rendered = json.dumps(decision.as_dict(), sort_keys=True)
    assert decision.allowed is False
    assert decision.error_category == OpaErrorCategory.MALFORMED_JSON
    assert "demo-secret" not in rendered


@pytest.mark.asyncio
async def test_opa_runtime_timeout_fail_closed():
    async with _client(exc=httpx.ReadTimeout) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    assert decision.allowed is False
    assert decision.error_category == OpaErrorCategory.TIMEOUT
    assert decision.runtime_status == OpaRuntimeStatus.ERROR


@pytest.mark.asyncio
async def test_opa_runtime_http_failure_sanitizes_provider_body():
    async with _client({"error": "opa failed sk-provider-secret"}, status_code=503) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    rendered = json.dumps(decision.as_dict(), sort_keys=True)
    assert decision.allowed is False
    assert decision.error_category == OpaErrorCategory.HTTP_ERROR
    assert decision.http_status == 503
    assert "sk-provider-secret" not in rendered


@pytest.mark.asyncio
async def test_opa_runtime_unreachable_server_fail_closed():
    async with _client(exc=httpx.ConnectError) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(_input_document())

    assert decision.allowed is False
    assert decision.error_category == OpaErrorCategory.CONNECTION_FAILURE


@pytest.mark.asyncio
async def test_opa_runtime_fail_open_behavior():
    async with _client(exc=httpx.ConnectError) as client:
        decision = await OpaRuntimeEvaluator(
            "http://opa/v1/data/authclaw/allow",
            failure_mode=OpaFailureMode.FAIL_OPEN,
            http_client=client,
        ).evaluate(_input_document())

    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.runtime_status == OpaRuntimeStatus.ERROR
    assert decision.error_category == OpaErrorCategory.CONNECTION_FAILURE
    assert decision.metadata["failure_mode"] == "fail_open"


@pytest.mark.asyncio
async def test_opa_runtime_fail_closed_behavior():
    async with _client(exc=httpx.ConnectError) as client:
        decision = await OpaRuntimeEvaluator(
            "http://opa/v1/data/authclaw/allow",
            failure_mode=OpaFailureMode.FAIL_CLOSED,
            http_client=client,
        ).evaluate(_input_document())

    assert decision.allowed is False
    assert decision.action == "deny"
    assert decision.metadata["failure_mode"] == "fail_closed"


@pytest.mark.asyncio
async def test_opa_runtime_deterministic_normalized_output_and_response_sanitization():
    body = {
        "result": {
            "allowed": True,
            "metadata": {"b": 2, "a": 1, "api_key": "gsk_fake_secret_value", "vault": "vault://secret/ref"},
            "matched_rules": [{"rule": "b"}, {"rule": "a"}],
            "reason": "allowed without token=demo-secret",
        }
    }
    async with _client(body) as client:
        evaluator = OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client)
        first = (await evaluator.evaluate(_input_document())).as_dict()
        second = (await evaluator.evaluate(_input_document())).as_dict()

    rendered = json.dumps(first, sort_keys=True)
    assert first == second
    assert list(first) == [
        "allowed",
        "action",
        "reason",
        "matched_rules",
        "redaction_required",
        "runtime_status",
        "error_category",
        "http_status",
        "metadata",
    ]
    assert first["matched_rules"] == [{"rule": "a"}, {"rule": "b"}]
    assert first["metadata"]["api_key"] == "[redacted]"
    assert "gsk_fake_secret_value" not in rendered
    assert "demo-secret" not in rendered
    assert "vault://secret/ref" not in rendered


@pytest.mark.asyncio
async def test_opa_runtime_rejects_non_t2_input_without_http_call():
    calls = []
    async with _client({"result": {"allow": True}}, capture=calls) as client:
        decision = await OpaRuntimeEvaluator("http://opa/v1/data/authclaw/allow", http_client=client).evaluate(
            {"tenant": {"id": "tenant-a"}}
        )

    assert calls == []
    assert decision.allowed is False
    assert decision.error_category == OpaErrorCategory.INVALID_INPUT
