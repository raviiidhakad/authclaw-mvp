import json
import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.engine.gateway import GatewayService, ProviderResponse
from app.core.policy.opa_integration import OpaRuntimeIntegration
from app.core.policy.opa_input import OpaInputBuilder, OpaInputContext
from app.core.policy.opa_runtime import OpaErrorCategory, OpaRuntimeDecision, OpaRuntimeStatus
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
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

    async def execute(self, _stmt, *args, **kwargs):
        if not self.results:
            raise AssertionError("Unexpected DB query in OPA phase 4 test")
        return self.results.pop(0)


class CapturingEvaluator:
    def __init__(self, decision):
        self.decision = decision
        self.calls = 0
        self.inputs = []

    async def evaluate(self, input_document):
        self.calls += 1
        self.inputs.append(input_document)
        return self.decision


def _provider():
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="groq api",
        type=ProviderType.groq,
        config={"base_url": "https://api.groq.com/openai/v1"},
        is_active=True,
    )


def _route(provider_id, policy_id):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="groq",
        provider_id=provider_id,
        is_default=False,
        is_active=True,
        redaction=RedactionStrategy.mask,
        config={"model": "llama3-8b-8192", "policy_id": str(policy_id)},
        created_at=datetime.utcnow(),
    )


def _policy(rule_type=RuleType.content_filter, action=PolicyAction.block, conditions=None, message=None):
    tenant_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        policy_id=policy_id,
        rule_type=rule_type,
        conditions=conditions if conditions is not None else {"keywords": ["token="]},
        action=action,
        message=message or "Gateway policy matched.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=tenant_id,
        name="Gateway policy",
        description="Phase 4 OPA proof policy",
        is_active=True,
        priority=10,
        rules=[rule],
    )


def _service(route, provider, policy, evaluator, *, mode="opa", runtime_mode="STRICT"):
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock(
        return_value=ProviderResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "safe provider response"}}], "usage": {}},
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=7,
        )
    )
    service.opa_integration = OpaRuntimeIntegration(
        enabled=mode in {"opa", "hybrid"},
        policy_url="http://opa/v1/data/authclaw/gateway/decision",
        runtime_mode=runtime_mode,
        policy_engine_mode=mode,
        evaluator_factory=lambda _mode: evaluator,
    )
    return service


@pytest.mark.asyncio
async def test_python_mode_preserves_existing_yaml_policy_enforcement(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy()
    route = _route(provider.id, policy.id)
    evaluator = CapturingEvaluator(OpaRuntimeDecision(True, "allow", "ok"))
    service = _service(route, provider, policy, evaluator, mode="python")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "token=demo-token-redacted"}]},
    )

    assert result["status_code"] == 403
    assert evaluator.calls == 0
    service.ai_client.chat_completion.assert_not_awaited()


@pytest.mark.asyncio
async def test_opa_allow_decision_allows_provider_call_with_sanitized_input(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(conditions={"keywords": ["token="]})
    route = _route(provider.id, policy.id)
    evaluator = CapturingEvaluator(OpaRuntimeDecision(True, "allow", "OPA allowed request."))
    service = _service(route, provider, policy, evaluator, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "hello without sensitive content"}]},
    )

    assert result["status_code"] == 200
    service.ai_client.chat_completion.assert_awaited_once()
    rendered_input = json.dumps(evaluator.inputs[0], sort_keys=True)
    assert "hello without sensitive content" not in rendered_input
    assert "vault://" not in rendered_input
    assert "gsk_" not in rendered_input
    assert evaluator.inputs[0]["gateway"]["engine_mode"] == "opa"


@pytest.mark.asyncio
async def test_opa_block_decision_prevents_provider_call(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy()
    route = _route(provider.id, policy.id)
    evaluator = CapturingEvaluator(
        OpaRuntimeDecision(
            False,
            "deny",
            "credential leakage",
            matched_rules=[{"id": "credential_leakage", "category": "credential"}],
        )
    )
    service = _service(route, provider, policy, evaluator, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "token=demo-token-redacted"}]},
    )

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_awaited()
    audit_payload = service.audit_engine.log_request.await_args.kwargs["response_payload"]
    assert audit_payload["policy_decision"]["decision_source"] == "opa_runtime"
    assert audit_payload["policy_decision"]["opa"]["matched_rules"][0]["id"] == "credential_leakage"


@pytest.mark.asyncio
async def test_opa_redaction_decision_uses_existing_safe_yaml_redaction(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(
        rule_type=RuleType.pii_redact,
        action=PolicyAction.warn,
        conditions={"pii_types": ["EMAIL"], "redaction_mode": "MASK"},
        message="Email must be redacted.",
    )
    route = _route(provider.id, policy.id)
    evaluator = CapturingEvaluator(
        OpaRuntimeDecision(
            True,
            "redact",
            "redaction required",
            matched_rules=[{"id": "pii_redaction_required", "category": "pii"}],
            redaction_required=True,
        )
    )
    service = _service(route, provider, policy, evaluator, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "contact ravii@example.test"}]},
    )

    assert result["status_code"] == 200
    sent_payload = service.ai_client.chat_completion.await_args.args[1]
    rendered_payload = json.dumps(sent_payload, sort_keys=True)
    assert "ravii@example.test" not in rendered_payload
    assert "[EMAIL]" in rendered_payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "decision",
    [
        OpaRuntimeDecision(False, "deny", "timeout", runtime_status=OpaRuntimeStatus.ERROR, error_category=OpaErrorCategory.TIMEOUT),
        OpaRuntimeDecision(False, "deny", "unavailable", runtime_status=OpaRuntimeStatus.ERROR, error_category=OpaErrorCategory.CONNECTION_FAILURE),
        OpaRuntimeDecision(False, "deny", "malformed", runtime_status=OpaRuntimeStatus.ERROR, error_category=OpaErrorCategory.MALFORMED_RESPONSE),
    ],
)
async def test_opa_runtime_errors_fail_closed_before_provider_call(monkeypatch, decision):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(conditions={"keywords": ["never-match"]})
    route = _route(provider.id, policy.id)
    evaluator = CapturingEvaluator(decision)
    service = _service(route, provider, policy, evaluator, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "normal sample"}]},
    )

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_awaited()
    audit_payload = service.audit_engine.log_request.await_args.kwargs["response_payload"]
    assert audit_payload["policy_decision"]["opa"]["runtime_status"] == "error"


@pytest.mark.asyncio
async def test_hybrid_mismatch_fails_closed(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(conditions={"keywords": ["token="]})
    route = _route(provider.id, policy.id)
    evaluator = CapturingEvaluator(OpaRuntimeDecision(True, "allow", "OPA allowed request."))
    service = _service(route, provider, policy, evaluator, mode="hybrid")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "token=demo-token-redacted"}]},
    )

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_awaited()
    audit_payload = service.audit_engine.log_request.await_args.kwargs["response_payload"]
    assert audit_payload["policy_decision"]["decision_source"] == "hybrid_mismatch_fail_closed"
    assert audit_payload["policy_decision"]["opa"]["error_category"] == "hybrid_mismatch"


def test_opa_input_builder_strips_raw_prompt_secrets_and_vault_refs():
    document = OpaInputBuilder().build(
        OpaInputContext(
            tenant_id=uuid.uuid4(),
            request_metadata={
                "prompt": "raw prompt with sk-testsecret",
                "authorization": "Bearer ac_secret",
                "vault_reference": "vault://secret/path",
                "safe": "metadata",
            },
            gateway_metadata={
                "provider_api_key": "gsk_fake_secret_value",
                "raw_provider_payload": {"content": "should not be present"},
            },
        )
    )

    rendered = json.dumps(document, sort_keys=True)
    assert "raw prompt" not in rendered
    assert "sk-testsecret" not in rendered
    assert "vault://secret/path" not in rendered
    assert "gsk_fake_secret_value" not in rendered
    assert "raw_provider_payload" not in rendered
    assert document["request"]["metadata"]["authorization"] == "[redacted]"
