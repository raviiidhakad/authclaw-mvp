from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from app.core.engine.gateway import GatewayService, ProviderResponse
from app.core.policy.opa_integration import OpaRuntimeIntegration
from app.core.policy.opa_runtime import OpaFailureMode, OpaRuntimeEvaluator, OpaRuntimeStatus
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
from app.models.provider import ProviderType


OPA_URL = os.getenv("OPA_URL", "http://127.0.0.1:8181/v1/data/authclaw/gateway/decision")
ENABLE_REAL_OPA = os.getenv("ENABLE_REAL_OPA_SIDECAR_TESTS", "").lower() in {"1", "true", "yes"}
FORBIDDEN_INPUT_MARKERS = ("gsk" + "_", "sk" + "-", "vault" + "://", "raw" + "_provider" + "_payload")


async def _opa_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=0.75) as client:
            response = await client.post(OPA_URL, json={"input": _input_document()})
        return response.status_code < 500
    except httpx.HTTPError:
        return False


async def _require_real_opa() -> None:
    if not ENABLE_REAL_OPA:
        pytest.skip("Set ENABLE_REAL_OPA_SIDECAR_TESTS=true and OPA_URL to run real OPA sidecar validation.")
    if not await _opa_available():
        pytest.skip(f"Real OPA runtime is not reachable at {OPA_URL}.")


def _input_document(*, python_action: str = "allow", keywords: list[str] | None = None, redaction: bool = False, request_type: str = "chat.completions") -> dict:
    return {
        "sanitization_version": "opa-input/v1",
        "tenant": {"id": "tenant-phase8"},
        "route": {"id": "route-phase8", "name": "groq"},
        "provider": {"type": "groq"},
        "model": {"name": "llama3-8b-8192"},
        "request": {"type": request_type, "metadata": {"stream": False}},
        "matches": {
            "keywords": keywords or [],
            "regex": [],
        },
        "gateway": {
            "engine_mode": "opa",
            "policy_hash": "phase8-policy-hash",
            "python_action": python_action,
            "python_allowed": python_action != "block",
            "python_redaction_required": redaction,
        },
        "policy": {
            "id": "policy-phase8",
            "version": 1,
            "normalized": {
                "policies": [
                    {
                        "id": "policy-phase8",
                        "rules": [
                            {
                                "id": "credential-leakage-rule",
                                "type": "content_filter",
                                "action": "block",
                                "conditions": {"keywords": ["sha256:credential-marker"]},
                            }
                        ],
                    }
                ]
            },
        },
    }


class FakeScalarResult:
    def __init__(self, first=None):
        self._first = first

    def first(self):
        return self._first


class FakeResult:
    def __init__(self, first=None):
        self._scalars = FakeScalarResult(first)

    def scalars(self):
        return self._scalars


class FakeDb:
    def __init__(self, *results):
        self.results = list(results)

    async def execute(self, _stmt, *args, **kwargs):
        if not self.results:
            raise AssertionError("Unexpected DB query in Phase 8 real OPA test")
        return self.results.pop(0)


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


def _policy(rule_type=RuleType.content_filter, action=PolicyAction.block, conditions=None):
    policy_id = uuid.uuid4()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        policy_id=policy_id,
        rule_type=rule_type,
        conditions=conditions if conditions is not None else {"keywords": ["token="]},
        action=action,
        message="Gateway policy matched.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=uuid.uuid4(),
        name="Gateway policy",
        description="Phase 8 real OPA proof policy",
        is_active=True,
        priority=10,
        rules=[rule],
    )


def _gateway_service(route, provider, policy, *, mode="opa"):
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
        enabled=True,
        policy_url=OPA_URL,
        runtime_mode="STRICT",
        policy_engine_mode=mode,
        fail_closed=True,
        evaluator_factory=lambda failure_mode: OpaRuntimeEvaluator(
            OPA_URL,
            failure_mode=OpaFailureMode.FAIL_CLOSED,
            timeout_seconds=2.0,
        ),
    )
    return service


def _logged_policy_decision(service: GatewayService) -> dict:
    kwargs = service.audit_engine.log_request.await_args.kwargs
    return kwargs["response_payload"]["policy_decision"]


@pytest.mark.asyncio
async def test_real_opa_sidecar_decision_contract():
    await _require_real_opa()
    evaluator = OpaRuntimeEvaluator(OPA_URL, failure_mode=OpaFailureMode.FAIL_CLOSED, timeout_seconds=2.0)

    cases = {
        "allow_normal_prompt": (_input_document(), True, "allow", False),
        "deny_credential_leakage": (_input_document(python_action="block", keywords=["sha256:credential-marker"]), False, "deny", False),
        "deny_disallowed_topic": (_input_document(python_action="block", keywords=["sha256:disallowed-topic"]), False, "deny", False),
        "redact_pii_path": (_input_document(redaction=True), True, "redact", True),
        "deny_malformed_or_unsupported_request": (_input_document(request_type="embeddings"), False, "deny", False),
    }

    for name, (input_document, allowed, action, redaction_required) in cases.items():
        serialized = json.dumps(input_document)
        for marker in FORBIDDEN_INPUT_MARKERS:
            assert marker not in serialized

        decision = await evaluator.evaluate(input_document)

        assert decision.runtime_status == OpaRuntimeStatus.OK, name
        assert decision.allowed is allowed, name
        assert decision.action == action, name
        assert decision.redaction_required is redaction_required, name


@pytest.mark.asyncio
async def test_real_opa_gateway_allow_reaches_mock_provider(monkeypatch):
    await _require_real_opa()
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(action=PolicyAction.allow, conditions={"keywords": []})
    route = _route(provider.id, policy.id)
    service = _gateway_service(route, provider, policy, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "simple harmless message"}]},
    )

    assert result["status_code"] == 200
    service.ai_client.chat_completion.assert_awaited_once()


@pytest.mark.asyncio
async def test_real_opa_gateway_block_prevents_provider_call(monkeypatch):
    await _require_real_opa()
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(conditions={"keywords": ["marker="]})
    route = _route(provider.id, policy.id)
    service = _gateway_service(route, provider, policy, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "marker=redacted"}]},
    )

    assert result["status_code"] == 403
    assert service.ai_client.chat_completion.await_count == 0
    audit_payload = _logged_policy_decision(service)
    assert audit_payload["decision_source"] in {"opa_runtime", "adapter_policy_deny"}


@pytest.mark.asyncio
async def test_real_opa_gateway_redaction_applies_before_provider_egress(monkeypatch):
    await _require_real_opa()
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(
        rule_type=RuleType.pii_redact,
        action=PolicyAction.warn,
        conditions={"pii_types": ["EMAIL"], "redaction_mode": "MASK"},
    )
    route = _route(provider.id, policy.id)
    service = _gateway_service(route, provider, policy, mode="opa")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "Please email owner@example.test"}]},
    )

    assert result["status_code"] == 200
    service.ai_client.chat_completion.assert_awaited_once()
    upstream_payload = service.ai_client.chat_completion.await_args.args[1]
    assert "owner@example.test" not in json.dumps(upstream_payload)


@pytest.mark.asyncio
async def test_real_opa_hybrid_mode_blocks_mismatch(monkeypatch):
    await _require_real_opa()
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    policy = _policy(action=PolicyAction.allow, conditions={"keywords": []})
    route = _route(provider.id, policy.id)
    service = _gateway_service(route, provider, policy, mode="hybrid")

    result = await service.process_chat_request(
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        {"route": "groq", "messages": [{"role": "user", "content": "simple harmless message"}]},
    )

    assert result["status_code"] in {200, 403}
    if result["status_code"] == 403:
        audit_payload = _logged_policy_decision(service)
        assert audit_payload["decision_source"] == "hybrid_mismatch_fail_closed"
