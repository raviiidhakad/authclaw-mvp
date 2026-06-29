import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.api.v1.endpoints.health_security import security_pipeline_health
from app.core.engine.gateway import GatewayService, ProviderResponse
from app.core.policy.cache import policy_cache
from app.core.policy.opa_integration import (
    OpaDecisionCache,
    OpaIntegrationResult,
    OpaPolicyVersionTracker,
    OpaRuntimeIntegration,
    OpaRuntimeMetrics,
    opa_decision_cache,
)
from app.core.policy.opa_runtime import OpaErrorCategory, OpaFailureMode, OpaRuntimeDecision, OpaRuntimeStatus
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

    async def execute(self, _stmt):
        if not self.results:
            raise AssertionError("Unexpected DB query")
        return self.results.pop(0)


class FakeEvaluator:
    def __init__(self, decision):
        self.decision = decision
        self.calls = 0

    async def evaluate(self, _input_document):
        self.calls += 1
        return self.decision


def _policy(priority=10, keyword="token="):
    tenant_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        policy_id=policy_id,
        rule_type=RuleType.content_filter,
        conditions={"keywords": [keyword]},
        action=PolicyAction.block,
        message="Credential marker blocked.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=tenant_id,
        name="Credential leakage block",
        description="Blocks demo credential markers.",
        is_active=True,
        priority=priority,
        rules=[rule],
    )


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


def test_policy_version_hash_is_deterministic_and_changes_with_policy_metadata():
    policy = _policy(keyword="token=")
    first = OpaPolicyVersionTracker.from_policies([policy])
    second = OpaPolicyVersionTracker.from_policies([policy])
    changed = OpaPolicyVersionTracker.from_policies([_policy(keyword="secret=")])

    assert first == second
    assert first.policy_version.startswith("sha256:")
    assert len(first.policy_hash) == 64
    assert first.policy_hash != changed.policy_hash


def test_decision_cache_is_tenant_route_model_and_policy_hash_aware():
    cache = OpaDecisionCache()
    tenant_id = uuid.uuid4()
    route_id = uuid.uuid4()
    input_document = {"sanitization_version": "opa-input/v1", "tenant": {"id": str(tenant_id)}}
    decision = OpaRuntimeDecision(allowed=True, action="allow", reason="ok")
    key = cache.make_key(
        tenant_id=tenant_id,
        route_id=route_id,
        model="llama3-8b-8192",
        policy_hash="abc",
        input_document=input_document,
    )
    different_model_key = cache.make_key(
        tenant_id=tenant_id,
        route_id=route_id,
        model="other-model",
        policy_hash="abc",
        input_document=input_document,
    )

    cache.set(tenant_id, key, decision)

    assert cache.get(tenant_id, key) == decision
    assert cache.get(uuid.uuid4(), key) is None
    assert cache.get(tenant_id, different_model_key) is None
    assert cache.invalidate_tenant(tenant_id) == 1
    assert cache.get(tenant_id, key) is None


@pytest.mark.asyncio
async def test_policy_cache_invalidation_also_clears_opa_decision_cache():
    tenant_id = uuid.uuid4()
    key = opa_decision_cache.make_key(
        tenant_id=tenant_id,
        route_id=uuid.uuid4(),
        model="llama3-8b-8192",
        policy_hash="abc",
        input_document={"sanitization_version": "opa-input/v1"},
    )
    opa_decision_cache.set(tenant_id, key, OpaRuntimeDecision(allowed=True, action="allow", reason="ok"))

    await policy_cache.invalidate(tenant_id)

    assert opa_decision_cache.get(tenant_id, key) is None


@pytest.mark.asyncio
async def test_opa_runtime_integration_records_metrics_and_uses_cache(monkeypatch):
    tenant_id = uuid.uuid4()
    policy = _policy()
    provider = _provider()
    route = _route(provider.id, policy.id)
    decision = OpaRuntimeDecision(
        allowed=True,
        action="allow",
        reason="ok",
        matched_rules=[{"id": "allow-default"}],
        runtime_status=OpaRuntimeStatus.OK,
    )
    evaluator = FakeEvaluator(decision)
    cache = OpaDecisionCache()
    metrics = OpaRuntimeMetrics()
    published = []
    monkeypatch.setattr(OpaRuntimeIntegration, "_publish_decision_event", staticmethod(lambda *_args: published.append(_args[-1])))
    integration = OpaRuntimeIntegration(
        enabled=True,
        policy_url="http://opa/v1/data/authclaw/gateway/decision",
        runtime_mode="STRICT",
        cache=cache,
        metrics=metrics,
        evaluator_factory=lambda _mode: evaluator,
    )

    first = await integration.evaluate_gateway(
        tenant_id=tenant_id,
        api_key_id=uuid.uuid4(),
        route=route,
        provider=provider,
        model="llama3-8b-8192",
        policies=[policy],
        action="allow",
        matched_rule_count=0,
        request_metadata={"stream": False},
    )
    second = await integration.evaluate_gateway(
        tenant_id=tenant_id,
        api_key_id=uuid.uuid4(),
        route=route,
        provider=provider,
        model="llama3-8b-8192",
        policies=[policy],
        action="allow",
        matched_rule_count=0,
        request_metadata={"stream": False},
    )

    assert isinstance(first, OpaIntegrationResult)
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert first.policy_hash == second.policy_hash
    assert evaluator.calls == 1
    assert metrics.snapshot()["cache_hits"] == 1
    assert metrics.snapshot()["cache_misses"] == 1
    assert metrics.snapshot()["allow_count"] == 1
    assert len(published) == 2
    assert "decision_id" in first.audit_metadata()
    assert published[0].decision.allowed is True


@pytest.mark.asyncio
async def test_gateway_opa_runtime_deny_blocks_before_provider_call(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy()
    route = _route(provider.id, policy.id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock(
        return_value=ProviderResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "normal response"}}], "usage": {}},
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=7,
        )
    )
    service.opa_integration = OpaRuntimeIntegration(
        enabled=True,
        policy_url="http://opa/v1/data/authclaw/gateway/decision",
        runtime_mode="STRICT",
        evaluator_factory=lambda _mode: FakeEvaluator(OpaRuntimeDecision(allowed=False, action="deny", reason="opa deny")),
    )

    result = await service.process_chat_request(
        tenant_id,
        uuid.uuid4(),
        uuid.uuid4(),
        {
            "route": "groq",
            "model": "ignored-client-model",
            "messages": [{"role": "user", "content": "normal sample"}],
            "stream": False,
        },
    )

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_awaited()
    event_payload = service.audit_engine.log_request.await_args.kwargs["evaluation_result"]
    assert event_payload.allowed is False
    audit_payload = service.audit_engine.log_request.await_args.kwargs["response_payload"]
    assert audit_payload["policy_decision"]["decision_source"] == "opa_runtime"
    assert audit_payload["policy_decision"]["opa"]["action"] == "deny"


@pytest.mark.asyncio
async def test_gateway_opa_strict_runtime_error_fails_closed(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy()
    route = _route(provider.id, policy.id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock()
    service.opa_integration = OpaRuntimeIntegration(
        enabled=True,
        policy_url="http://opa/v1/data/authclaw/gateway/decision",
        runtime_mode="STRICT",
        evaluator_factory=lambda _mode: FakeEvaluator(
            OpaRuntimeDecision(
                allowed=False,
                action="deny",
                reason="runtime unavailable",
                runtime_status=OpaRuntimeStatus.ERROR,
                error_category=OpaErrorCategory.CONNECTION_FAILURE,
            )
        ),
    )

    result = await service.process_chat_request(
        tenant_id,
        uuid.uuid4(),
        uuid.uuid4(),
        {
            "route": "groq",
            "model": "ignored-client-model",
            "messages": [{"role": "user", "content": "normal sample"}],
            "stream": False,
        },
    )

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_awaited()
    audit_payload = service.audit_engine.log_request.await_args.kwargs["response_payload"]
    assert audit_payload["policy_decision"]["decision_source"] == "opa_runtime"
    assert audit_payload["policy_decision"]["opa"]["runtime_status"] == "error"


@pytest.mark.asyncio
async def test_gateway_opa_compatibility_runtime_error_uses_python_adapter(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy()
    route = _route(provider.id, policy.id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock(
        return_value=ProviderResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "normal response"}}], "usage": {}},
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=7,
        )
    )
    service.opa_integration = OpaRuntimeIntegration(
        enabled=True,
        policy_url="http://opa/v1/data/authclaw/gateway/decision",
        runtime_mode="COMPATIBILITY",
        evaluator_factory=lambda _mode: FakeEvaluator(
            OpaRuntimeDecision(
                allowed=False,
                action="deny",
                reason="runtime unavailable",
                runtime_status=OpaRuntimeStatus.ERROR,
                error_category=OpaErrorCategory.CONNECTION_FAILURE,
            )
        ),
    )

    result = await service.process_chat_request(
        tenant_id,
        uuid.uuid4(),
        uuid.uuid4(),
        {
            "route": "groq",
            "model": "ignored-client-model",
            "messages": [{"role": "user", "content": "normal sample"}],
            "stream": False,
        },
    )

    assert result["status_code"] == 200
    service.ai_client.chat_completion.assert_awaited_once()
    event_payload = service.audit_engine.log_request.await_args.kwargs["evaluation_result"]
    assert event_payload.allowed is True
    gateway_event_payload = service.audit_engine.log_request.await_args.kwargs
    assert gateway_event_payload["evaluation_result"].action_taken == "allow"


@pytest.mark.asyncio
async def test_opa_health_component_reports_disabled_without_sensitive_url(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.ENABLE_OPA_RUNTIME_INTEGRATION", False)
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)

    response = await security_pipeline_health()

    assert response.status_code == 200
    body = response.body.decode("utf-8")
    assert "opa_runtime" in body
    assert "disabled" in body
    assert "http://opa" not in body


def test_runtime_mode_maps_strict_and_compatibility_to_failure_modes():
    strict_modes = []
    compat_modes = []
    OpaRuntimeIntegration(
        enabled=True,
        policy_url="http://opa",
        runtime_mode="STRICT",
        evaluator_factory=lambda mode: strict_modes.append(mode) or FakeEvaluator(OpaRuntimeDecision(True, "allow", "ok")),
    )._evaluator()
    OpaRuntimeIntegration(
        enabled=True,
        policy_url="http://opa",
        runtime_mode="COMPATIBILITY",
        evaluator_factory=lambda mode: compat_modes.append(mode) or FakeEvaluator(OpaRuntimeDecision(True, "allow", "ok")),
    )._evaluator()

    assert strict_modes == [OpaFailureMode.FAIL_CLOSED]
    assert compat_modes == [OpaFailureMode.FAIL_OPEN]
