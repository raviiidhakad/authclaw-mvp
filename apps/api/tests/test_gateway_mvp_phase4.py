import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.api.v1.endpoints.gateway_routes import _ensure_tenant_policy
from app.api.v1.endpoints.policies import test_policy as run_policy_test_endpoint
from app.api.v1.endpoints.policies import validate_policy
from app.core.engine.gateway import GatewayService
from app.core.policy.yaml_policy import (
    OpaEvaluationContext,
    OpaPolicyAdapter,
    OpaRuntimeKind,
    OpaRuntimeMode,
    PythonPolicyAdapter,
    export_policy_yaml,
    policy_from_normalized,
    validate_policy_yaml,
)
from app.core.exceptions import BadRequestException
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
from app.models.provider import ProviderType
from app.schemas.policy import PolicyTestRequest, PolicyYamlRequest


VALID_YAML = """
version: authclaw.policy/v1
name: Credential leakage block
description: Blocks demo credential markers.
enabled: true
priority: 10
rules:
  - type: content_filter
    action: block
    message: Credential marker blocked.
    conditions:
      keywords:
        - token=
  - type: pii_redact
    action: warn
    conditions:
      pii_types: [EMAIL_ADDRESS]
      redaction_mode: MASK
"""


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
            raise AssertionError("Unexpected DB query in phase 4 test")
        return self.results.pop(0)

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def flush(self):
        return None


def _provider():
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="groq api",
        type=ProviderType.groq,
        config={"base_url": "https://api.groq.com/openai/v1"},
        is_active=True,
    )


def _route(provider_id, policy_id=None):
    config = {"model": "llama3-8b-8192"}
    if policy_id:
        config["policy_id"] = str(policy_id)
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="groq",
        provider_id=provider_id,
        is_default=False,
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
        rule_type=RuleType.content_filter,
        conditions={"keywords": ["token="]},
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
        priority=10,
        rules=[rule],
    )


def _service(db):
    service = GatewayService(db)
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock()
    return service


def test_yaml_valid_policy_compiles_and_exports_without_raw_secret_markers():
    result = validate_policy_yaml(VALID_YAML)

    assert result.valid is True
    assert result.normalized["version"] == "authclaw.policy/v1"
    assert result.normalized["rules"][0]["conditions"]["keywords"] == ["token="]
    policy = policy_from_normalized(result.normalized, uuid.uuid4())
    exported = export_policy_yaml(policy)
    assert "authclaw.policy/v1" in exported
    assert "gsk_" not in exported
    assert "vault://" not in exported


def test_yaml_malformed_invalid_regex_and_allow_all_are_rejected():
    malformed = validate_policy_yaml("version: [")
    invalid_regex = validate_policy_yaml(
        """
version: authclaw.policy/v1
name: Bad regex
rules:
  - type: content_filter
    action: block
    conditions:
      regex_patterns: ["["]
"""
    )
    allow_all = validate_policy_yaml(
        """
version: authclaw.policy/v1
name: Unsafe allow
rules:
  - type: custom
    action: allow
    conditions: {}
"""
    )

    assert malformed.valid is False
    assert malformed.errors[0].code == "malformed_yaml"
    assert invalid_regex.valid is False
    assert any(error.code == "invalid_regex" for error in invalid_regex.errors)
    assert allow_all.valid is False
    assert any(error.code == "unsafe_allow_all" for error in allow_all.errors)


def test_opa_adapter_seam_can_be_swapped():
    class DenyAdapter(OpaPolicyAdapter):
        name = "test_deny_adapter"

        def validate(self, normalized_policy):
            return []

        def evaluate(self, text, normalized_policy):
            return {"allowed": False, "action": "block", "matched_rules": [], "redaction_required": False, "reason": "adapter deny"}

    result = validate_policy_yaml(VALID_YAML, adapter=DenyAdapter())

    assert result.valid is True
    assert result.opa_adapter == "test_deny_adapter"


def test_opa_adapter_contract_preserves_python_compatibility():
    validation = validate_policy_yaml(VALID_YAML)
    adapter = PythonPolicyAdapter()
    decision = adapter.evaluate(
        "A demo token=secret-value should be blocked.",
        validation.normalized,
        OpaEvaluationContext(runtime_mode=OpaRuntimeMode.COMPATIBILITY, target_model="llama3-8b-8192"),
    )

    assert adapter.capabilities.runtime_kind == OpaRuntimeKind.PYTHON
    assert adapter.capabilities.supports_strict_mode is True
    assert adapter.capabilities.supports_compatibility_mode is True
    assert adapter.capabilities.full_opa_runtime is False
    assert decision["allowed"] is False
    assert decision["action"] == "block"
    assert set(decision) == {"allowed", "action", "matched_rules", "redaction_required", "reason"}


@pytest.mark.asyncio
async def test_policy_validate_and_test_endpoints_are_safe():
    validation = await validate_policy(PolicyYamlRequest(yaml_source=VALID_YAML), _tenant=SimpleNamespace(), _user=SimpleNamespace())
    decision = await run_policy_test_endpoint(
        PolicyTestRequest(yaml_source=VALID_YAML, sample_text="A demo token=secret-value should be blocked."),
        tenant=SimpleNamespace(id=uuid.uuid4()),
        db=FakeDb(),
        _user=SimpleNamespace(),
    )

    assert validation.valid is True
    assert decision.blocked is True
    assert decision.action == "block"
    rendered = str(decision.model_dump())
    assert "secret-value" not in rendered
    assert "token=secret-value" not in rendered


@pytest.mark.asyncio
async def test_disabled_or_cross_tenant_policy_cannot_attach_to_route():
    with pytest.raises(BadRequestException):
        await _ensure_tenant_policy(uuid.uuid4(), uuid.uuid4(), FakeDb(FakeResult(None)))


@pytest.mark.asyncio
async def test_route_attached_policy_blocks_before_provider_call(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy(tenant_id)
    route = _route(provider.id, policy.id)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))

    result = await service.process_chat_request(
        tenant_id,
        uuid.uuid4(),
        uuid.uuid4(),
        {
            "route": "groq",
            "model": "ignored-client-model",
            "messages": [{"role": "user", "content": "A demo token=secret-value should be blocked."}],
            "stream": False,
        },
    )

    assert result["status_code"] == 403
    service.ai_client.chat_completion.assert_not_called()
    audit_payload = service.audit_engine.log_request.await_args.kwargs["response_payload"]
    assert audit_payload["policy_decision"]["route_policy_id"] == str(policy.id)
    assert "secret-value" not in str(result["data"])


@pytest.mark.asyncio
async def test_route_policy_evaluator_exception_fails_closed(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy(tenant_id)
    route = _route(provider.id, policy.id)
    service = _service(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.opa_integration.adapter.evaluate = Mock(side_effect=RuntimeError("policy stack trace token=secret"))

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

    assert result["status_code"] == 503
    assert result["data"]["error"]["code"] == "policy_evaluation_failed"
    service.ai_client.chat_completion.assert_not_called()
    assert "secret" not in str(result["data"])
