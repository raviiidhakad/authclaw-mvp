import inspect

from app.core.engine import streaming_contracts as contracts


def test_e2_3_contracts_are_non_executing_scaffolding():
    source = inspect.getsource(contracts)

    assert "from app.core.engine.gateway" not in source
    assert "from app.core.engine.streaming import StreamingEngine" not in source
    assert "from app.core.providers" not in source
    assert "from app.core.policy" not in source
    assert "from app.core.engine.token_vault" not in source


def test_e2_3_security_invariants_are_explicit_and_enabled():
    invariants = contracts.E2_3_SECURITY_INVARIANTS

    assert invariants.preserve_gateway_api is True
    assert invariants.preserve_provider_abstractions is True
    assert invariants.preserve_openai_compatible_sse is True
    assert invariants.preserve_reversible_tokenization is True
    assert invariants.preserve_yaml_opa_enforcement is True
    assert invariants.preserve_sanitized_audit_behavior is True
    assert invariants.preserve_fail_closed_posture is True


def test_e2_3_contract_shapes_are_sanitized_metadata_only():
    context = contracts.StreamingContext(
        tenant_id="tenant-1",
        stream_id="stream-1",
        direction=contracts.StreamingDirection.OUTBOUND,
        route_id="route-1",
        provider_name="groq",
        model="llama3-8b-8192",
        redaction_mode="mask",
        policy_id="policy-1",
    )
    window = contracts.StreamingTextWindow(
        text="[redacted]",
        safe_prefix="[redacted]",
        retained_suffix="",
        sequence=1,
        is_final=True,
    )
    decision = contracts.StreamingPolicyDecision(
        action=contracts.StreamingPolicyAction.REDACT,
        allowed=True,
        reason_code="pii_redacted",
        matched_rules=("rule-1",),
    )
    tokenized = contracts.StreamingTokenizationResult(
        text="[redacted]",
        mode="mask",
        token_count=1,
        entity_types=("EMAIL_ADDRESS",),
    )
    emission = contracts.StreamingEmission(
        kind=contracts.StreamingEmissionKind.DELTA,
        payload={"choices": [{"delta": {"content": "[redacted]"}}]},
        sequence=1,
    )

    assert context.direction == contracts.StreamingDirection.OUTBOUND
    assert window.is_final is True
    assert decision.action == contracts.StreamingPolicyAction.REDACT
    assert tokenized.entity_types == ("EMAIL_ADDRESS",)
    assert emission.kind == contracts.StreamingEmissionKind.DELTA

