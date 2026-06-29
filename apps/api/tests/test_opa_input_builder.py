import json
import uuid

from app.core.policy.opa_input import OpaInputBuilder, OpaInputContext


def _build_document():
    tenant_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    route_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    provider_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    policy_id = uuid.UUID("44444444-4444-4444-4444-444444444444")
    context = OpaInputContext(
        tenant_id=tenant_id,
        route_id=route_id,
        provider_id=provider_id,
        provider="groq api",
        provider_type="groq",
        model="llama3-8b-8192",
        direction="inbound",
        request_metadata={
            "stream": False,
            "tenant_id": "99999999-9999-9999-9999-999999999999",
            "raw_prompt": "here is my email ravi@example.com",
            "messages": [{"role": "user", "content": "token=demo-secret"}],
            "api_key": "gsk_fake_secret_key_value",
            "vault_reference_id": "vault://provider/groq/key",
            "headers": {"Authorization": "Bearer sk-fakeprovidersecret"},
        },
        detected_entities=[
            {"entity_type": "EMAIL_ADDRESS", "start": 11, "end": 27, "score": 0.91, "text": "ravi@example.com"},
            {"score": 0.8, "end": 15, "entity_type": "PHONE_NUMBER", "start": 3},
        ],
        entity_types=["PHONE_NUMBER", "EMAIL_ADDRESS", "EMAIL_ADDRESS"],
        policy_id=policy_id,
        policy_version="authclaw.policy/v1",
        normalized_policy={
            "rules": [
                {
                    "type": "pii_redact",
                    "action": "warn",
                    "conditions": {"pii_types": ["EMAIL_ADDRESS"], "redaction_mode": "MASK"},
                }
            ],
            "raw_provider_payload": {"token": "demo-secret"},
        },
        keyword_matches=["token=", "confidential"],
        risk_metadata={"max_risk_level": "HIGH", "private_key": "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----"},
        compliance_metadata={"framework": "SOC2"},
        gateway_metadata={"shadow_mode": False, "latency_ms": 12},
    )
    return OpaInputBuilder().build(context)


def test_opa_input_generation_is_deterministic_and_stably_ordered():
    first = _build_document()
    second = _build_document()

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert list(first) == sorted(first)
    assert first["entities"]["types"] == ["EMAIL_ADDRESS", "PHONE_NUMBER"]
    assert [item["entity_type"] for item in first["entities"]["detected"]] == ["EMAIL_ADDRESS", "PHONE_NUMBER"]


def test_opa_input_uses_context_tenant_and_omits_cross_tenant_metadata():
    document = _build_document()

    assert document["tenant"]["id"] == "11111111-1111-1111-1111-111111111111"
    rendered = json.dumps(document, sort_keys=True)
    assert "99999999-9999-9999-9999-999999999999" not in rendered


def test_opa_input_sanitizes_raw_prompts_secrets_and_vault_references():
    document = _build_document()
    rendered = json.dumps(document, sort_keys=True)

    assert "raw_prompt" not in rendered
    assert "messages" not in rendered
    assert "ravi@example.com" not in rendered
    assert "demo-secret" not in rendered
    assert "gsk_fake_secret_key_value" not in rendered
    assert "sk-fakeprovidersecret" not in rendered
    assert "vault://provider" not in rendered
    assert "[redacted]" in rendered


def test_opa_input_omits_missing_optional_fields_without_inventing_metadata():
    tenant_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    document = OpaInputBuilder().build(OpaInputContext(tenant_id=tenant_id))

    assert document == {
        "request": {"direction": "INBOUND", "type": "chat.completions"},
        "sanitization_version": "opa-input/v1",
        "tenant": {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
    }


def test_opa_input_sanitizes_nested_structures_without_reordering_lists():
    document = OpaInputBuilder().build(
        OpaInputContext(
            tenant_id="tenant-a",
            request_metadata={
                "safe_list": ["first", "second"],
                "nested": {
                    "access_token": "demo-token",
                    "safe": {"b": 2, "a": 1},
                },
            },
        )
    )

    assert document["request"]["metadata"]["safe_list"] == ["first", "second"]
    assert list(document["request"]["metadata"]["nested"]["safe"]) == ["a", "b"]
    assert document["request"]["metadata"]["nested"]["access_token"] == "[redacted]"
