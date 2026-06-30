from __future__ import annotations

import builtins
import os

import pytest

from authclaw import (
    ApiKeyConfigurationContract,
    AuthClawClient,
    AuthClawConfig,
    AuthenticationError,
    AuthorizationError,
    ChatCompletionRequestContract,
    ChatMessage,
    ConfigurationError,
    ConnectionError,
    MessageRole,
    MockTransport,
    RateLimitError,
    ServerError,
    TimeoutConfigurationContract,
    TransportRequest,
    TransportResponse,
    ValidationError,
    dumps_json,
)
from authclaw.retry import RetryPolicy
from authclaw.transport import RequestsTransport


def _chat_request() -> ChatCompletionRequestContract:
    return ChatCompletionRequestContract(
        model="llama",
        messages=(ChatMessage(role=MessageRole.USER, content="hello"),),
    )


def _chat_response() -> TransportResponse:
    return TransportResponse(
        status_code=200,
        json_body={
            "id": "chatcmpl_sdk",
            "model": "llama-3.3-70b-versatile",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 2,
                "total_tokens": 5,
            },
            "gateway": {
                "trace_id": "trace_sdk",
                "route_id": "route_1",
                "provider": "groq",
                "model": "llama",
                "redaction_mode": "mask",
                "policy_decision": "allow",
            },
        },
    )


def test_config_loads_from_contracts_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTHCLAW_TEST_KEY", "ac_env_key")

    config = AuthClawConfig.from_contracts(
        ApiKeyConfigurationContract(
            api_key_env_var="AUTHCLAW_TEST_KEY",
            base_url="http://localhost:8000/",
        )
    )

    assert config.api_key == "ac_env_key"
    assert config.base_url == "http://localhost:8000"
    assert config.build_url("chat/completions") == "http://localhost:8000/v1/chat/completions"
    assert config.build_url("/v1/health") == "http://localhost:8000/v1/health"


def test_config_rejects_empty_base_url() -> None:
    with pytest.raises(ConfigurationError):
        AuthClawConfig.from_contracts(ApiKeyConfigurationContract(base_url=" "))


def test_client_construction_rejects_mixed_config_and_direct_options() -> None:
    with pytest.raises(ConfigurationError):
        AuthClawClient(config=AuthClawConfig.from_contracts(), api_key="ac_test")


def test_health_and_version_use_transport_without_required_api_key() -> None:
    transport = MockTransport(
        [
            TransportResponse(status_code=200, json_body={"status": "ok"}),
            TransportResponse(status_code=200, json_body={"version": "0.11.0"}),
        ]
    )
    client = AuthClawClient(config=AuthClawConfig.from_contracts(), transport=transport)

    assert client.health() == {"status": "ok"}
    assert client.version() == {"version": "0.11.0"}
    assert transport.requests[0].url == "http://localhost:8000/v1/health"
    assert transport.requests[1].url == "http://localhost:8000/v1/version"
    assert "Authorization" not in transport.requests[0].headers


def test_chat_completion_serializes_request_and_parses_response() -> None:
    transport = MockTransport([_chat_response()])
    client = AuthClawClient(api_key="ac_sdk_test", transport=transport)
    request = ChatCompletionRequestContract(
        model="llama-3.3-70b-versatile",
        messages=(ChatMessage(role=MessageRole.USER, content="hello"),),
        stream=True,
    )

    response = client.create_chat_completion(request)

    sent = transport.requests[0]
    assert sent.method == "POST"
    assert sent.url == "http://localhost:8000/v1/chat/completions"
    assert sent.headers["Authorization"] == "Bearer ac_sdk_test"
    assert sent.headers["User-Agent"] == "authclaw-python/0.1.0"
    assert sent.json_body is not None
    assert sent.json_body["stream"] is False
    assert sent.json_body["messages"] == [
        {"role": "user", "content": "hello", "name": None, "metadata": {}}
    ]
    assert response.id == "chatcmpl_sdk"
    assert response.choices[0].message.content == "hello"
    assert response.usage is not None
    assert response.usage.total_tokens == 5
    assert response.gateway is not None
    assert response.gateway.trace_id == "trace_sdk"


def test_chat_completion_requires_api_key() -> None:
    client = AuthClawClient(config=AuthClawConfig.from_contracts(), transport=MockTransport())

    with pytest.raises(ConfigurationError):
        client.create_chat_completion(_chat_request())


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, ValidationError),
        (401, AuthenticationError),
        (403, AuthorizationError),
        (404, ValidationError),
        (409, ValidationError),
        (422, ValidationError),
        (429, RateLimitError),
        (500, ServerError),
        (502, ServerError),
        (503, ServerError),
        (504, ServerError),
    ],
)
def test_error_mapping(status: int, expected: type[Exception]) -> None:
    transport = MockTransport([TransportResponse(status_code=status, json_body={"detail": "boom"})])
    client = AuthClawClient(
        api_key="ac_sdk_test",
        transport=transport,
        retry_policy=RetryPolicy(max_attempts=1),
    )

    with pytest.raises(expected, match="boom"):
        client.create_chat_completion(_chat_request())


def test_invalid_json_object_response_maps_to_server_error() -> None:
    client = AuthClawClient(
        api_key="ac_sdk_test",
        transport=MockTransport([TransportResponse(status_code=200, json_body=["bad"])]),
    )

    with pytest.raises(ServerError):
        client.create_chat_completion(_chat_request())


def test_transport_timeout_configuration_is_carried_on_request() -> None:
    timeout = TimeoutConfigurationContract(connect_timeout_seconds=1.0, read_timeout_seconds=2.0)
    transport = MockTransport([_chat_response()])
    client = AuthClawClient(api_key="ac_sdk_test", timeout=timeout, transport=transport)

    client.create_chat_completion(_chat_request())

    assert transport.requests[0].timeout == timeout


def test_deterministic_json_serialization() -> None:
    assert dumps_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_requests_transport_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "requests":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ConnectionError):
        RequestsTransport().send(TransportRequest(method="GET", url="http://localhost:8000/v1/health"))


def test_config_from_env_uses_default_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTHCLAW_API_KEY", "ac_default_env")

    assert AuthClawConfig.from_env().api_key == "ac_default_env"


def test_config_from_env_does_not_mutate_process_env() -> None:
    before = dict(os.environ)
    AuthClawConfig.from_env()
    assert dict(os.environ) == before
