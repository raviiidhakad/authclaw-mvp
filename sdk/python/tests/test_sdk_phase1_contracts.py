from __future__ import annotations

import importlib

import pytest

import authclaw
from authclaw import (
    ApiKeyConfigurationContract,
    AuthClawError,
    AuthenticationError,
    ChatCompletionChoice,
    ChatCompletionRequestContract,
    ChatCompletionResponseContract,
    ChatMessage,
    FinishReason,
    GatewayMetadata,
    MessageRole,
    RateLimitError,
    RedactionMode,
    RetryBackoff,
    RetryConfigurationContract,
    SDK_VERSION,
    SUPPORTED_API_VERSION,
    SdkMetadataContract,
    SdkVersionContract,
    StreamEventType,
    StreamingDelta,
    StreamingRequestContract,
    StreamingResponseContract,
    TimeoutConfigurationContract,
    get_version,
)


def test_chat_completion_contract_serializes_nested_models() -> None:
    request = ChatCompletionRequestContract(
        model="llama-3.3-70b-versatile",
        messages=(ChatMessage(role=MessageRole.USER, content="hello"),),
        temperature=0.2,
    )

    assert request.to_dict() == {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "user", "content": "hello", "name": None, "metadata": {}},
        ],
        "stream": False,
        "temperature": 0.2,
        "max_tokens": None,
        "request_options": {"response_format": "text", "metadata": {}},
    }


def test_chat_completion_response_contract_serializes_gateway_metadata() -> None:
    response = ChatCompletionResponseContract(
        id="chatcmpl_test",
        model="route/default",
        choices=(
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role=MessageRole.ASSISTANT, content="ok"),
                finish_reason=FinishReason.STOP,
            ),
        ),
        gateway=GatewayMetadata(
            trace_id="trace_123",
            provider="groq",
            model="llama",
            redaction_mode=RedactionMode.MASK,
            policy_decision="allow",
        ),
    )

    payload = response.to_dict()

    assert payload["choices"][0]["finish_reason"] == "stop"
    assert payload["gateway"]["redaction_mode"] == "mask"
    assert payload["gateway"]["trace_id"] == "trace_123"


def test_streaming_contracts_are_transport_neutral() -> None:
    request = StreamingRequestContract(
        model="route/stream",
        messages=(ChatMessage(role=MessageRole.USER, content="stream"),),
    )
    response = StreamingResponseContract(
        id="stream_test",
        model=request.model,
        deltas=(
            StreamingDelta(event_type=StreamEventType.MESSAGE_START),
            StreamingDelta(event_type=StreamEventType.CONTENT_DELTA, content="hel"),
            StreamingDelta(event_type=StreamEventType.MESSAGE_STOP),
        ),
    )

    assert request.to_dict()["messages"][0]["content"] == "stream"
    assert response.to_dict()["deltas"][1]["event_type"] == "content_delta"


def test_configuration_contract_defaults() -> None:
    api_key_config = ApiKeyConfigurationContract()
    timeout_config = TimeoutConfigurationContract()
    retry_config = RetryConfigurationContract()

    assert api_key_config.to_dict()["api_key_env_var"] == "AUTHCLAW_API_KEY"
    assert api_key_config.to_dict()["api_version"] == "v1"
    assert timeout_config.to_dict()["read_timeout_seconds"] == 60.0
    assert retry_config.to_dict()["backoff"] == "exponential"
    assert 429 in retry_config.retry_on_status_codes
    assert retry_config.backoff is RetryBackoff.EXPONENTIAL


def test_sdk_version_metadata() -> None:
    version = get_version()
    metadata = SdkMetadataContract()

    assert isinstance(version, SdkVersionContract)
    assert SDK_VERSION == "0.1.0"
    assert SUPPORTED_API_VERSION == "v1"
    assert version.to_dict()["minimum_authclaw_version"] == "0.11.0"
    assert metadata.to_dict()["version"]["sdk_version"] == SDK_VERSION


def test_exception_hierarchy() -> None:
    assert issubclass(AuthenticationError, AuthClawError)
    assert issubclass(RateLimitError, AuthClawError)

    with pytest.raises(AuthClawError):
        raise AuthenticationError("invalid key")


def test_public_exports_are_stable() -> None:
    expected_exports = {
        "ApiKeyConfigurationContract",
        "ChatCompletionRequestContract",
        "ClientContract",
        "SdkVersionContract",
        "StreamingRequestContract",
        "AuthClawError",
        "MessageRole",
        "get_version",
    }

    assert expected_exports.issubset(set(authclaw.__all__))
    for export in expected_exports:
        assert hasattr(authclaw, export)


def test_sdk_package_does_not_import_server_runtime_modules() -> None:
    for module_name in (
        "authclaw",
        "authclaw.client_contracts",
        "authclaw.models",
        "authclaw.exceptions",
        "authclaw.types",
        "authclaw.version",
    ):
        module = importlib.import_module(module_name)
        assert module.__name__.startswith("authclaw")

    assert importlib.util.find_spec("authclaw") is not None
