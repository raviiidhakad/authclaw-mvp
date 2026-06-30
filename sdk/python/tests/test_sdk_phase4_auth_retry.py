from __future__ import annotations

import pytest

from authclaw import (
    ApiKeyConfigurationContract,
    ApiKeyManager,
    AuthClawClient,
    AuthClawConfig,
    ChatMessage,
    ConfigurationError,
    ConnectionError,
    MessageRole,
    MockTransport,
    RetryConfigurationContract,
    RetryContext,
    RetryDecision,
    RetryPolicy,
    RetryStrategy,
    ServerError,
    StreamingRequestContract,
    TimeoutConfigurationContract,
    TimeoutError,
    TransportRequest,
    TransportResponse,
    TransportStreamResponse,
    ValidationError,
    build_authenticated_headers,
    build_default_headers,
)
from authclaw.client_contracts import ChatCompletionRequestContract, SdkMetadataContract
from authclaw.types import RetryBackoff


def _request() -> ChatCompletionRequestContract:
    return ChatCompletionRequestContract(
        model="llama",
        messages=(ChatMessage(role=MessageRole.USER, content="hello"),),
    )


def _success_response() -> TransportResponse:
    return TransportResponse(
        status_code=200,
        json_body={
            "id": "chatcmpl_retry",
            "model": "llama",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
        },
    )


class FlakyTransport(MockTransport):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def send(self, request: TransportRequest) -> TransportResponse:
        self.requests.append(request)
        self.calls += 1
        if self.calls == 1:
            raise ConnectionError("network down")
        return _success_response()


def test_api_key_manager_resolves_explicit_and_env_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTHCLAW_SDK_KEY", "ac_env")

    explicit = ApiKeyManager.from_contract(
        ApiKeyConfigurationContract(api_key="ac_explicit", api_key_env_var="AUTHCLAW_SDK_KEY")
    )
    env = ApiKeyManager.from_contract(
        ApiKeyConfigurationContract(api_key_env_var="AUTHCLAW_SDK_KEY")
    )

    assert explicit.require_api_key() == "ac_explicit"
    assert env.authorization_header() == {"Authorization": "Bearer ac_env"}


def test_api_key_manager_rejects_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTHCLAW_SDK_MISSING", raising=False)
    manager = ApiKeyManager.from_contract(
        ApiKeyConfigurationContract(api_key_env_var="AUTHCLAW_SDK_MISSING")
    )

    with pytest.raises(ConfigurationError):
        manager.require_api_key()


def test_header_generation() -> None:
    metadata = SdkMetadataContract()
    manager = ApiKeyManager(api_key="ac_header")

    assert build_default_headers(metadata)["Accept"] == "application/json"
    assert build_authenticated_headers(manager, metadata)["Authorization"] == "Bearer ac_header"
    assert build_authenticated_headers(manager, metadata, accept="text/event-stream")[
        "Accept"
    ] == "text/event-stream"


def test_configuration_validation_rejects_invalid_timeouts_and_retries() -> None:
    with pytest.raises(ConfigurationError):
        AuthClawConfig.from_contracts(timeout=TimeoutConfigurationContract(read_timeout_seconds=0))
    with pytest.raises(ConfigurationError):
        AuthClawConfig.from_contracts(retry=RetryConfigurationContract(max_attempts=0))
    with pytest.raises(ConfigurationError):
        AuthClawConfig.from_contracts(
            retry=RetryConfigurationContract(initial_delay_seconds=5, max_delay_seconds=1)
        )
    with pytest.raises(ConfigurationError):
        AuthClawConfig.from_contracts(ApiKeyConfigurationContract(api_version="/"))


def test_retry_strategy_backoff_calculation() -> None:
    fixed = RetryStrategy(
        RetryBackoff.FIXED,
        initial_delay_seconds=0.5,
        max_delay_seconds=10.0,
    )
    exponential = RetryStrategy(
        RetryBackoff.EXPONENTIAL,
        initial_delay_seconds=0.5,
        max_delay_seconds=2.0,
    )
    none = RetryStrategy(
        RetryBackoff.NONE,
        initial_delay_seconds=0.5,
        max_delay_seconds=2.0,
    )

    assert fixed.delay_for_attempt(3) == 0.5
    assert exponential.delay_for_attempt(1) == 0.5
    assert exponential.delay_for_attempt(3) == 2.0
    assert none.delay_for_attempt(3) == 0.0


def test_retry_strategy_jitter_is_bounded_and_deterministic() -> None:
    strategy = RetryStrategy(
        RetryBackoff.FIXED,
        initial_delay_seconds=1.0,
        max_delay_seconds=1.0,
        jitter_ratio=0.2,
    )

    first = strategy.delay_for_attempt(2)
    second = strategy.delay_for_attempt(2)

    assert first == second
    assert 0.8 <= first <= 1.2


def test_retry_policy_decides_on_status_and_exception() -> None:
    policy = RetryPolicy.from_contract(
        RetryConfigurationContract(max_attempts=3, initial_delay_seconds=0, max_delay_seconds=0)
    )

    status_decision = policy.decide(
        RetryContext(
            attempt_index=1,
            max_attempts=3,
            method="POST",
            url="http://localhost",
            status_code=503,
        )
    )
    exception_decision = policy.decide(
        RetryContext(
            attempt_index=1,
            max_attempts=3,
            method="POST",
            url="http://localhost",
            exception=TimeoutError("slow"),
        )
    )
    no_retry = policy.decide(
        RetryContext(
            attempt_index=3,
            max_attempts=3,
            method="POST",
            url="http://localhost",
            status_code=503,
        )
    )

    assert status_decision == RetryDecision(True, 0.0, "status_503", 2)
    assert exception_decision.reason == "TimeoutError"
    assert no_retry.should_retry is False


def test_retry_policy_prevents_retry_after_stream_started() -> None:
    policy = RetryPolicy()

    decision = policy.decide(
        RetryContext(
            attempt_index=1,
            max_attempts=3,
            method="POST",
            url="http://localhost",
            status_code=503,
            stream_started=True,
        )
    )

    assert decision.should_retry is False
    assert decision.reason == "stream_already_started"


def test_client_retries_retryable_status_before_success() -> None:
    transport = MockTransport(
        [
            TransportResponse(status_code=503, json_body={"detail": "temporary"}),
            _success_response(),
        ]
    )
    delays: list[float] = []
    client = AuthClawClient(
        api_key="ac_retry",
        transport=transport,
        retry_policy=RetryPolicy.from_contract(
            RetryConfigurationContract(max_attempts=2, initial_delay_seconds=0, max_delay_seconds=0)
        ),
        sleeper=delays.append,
    )

    response = client.create_chat_completion(_request())

    assert response.id == "chatcmpl_retry"
    assert len(transport.requests) == 2
    assert delays == [0.0]


def test_client_retries_retryable_transport_exception() -> None:
    transport = FlakyTransport()
    client = AuthClawClient(
        api_key="ac_retry",
        transport=transport,
        retry_policy=RetryPolicy.from_contract(
            RetryConfigurationContract(max_attempts=2, initial_delay_seconds=0, max_delay_seconds=0)
        ),
        sleeper=lambda delay: None,
    )

    response = client.create_chat_completion(_request())

    assert response.id == "chatcmpl_retry"
    assert transport.calls == 2


def test_client_does_not_retry_non_retryable_status() -> None:
    transport = MockTransport([TransportResponse(status_code=400, json_body={"detail": "bad"})])
    client = AuthClawClient(
        api_key="ac_retry",
        transport=transport,
        retry_policy=RetryPolicy.from_contract(RetryConfigurationContract(max_attempts=3)),
    )

    with pytest.raises(ValidationError, match="bad"):
        client.create_chat_completion(_request())

    assert len(transport.requests) == 1


def test_streaming_transport_is_not_retried_after_error_status() -> None:
    transport = MockTransport(
        stream_responses=[
            TransportStreamResponse(status_code=503, text="temporary"),
            TransportStreamResponse(status_code=200, chunks=[]),
        ]
    )
    client = AuthClawClient(
        api_key="ac_stream",
        transport=transport,
        retry_policy=RetryPolicy.from_contract(RetryConfigurationContract(max_attempts=3)),
    )

    with pytest.raises(ServerError, match="temporary"):
        client.stream_chat_completion(
            request=StreamingRequestContract(
                model="llama",
                messages=(ChatMessage(role=MessageRole.USER, content="hello"),),
            )
        )

    assert len(transport.stream_requests) == 1
