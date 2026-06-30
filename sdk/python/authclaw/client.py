"""Synchronous AuthClaw SDK client for non-streaming operations."""

from __future__ import annotations

import time
from collections.abc import Callable

from .auth import build_authenticated_headers, build_default_headers
from .client_contracts import (
    ApiKeyConfigurationContract,
    ChatCompletionRequestContract,
    ChatCompletionResponseContract,
    SdkMetadataContract,
    StreamingRequestContract,
    TimeoutConfigurationContract,
)
from .config import AuthClawConfig
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    AuthClawError,
    ConfigurationError,
    ConnectionError,
    RateLimitError,
    ServerError,
    TimeoutError,
    ValidationError,
)
from .models import (
    ChatCompletionChoice,
    ChatMessage,
    GatewayMetadata,
    UsageMetadata,
)
from .transport import RequestsTransport, Transport, TransportRequest, TransportResponse
from .retry import RetryContext, RetryPolicy
from .types import FinishReason, MessageRole, RedactionMode


class AuthClawClient:
    """Synchronous SDK client for AuthClaw non-streaming APIs."""

    def __init__(
        self,
        config: AuthClawConfig | None = None,
        transport: Transport | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: TimeoutConfigurationContract | None = None,
        retry_policy: RetryPolicy | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if config is not None and any(value is not None for value in (api_key, base_url, timeout)):
            raise ConfigurationError("Pass either config or direct client options, not both")

        if config is None:
            config = AuthClawConfig.from_contracts(
                ApiKeyConfigurationContract(
                    api_key=api_key,
                    base_url=base_url or ApiKeyConfigurationContract().base_url,
                ),
                timeout=timeout,
            )

        self.config = config
        self.transport = transport or RequestsTransport()
        self.retry_policy = retry_policy or RetryPolicy.from_contract(config.retry)
        self._sleep = sleeper or time.sleep

    @property
    def metadata(self) -> SdkMetadataContract:
        return self.config.metadata

    def health(self) -> dict[str, object]:
        response = self._send("GET", "health", authenticated=False)
        return _expect_json_object(response)

    def version(self) -> dict[str, object]:
        response = self._send("GET", "version", authenticated=False)
        return _expect_json_object(response)

    def create_chat_completion(
        self,
        request: ChatCompletionRequestContract,
    ) -> ChatCompletionResponseContract:
        payload = request.to_dict()
        payload["stream"] = False
        response = self._send("POST", "chat/completions", payload, authenticated=True)
        return _parse_chat_completion_response(_expect_json_object(response))

    def stream_chat_completion(self, request: StreamingRequestContract):
        from .streaming import StreamingClient

        return StreamingClient(self.config, self.transport).stream_chat_completion(request)

    def _send(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        authenticated: bool,
    ) -> TransportResponse:
        headers = self._headers(authenticated=authenticated)
        url = self.config.build_url(path)
        attempt_index = 1
        while True:
            try:
                response = self.transport.send(
                    TransportRequest(
                        method=method,
                        url=url,
                        headers=headers,
                        json_body=payload,
                        timeout=self.config.timeout,
                    )
                )
            except (ConnectionError, TimeoutError) as exc:
                decision = self.retry_policy.decide(
                    RetryContext(
                        attempt_index=attempt_index,
                        max_attempts=self.retry_policy.max_attempts,
                        method=method,
                        url=url,
                        exception=exc,
                    )
                )
                if decision.should_retry:
                    self._sleep(decision.delay_seconds)
                    attempt_index = decision.next_attempt_index
                    continue
                raise

            decision = self.retry_policy.decide(
                RetryContext(
                    attempt_index=attempt_index,
                    max_attempts=self.retry_policy.max_attempts,
                    method=method,
                    url=url,
                    status_code=response.status_code,
                )
            )
            if response.status_code >= 400 and decision.should_retry:
                self._sleep(decision.delay_seconds)
                attempt_index = decision.next_attempt_index
                continue
            _raise_for_status(response)
            return response

    def _headers(self, *, authenticated: bool) -> dict[str, str]:
        if authenticated:
            return build_authenticated_headers(self.config.auth_manager(), self.config.metadata)
        headers = build_default_headers(self.config.metadata)
        if self.config.api_key:
            headers.update(self.config.auth_manager().authorization_header())
        return headers


def _expect_json_object(response: TransportResponse) -> dict[str, object]:
    if not isinstance(response.json_body, dict):
        raise ServerError("AuthClaw response did not contain a JSON object")
    return response.json_body


def _raise_for_status(response: TransportResponse) -> None:
    if response.status_code < 400:
        return

    detail = _error_detail(response)
    error_map: dict[int, type[AuthClawError]] = {
        400: ValidationError,
        401: AuthenticationError,
        403: AuthorizationError,
        404: ValidationError,
        409: ValidationError,
        422: ValidationError,
        429: RateLimitError,
        500: ServerError,
        502: ServerError,
        503: ServerError,
        504: ServerError,
    }
    error_type = error_map.get(response.status_code, ServerError)
    raise error_type(detail)


def _error_detail(response: TransportResponse) -> str:
    if isinstance(response.json_body, dict):
        for key in ("detail", "message", "error", "title"):
            value = response.json_body.get(key)
            if isinstance(value, str) and value:
                return value
    if response.text:
        return response.text
    return f"AuthClaw request failed with status {response.status_code}"


def _parse_chat_completion_response(payload: dict[str, object]) -> ChatCompletionResponseContract:
    return ChatCompletionResponseContract(
        id=str(payload.get("id", "")),
        model=str(payload.get("model", "")),
        choices=tuple(_parse_choice(choice) for choice in _as_list(payload.get("choices"))),
        usage=_parse_usage(payload.get("usage")),
        gateway=_parse_gateway(payload.get("gateway")),
    )


def _parse_choice(payload: object) -> ChatCompletionChoice:
    if not isinstance(payload, dict):
        raise ServerError("Invalid AuthClaw choice payload")
    return ChatCompletionChoice(
        index=int(payload.get("index", 0)),
        message=_parse_message(payload.get("message")),
        finish_reason=_parse_finish_reason(payload.get("finish_reason")),
    )


def _parse_message(payload: object) -> ChatMessage:
    if not isinstance(payload, dict):
        raise ServerError("Invalid AuthClaw message payload")
    return ChatMessage(
        role=_parse_message_role(payload.get("role")),
        content=str(payload.get("content", "")),
        name=_optional_str(payload.get("name")),
        metadata=_str_dict(payload.get("metadata")),
    )


def _parse_usage(payload: object) -> UsageMetadata | None:
    if not isinstance(payload, dict):
        return None
    return UsageMetadata(
        prompt_tokens=_optional_int(payload.get("prompt_tokens")),
        completion_tokens=_optional_int(payload.get("completion_tokens")),
        total_tokens=_optional_int(payload.get("total_tokens")),
    )


def _parse_gateway(payload: object) -> GatewayMetadata | None:
    if not isinstance(payload, dict):
        return None
    return GatewayMetadata(
        trace_id=_optional_str(payload.get("trace_id")),
        route_id=_optional_str(payload.get("route_id")),
        provider=_optional_str(payload.get("provider")),
        model=_optional_str(payload.get("model")),
        redaction_mode=_parse_redaction_mode(payload.get("redaction_mode")),
        policy_decision=_optional_str(payload.get("policy_decision")),
    )


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    raise ServerError("AuthClaw response choices must be a list")


def _parse_message_role(value: object) -> MessageRole:
    try:
        return MessageRole(str(value))
    except ValueError as exc:
        raise ServerError("AuthClaw response contained an unsupported message role") from exc


def _parse_finish_reason(value: object) -> FinishReason | None:
    if value is None:
        return None
    try:
        return FinishReason(str(value))
    except ValueError as exc:
        raise ServerError("AuthClaw response contained an unsupported finish reason") from exc


def _parse_redaction_mode(value: object) -> RedactionMode | None:
    if value is None:
        return None
    try:
        return RedactionMode(str(value))
    except ValueError:
        return None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def _str_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(item, str):
            result[str(key)] = item
    return result
