"""Public SDK contracts and client interface definitions.

This module intentionally defines data contracts only. It does not implement
HTTP, authentication, retries, streaming, or AuthClaw runtime integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, Sequence

from .models import (
    ChatCompletionChoice,
    ChatMessage,
    GatewayMetadata,
    RequestOptions,
    SerializableContract,
    StreamingDelta,
    UsageMetadata,
)
from .types import RetryBackoff
from .version import SdkVersionContract


@dataclass(frozen=True, slots=True)
class ApiKeyConfigurationContract(SerializableContract):
    api_key: str | None = None
    api_key_env_var: str = "AUTHCLAW_API_KEY"
    base_url: str = "http://localhost:8000"
    api_version: str = "v1"


@dataclass(frozen=True, slots=True)
class TimeoutConfigurationContract(SerializableContract):
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 60.0
    write_timeout_seconds: float = 30.0
    total_timeout_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class RetryConfigurationContract(SerializableContract):
    max_attempts: int = 3
    backoff: RetryBackoff = RetryBackoff.EXPONENTIAL
    initial_delay_seconds: float = 0.25
    max_delay_seconds: float = 5.0
    retry_on_status_codes: tuple[int, ...] = (408, 409, 425, 429, 500, 502, 503, 504)


@dataclass(frozen=True, slots=True)
class SdkMetadataContract(SerializableContract):
    sdk_name: str = "authclaw-python"
    language: str = "python"
    user_agent_prefix: str = "authclaw-python"
    version: SdkVersionContract = field(default_factory=SdkVersionContract)


@dataclass(frozen=True, slots=True)
class ChatCompletionRequestContract(SerializableContract):
    model: str
    messages: tuple[ChatMessage, ...]
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None
    request_options: RequestOptions = field(default_factory=RequestOptions)


@dataclass(frozen=True, slots=True)
class ChatCompletionResponseContract(SerializableContract):
    id: str
    model: str
    choices: tuple[ChatCompletionChoice, ...]
    usage: UsageMetadata | None = None
    gateway: GatewayMetadata | None = None


@dataclass(frozen=True, slots=True)
class StreamingRequestContract(SerializableContract):
    model: str
    messages: tuple[ChatMessage, ...]
    request_options: RequestOptions = field(default_factory=RequestOptions)


@dataclass(frozen=True, slots=True)
class StreamingResponseContract(SerializableContract):
    id: str
    model: str
    deltas: tuple[StreamingDelta, ...]
    gateway: GatewayMetadata | None = None


class ClientContract(Protocol):
    """Interface future SDK clients must implement."""

    @property
    def metadata(self) -> SdkMetadataContract:
        """Return SDK metadata."""

    def create_chat_completion(
        self,
        request: ChatCompletionRequestContract,
    ) -> ChatCompletionResponseContract:
        """Create a non-streaming chat completion."""

    def stream_chat_completion(
        self,
        request: StreamingRequestContract,
    ) -> Sequence[StreamingResponseContract]:
        """Create a streaming chat completion sequence."""
