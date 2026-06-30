"""Public SDK data models.

These models are transport-neutral and intentionally do not perform networking
or import AuthClaw server runtime modules.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from .types import FinishReason, MessageRole, RedactionMode, ResponseFormat, StreamEventType


def _serialize_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _serialize_value(item) for key, item in asdict(value).items()}
    if isinstance(value, list | tuple):
        return [_serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    if hasattr(value, "value"):
        return value.value
    return value


class SerializableContract:
    """Mixin for deterministic dictionary serialization."""

    def to_dict(self) -> dict[str, Any]:
        if not is_dataclass(self):
            raise TypeError("SerializableContract requires dataclass instances")
        return {key: _serialize_value(value) for key, value in asdict(self).items()}


@dataclass(frozen=True, slots=True)
class ChatMessage(SerializableContract):
    role: MessageRole
    content: str
    name: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UsageMetadata(SerializableContract):
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class GatewayMetadata(SerializableContract):
    trace_id: str | None = None
    route_id: str | None = None
    provider: str | None = None
    model: str | None = None
    redaction_mode: RedactionMode | None = None
    policy_decision: str | None = None


@dataclass(frozen=True, slots=True)
class ChatCompletionChoice(SerializableContract):
    index: int
    message: ChatMessage
    finish_reason: FinishReason | None = None


@dataclass(frozen=True, slots=True)
class StreamingDelta(SerializableContract):
    event_type: StreamEventType
    content: str = ""
    index: int = 0
    finish_reason: FinishReason | None = None


@dataclass(frozen=True, slots=True)
class RequestOptions(SerializableContract):
    response_format: ResponseFormat = ResponseFormat.TEXT
    metadata: dict[str, str] = field(default_factory=dict)
