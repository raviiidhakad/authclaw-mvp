"""Stable public type identifiers for the AuthClaw Python SDK."""

from __future__ import annotations

from enum import Enum


class AuthClawEnum(str, Enum):
    """Base enum with string serialization suitable for SDK contracts."""

    def __str__(self) -> str:
        return self.value


class MessageRole(AuthClawEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ResponseFormat(AuthClawEnum):
    TEXT = "text"
    JSON = "json"


class StreamEventType(AuthClawEnum):
    MESSAGE_START = "message_start"
    CONTENT_DELTA = "content_delta"
    MESSAGE_STOP = "message_stop"
    ERROR = "error"


class FinishReason(AuthClawEnum):
    STOP = "stop"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    TOOL_CALLS = "tool_calls"
    ERROR = "error"


class RedactionMode(AuthClawEnum):
    MASK = "mask"
    HASH = "hash"
    SYNTHETIC = "synthetic"


class SdkTransport(AuthClawEnum):
    HTTP = "http"
    MOCK = "mock"


class RetryBackoff(AuthClawEnum):
    NONE = "none"
    FIXED = "fixed"
    EXPONENTIAL = "exponential"
