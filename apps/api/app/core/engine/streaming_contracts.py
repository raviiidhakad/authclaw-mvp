"""
E2.3 Streaming Hardening contracts.

This module is intentionally non-executable scaffolding for the streaming
hardening epic. It defines interface boundaries and immutable data shapes only;
Gateway, provider adapter, StreamingEngine, policy, tokenization, and audit
behavior must remain unchanged until a later approved implementation phase.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterable, AsyncIterator, Mapping, Protocol, Sequence


class StreamingDirection(str, Enum):
    """Direction of text moving through the streaming security pipeline."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


class StreamingPolicyAction(str, Enum):
    """Normalized policy action for future streaming decisions."""

    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class StreamingEmissionKind(str, Enum):
    """OpenAI-compatible output event categories for future emitters."""

    DELTA = "delta"
    ERROR = "error"
    DONE = "done"


class StreamingFailureCategory(str, Enum):
    """Sanitized failure categories for future fail-closed streaming handling."""

    DECODER_ERROR = "decoder_error"
    SSE_PARSE_ERROR = "sse_parse_error"
    REDACTION_ERROR = "redaction_error"
    POLICY_ERROR = "policy_error"
    TOKENIZATION_ERROR = "tokenization_error"
    PROVIDER_ERROR = "provider_error"
    CLIENT_DISCONNECT = "client_disconnect"
    BACK_PRESSURE_LIMIT = "back_pressure_limit"
    AUDIT_ERROR = "audit_error"


@dataclass(frozen=True)
class StreamingSecurityInvariants:
    """Architecture boundaries that E2.3 implementations must preserve."""

    preserve_gateway_api: bool = True
    preserve_provider_abstractions: bool = True
    preserve_openai_compatible_sse: bool = True
    preserve_reversible_tokenization: bool = True
    preserve_yaml_opa_enforcement: bool = True
    preserve_sanitized_audit_behavior: bool = True
    preserve_fail_closed_posture: bool = True


@dataclass(frozen=True)
class StreamingContext:
    """Tenant-scoped metadata available to future streaming components."""

    tenant_id: str
    stream_id: str
    direction: StreamingDirection
    route_id: str | None = None
    provider_id: str | None = None
    provider_name: str | None = None
    model: str | None = None
    redaction_mode: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    request_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SseEvent:
    """Provider-agnostic SSE event representation."""

    data: str | None = None
    event: str | None = None
    event_id: str | None = None
    retry_ms: int | None = None
    comment: str | None = None


@dataclass(frozen=True)
class StreamingTextWindow:
    """A deterministic text window held until it is safe to emit."""

    text: str
    safe_prefix: str
    retained_suffix: str
    sequence: int
    is_final: bool = False


@dataclass(frozen=True)
class StreamingPolicyDecision:
    """Sanitized policy decision shape for future streaming enforcement."""

    action: StreamingPolicyAction
    allowed: bool
    reason_code: str
    matched_rules: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StreamingTokenizationResult:
    """Tokenization summary that excludes raw sensitive values."""

    text: str
    mode: str
    token_count: int = 0
    entity_types: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StreamingEmission:
    """SSE emission requested by a future output emitter."""

    kind: StreamingEmissionKind
    payload: Mapping[str, Any]
    sequence: int


class SseParserContract(Protocol):
    """Parse byte chunks into normalized SSE events without policy decisions."""

    async def parse(self, chunks: AsyncIterable[bytes]) -> AsyncIterator[SseEvent]:
        ...


class Utf8IncrementalDecoderContract(Protocol):
    """Decode provider bytes incrementally without replacing partial codepoints."""

    def decode(self, chunk: bytes, *, final: bool = False) -> str:
        ...


class StreamingRedactionStateMachineContract(Protocol):
    """Hold unsafe suffixes and emit only scanned, policy-safe text windows."""

    async def process_text(
        self,
        context: StreamingContext,
        text: str,
        *,
        is_final: bool = False,
    ) -> AsyncIterator[StreamingTextWindow]:
        ...


class StreamingPolicyEvaluationContract(Protocol):
    """Evaluate sanitized streaming windows through the existing policy boundary."""

    async def evaluate_window(
        self,
        context: StreamingContext,
        window: StreamingTextWindow,
    ) -> StreamingPolicyDecision:
        ...


class StreamingTokenizationContract(Protocol):
    """Apply E2.1-compatible tokenization/redaction without exposing raw values."""

    async def transform_window(
        self,
        context: StreamingContext,
        window: StreamingTextWindow,
        decision: StreamingPolicyDecision,
    ) -> StreamingTokenizationResult:
        ...


class StreamingOutputEmitterContract(Protocol):
    """Emit OpenAI-compatible SSE events from sanitized streaming payloads."""

    async def emit(
        self,
        context: StreamingContext,
        tokenized: StreamingTokenizationResult,
        *,
        sequence: int,
        is_final: bool = False,
    ) -> AsyncIterator[StreamingEmission]:
        ...


E2_3_SECURITY_INVARIANTS = StreamingSecurityInvariants()

