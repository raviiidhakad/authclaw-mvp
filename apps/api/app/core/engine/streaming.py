import uuid
import time
import json
import hashlib
import asyncio
import codecs
import logging
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Any, AsyncGenerator, AsyncIterable, AsyncIterator, Dict, Mapping, Optional, Protocol, Sequence
import httpx
from fastapi.responses import StreamingResponse

from app.core.engine.audit import AuditEngine
from app.core.config import settings
from app.core.rate_limit.tenant_limiter import tenant_plan_limiter
from app.services.api_safety import sanitize_text

logger = logging.getLogger(__name__)


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


class Utf8DecoderError(UnicodeError):
    """Controlled UTF-8 decoder failure without raw byte disclosure."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"utf8_decoder_error:{reason}")
        self.reason = reason


class Utf8IncrementalDecoder(Utf8IncrementalDecoderContract):
    """
    Strict incremental UTF-8 decoder for arbitrary byte chunks.

    The decoder buffers incomplete UTF-8 sequences internally and emits only
    complete Unicode text. Malformed UTF-8 raises Utf8DecoderError instead of
    silently replacing bytes with U+FFFD.
    """

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        self._lock = RLock()

    def decode(self, chunk: bytes, *, final: bool = False) -> str:
        """Decode a bytes chunk, buffering incomplete sequences until complete."""
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("chunk must be bytes-like")

        try:
            with self._lock:
                return self._decoder.decode(chunk, final=final)
        except UnicodeDecodeError as exc:
            raise Utf8DecoderError(self._classify_error(exc)) from exc

    def flush(self) -> str:
        """Flush buffered bytes at stream end, failing on truncated sequences."""
        return self.decode(b"", final=True)

    def reset(self) -> None:
        """Reset decoder state so the instance can be reused for a new stream."""
        with self._lock:
            self._decoder.reset()

    @staticmethod
    def _classify_error(exc: UnicodeDecodeError) -> str:
        reason = (exc.reason or "").lower()
        if "unexpected end of data" in reason:
            return "unexpected_eof"
        if "invalid continuation byte" in reason:
            return "invalid_continuation_byte"
        if "invalid start byte" in reason:
            return "invalid_start_byte"
        if "surrogates not allowed" in reason:
            return "illegal_utf8"
        return "malformed_utf8"


class SseParserError(ValueError):
    """Controlled SSE parser failure without partial event disclosure."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"sse_parser_error:{reason}")
        self.reason = reason


@dataclass(frozen=True)
class SseField:
    """Ordered SSE field as received after line parsing."""

    name: str
    value: str


@dataclass(frozen=True)
class ParsedSseEvent(SseEvent):
    """Immutable parsed SSE event with ordered field preservation."""

    fields: tuple[SseField, ...] = field(default_factory=tuple)
    unknown_fields: tuple[SseField, ...] = field(default_factory=tuple)


class SseParser(SseParserContract):
    """
    Incremental SSE parser for decoded Unicode text chunks.

    The parser implements field framing only. It does not parse JSON, interpret
    OpenAI payloads, apply policy, redact, tokenize, or detokenize.
    """

    _KNOWN_FIELDS = {"data", "event", "id", "retry"}

    def __init__(self, *, max_event_chars: int = 1_048_576) -> None:
        if max_event_chars <= 0:
            raise ValueError("max_event_chars must be positive")
        self._max_event_chars = max_event_chars
        self._line_buffer = ""
        self._line_buffer_counted_chars = 0
        self._data_lines: list[str] = []
        self._event: str | None = None
        self._event_id: str | None = None
        self._retry_ms: int | None = None
        self._comment_lines: list[str] = []
        self._fields: list[SseField] = []
        self._unknown_fields: list[SseField] = []
        self._event_chars = 0

    async def parse(self, chunks: AsyncIterable[str]) -> AsyncIterator[ParsedSseEvent]:
        """Parse decoded text chunks into immutable SSE events."""
        async for chunk in chunks:
            for event in self.feed(chunk):
                yield event

    def feed(self, text: str) -> tuple[ParsedSseEvent, ...]:
        """Feed decoded Unicode text and return complete events."""
        if not isinstance(text, str):
            raise TypeError("SseParser.feed expects decoded Unicode text")
        if text == "":
            return ()

        self._line_buffer += text
        events: list[ParsedSseEvent] = []

        try:
            while True:
                newline_index = self._next_newline_index(self._line_buffer)
                if newline_index is None:
                    uncounted_chars = len(self._line_buffer) - self._line_buffer_counted_chars
                    if uncounted_chars > 0:
                        self._check_size(uncounted_chars)
                        self._line_buffer_counted_chars = len(self._line_buffer)
                    break

                raw_line = self._line_buffer[:newline_index]
                newline_len = 2 if self._line_buffer[newline_index:newline_index + 2] == "\r\n" else 1
                self._line_buffer = self._line_buffer[newline_index + newline_len:]
                self._line_buffer_counted_chars = 0

                line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
                event = self._parse_line(line)
                if event is not None:
                    events.append(event)
        except Exception:
            self.reset()
            raise

        return tuple(events)

    def flush(self) -> tuple[ParsedSseEvent, ...]:
        """
        Finish parsing at stream end.

        A buffered partial line or pending event without a terminating blank line
        is treated as a truncated final event and fails closed.
        """
        if self._line_buffer:
            self.reset()
            raise SseParserError("truncated_final_event")
        if self._has_pending_event():
            self.reset()
            raise SseParserError("truncated_final_event")
        return ()

    def reset(self) -> None:
        """Clear parser state for reuse on a new stream."""
        self._line_buffer = ""
        self._line_buffer_counted_chars = 0
        self._data_lines = []
        self._event = None
        self._event_id = None
        self._retry_ms = None
        self._comment_lines = []
        self._fields = []
        self._unknown_fields = []
        self._event_chars = 0

    def _parse_line(self, line: str) -> ParsedSseEvent | None:
        if line == "":
            return self._dispatch_event()

        self._check_size(len(line))
        if line.startswith(":"):
            value = line[1:]
            if value.startswith(" "):
                value = value[1:]
            self._comment_lines.append(value)
            self._fields.append(SseField("comment", value))
            return None

        name, value = self._split_field(line)
        field_item = SseField(name, value)
        self._fields.append(field_item)

        if name == "data":
            self._data_lines.append(value)
        elif name == "event":
            self._event = value
        elif name == "id":
            self._event_id = value
        elif name == "retry":
            self._retry_ms = self._parse_retry(value)
        else:
            self._unknown_fields.append(field_item)

        return None

    def _dispatch_event(self) -> ParsedSseEvent | None:
        if not self._has_pending_event():
            return None

        event = ParsedSseEvent(
            data="\n".join(self._data_lines) if self._data_lines else None,
            event=self._event,
            event_id=self._event_id,
            retry_ms=self._retry_ms,
            comment="\n".join(self._comment_lines) if self._comment_lines else None,
            fields=tuple(self._fields),
            unknown_fields=tuple(self._unknown_fields),
        )
        self._clear_event_state()
        return event

    def _split_field(self, line: str) -> tuple[str, str]:
        if "\x00" in line:
            raise SseParserError("malformed_field")

        if ":" in line:
            name, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            name, value = line, ""

        if not name or any(char.isspace() for char in name):
            raise SseParserError("malformed_field")
        return name, value

    @staticmethod
    def _parse_retry(value: str) -> int:
        if not value.isdigit():
            raise SseParserError("invalid_retry")
        return int(value)

    @staticmethod
    def _next_newline_index(text: str) -> int | None:
        indexes = [idx for idx in (text.find("\n"), text.find("\r")) if idx != -1]
        return min(indexes) if indexes else None

    def _check_size(self, incoming_chars: int) -> None:
        self._event_chars += incoming_chars
        if self._event_chars > self._max_event_chars:
            raise SseParserError("event_too_large")

    def _has_pending_event(self) -> bool:
        return bool(
            self._data_lines
            or self._event is not None
            or self._event_id is not None
            or self._retry_ms is not None
            or self._comment_lines
            or self._fields
            or self._unknown_fields
        )

    def _clear_event_state(self) -> None:
        self._data_lines.clear()
        self._event = None
        self._event_id = None
        self._retry_ms = None
        self._comment_lines.clear()
        self._fields.clear()
        self._unknown_fields.clear()
        self._event_chars = 0


class StreamingMode:
    STRICT = "strict"
    BUFFERED = "buffered"
    PASSTHROUGH = "passthrough"


class StreamingSecurityBlocked(RuntimeError):
    """Raised when outbound streaming content is blocked by existing policy."""

    def __init__(self, reason: str) -> None:
        super().__init__("streaming_security_blocked")
        self.reason = sanitize_text(reason)


async def detokenize_sse_chunks(tenant_id: str | uuid.UUID, original_iterator):
    from app.core.engine.token_vault import TokenVaultService

    async for chunk in original_iterator:
        chunk_str = chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk)

        if not chunk_str.startswith("data: "):
            yield chunk_str
            continue

        data_str = chunk_str[len("data: "):].strip()
        if data_str == "[DONE]":
            yield chunk_str
            continue

        try:
            data_json = json.loads(data_str)
            data_json = await TokenVaultService.detokenize_payload(tenant_id, data_json)
            yield f"data: {json.dumps(data_json, separators=(',', ':'))}\n\n"
        except Exception as exc:
            logger.error("Outbound streaming detokenization failed: %s", exc)
            yield chunk_str


class StreamingEngine:
    def __init__(self, audit_engine: AuditEngine, *, db=None, rate_limiter=tenant_plan_limiter):
        self.audit_engine = audit_engine
        self.db = db
        self.rate_limiter = rate_limiter

    @staticmethod
    def _safe_sse_payload(payload: Dict[str, Any]) -> str:
        return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"

    @staticmethod
    def _done_sse() -> str:
        return "data: [DONE]\n\n"

    @staticmethod
    def _sanitize_request_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        sanitized_payload = dict(payload)
        messages = []
        for message in payload.get("messages", []):
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                messages.append({**message, "content": sanitize_text(message["content"])})
            else:
                messages.append(message)
        if messages:
            sanitized_payload["messages"] = messages
        sanitized_payload["stream"] = True
        return sanitized_payload

    @staticmethod
    def _extract_openai_delta(raw_chunk: bytes | str) -> tuple[Optional[str], bool]:
        chunk = raw_chunk.decode("utf-8") if isinstance(raw_chunk, bytes) else str(raw_chunk)
        chunk = chunk.strip()
        if not chunk:
            return None, False
        if not chunk.startswith("data: "):
            return None, False
        data_str = chunk[len("data: "):].strip()
        return StreamingEngine._extract_openai_delta_data(data_str)

    @staticmethod
    def _extract_openai_delta_data(data_str: str) -> tuple[Optional[str], bool]:
        if data_str == "[DONE]":
            return None, True
        try:
            data_json = json.loads(data_str)
        except json.JSONDecodeError:
            return None, False
        choices = data_json.get("choices") or []
        if not choices:
            return None, False
        delta = choices[0].get("delta") or {}
        content = delta.get("content")
        return content if isinstance(content, str) else None, False

    @staticmethod
    def _normalize_legacy_sse_text(text: str) -> str:
        stripped = text.strip()
        if "\n" in text or not stripped.startswith("data: "):
            return text
        data_str = stripped[len("data: "):].strip()
        if data_str == "[DONE]":
            return text + "\n\n"
        try:
            json.loads(data_str)
        except json.JSONDecodeError:
            return text
        return text + "\n\n"

    async def _sanitize_stream_text(self, text: str) -> tuple[str, int]:
        sanitized = sanitize_text(text)
        entity_count = 1 if sanitized != text else 0
        if settings.FF_SECURITY_PIPELINE and settings.FF_STREAM_SCAN:
            from app.core.detection.presidio_engine import presidio_engine

            if not presidio_engine.is_healthy():
                raise RuntimeError("stream_security_scanner_unavailable")
            scan_result = await presidio_engine.scan(text)
            if scan_result.has_detections:
                sanitized = sanitize_text(scan_result.sanitized_text)
                entity_count = max(entity_count, len(scan_result.detections))
        return sanitized, entity_count

    async def _apply_stream_security(
        self,
        tenant_id: uuid.UUID,
        api_key_id: uuid.UUID,
        text: str,
    ) -> tuple[str, int]:
        if not (settings.FF_SECURITY_PIPELINE and settings.FF_STREAM_SCAN):
            return await self._sanitize_stream_text(text)

        from app.core.database import AsyncSessionLocal
        from app.core.detection.classification import classifier
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.events.producer import producer as event_producer
        from app.core.policy.cache import policy_cache
        from app.core.policy.evaluator import evaluator as policy_evaluator
        from app.schemas.security_events import (
            ContentRedactedEvent,
            PHIDetectedEvent,
            PIIDetectedEvent,
            PolicyEvaluatedEvent,
            ResponseBlockedEvent,
        )

        if not presidio_engine.is_healthy():
            raise RuntimeError("stream_security_scanner_unavailable")

        async with AsyncSessionLocal() as db:
            compiled_policy = await policy_cache.get(tenant_id, db)

        scan_result = await presidio_engine.scan(text)
        decision = policy_evaluator.evaluate(
            detections=scan_result.detections,
            text=text,
            compiled_policy=compiled_policy,
            shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
        )
        entity_count = len(scan_result.detections)

        if scan_result.has_detections or decision.keyword_hits:
            entity_actions = compiled_policy.get("entity_actions", {})
            reversible_entities = compiled_policy.get("reversible_entities", [])
            classification_overrides = compiled_policy.get("classification_overrides", {})
            entity_types = scan_result.entity_types
            max_risk = classifier.max_risk(entity_types, classification_overrides) if entity_types else None
            pii_entities = [item for item in entity_types if not item.startswith("PHI_")]
            phi_entities = [item for item in entity_types if item.startswith("PHI_")]
            detection_payload = {
                "entity_types": entity_types,
                "max_risk_level": max_risk.value if max_risk else "UNKNOWN",
                "detection_count": entity_count,
                "latency_presidio_ms": scan_result.latency_ms,
                "policy_action": decision.action.value,
                "shadow_mode": settings.FF_SECURITY_SHADOW_MODE,
                "keyword_hits": decision.keyword_hits,
            }

            if pii_entities:
                asyncio.create_task(event_producer.publish_security_event(
                    PIIDetectedEvent(
                        event_type="completion.pii_detected",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                        payload={**detection_payload, "pii_entities": pii_entities},
                    )
                ))
            if phi_entities:
                asyncio.create_task(event_producer.publish_security_event(
                    PHIDetectedEvent(
                        event_type="completion.phi_detected",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                        payload={**detection_payload, "phi_entities": phi_entities},
                    )
                ))
            asyncio.create_task(event_producer.publish_security_event(
                PolicyEvaluatedEvent(
                    event_type="policy.evaluated",
                    tenant_id=str(tenant_id),
                    request_id=str(api_key_id),
                    direction="OUTBOUND",
                    shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                    payload={
                        "policies_evaluated": len(compiled_policy.get("policy_ids", [])) or 1,
                        "rules_evaluated": len(compiled_policy.get("entity_actions", {})),
                        "violations_found": len(decision.violations),
                        "evaluation_ms": scan_result.latency_ms,
                        "action": decision.action.value,
                    },
                )
            ))

            if decision.should_block:
                asyncio.create_task(event_producer.publish_security_event(
                    ResponseBlockedEvent(
                        event_type="response.blocked",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=False,
                        payload={
                            "block_reason": decision.block_reason or "Completion blocked by tenant policy.",
                            "entity_types": entity_types,
                            "keyword_hits": decision.keyword_hits,
                        },
                    )
                ))
                raise StreamingSecurityBlocked(decision.block_reason or "Completion blocked by tenant policy.")

            if decision.should_redact and scan_result.detections:
                from app.core.engine.token_vault import TokenVaultService

                transformed, redaction_mode = await TokenVaultService.apply_redaction(
                    text,
                    scan_result.detections,
                    scan_result.sanitized_text,
                    "NONE",
                    entity_actions,
                    reversible_entities,
                    tenant_id,
                )
                asyncio.create_task(event_producer.publish_security_event(
                    ContentRedactedEvent(
                        event_type="completion.redacted",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=False,
                        payload={
                            "redaction_mode": redaction_mode,
                            "entities_redacted": decision.redact_entities or entity_types,
                            "entity_count": entity_count,
                        },
                    )
                ))
                return transformed, entity_count

        return scan_result.sanitized_text if scan_result.has_detections else sanitize_text(text), entity_count

    async def _make_security_scan_fn(self, tenant_id: uuid.UUID, api_key_id: uuid.UUID):
        """
        Returns an async scan function compatible with StreamingBuffer.
        The function performs Presidio analysis on a text chunk and returns
        (sanitized_text, entity_count).
        Called once per stream setup — the closure captures the security engine.
        """
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.policy.cache import policy_cache
        from app.core.policy.evaluator import evaluator as policy_evaluator
        from app.schemas.security_events import PIIDetectedEvent, PHIDetectedEvent
        from app.core.events.producer import producer as event_producer

        # Pre-fetch compiled policy once for the stream lifetime
        # (avoids per-chunk Redis calls on the hot path)
        # Note: we can't await here; this is called at setup time in an async context
        compiled_policy = {}

        async def scan_fn(text: str):
            nonlocal compiled_policy
            # Lazy-load policy on first chunk
            if not compiled_policy:
                try:
                    from app.core.database import AsyncSessionLocal
                    async with AsyncSessionLocal() as db:
                        compiled_policy = await policy_cache.get(tenant_id, db)
                except Exception:
                    compiled_policy = {}

            if not presidio_engine.is_healthy():
                return text, 0  # Fail open on unhealthy engine

            scan_result = await presidio_engine.scan(text)
            entity_count = len(scan_result.detections)

            if scan_result.has_detections and not settings.FF_SECURITY_SHADOW_MODE:
                decision = policy_evaluator.evaluate(
                    detections=scan_result.detections,
                    text=text,
                    compiled_policy=compiled_policy,
                    shadow_mode=False,
                )
                return scan_result.sanitized_text, entity_count
            elif scan_result.has_detections:
                # Shadow mode: emit events but return original
                entity_types = scan_result.entity_types
                phi_entities = [et for et in entity_types if et.startswith("PHI_")]
                pii_entities = [et for et in entity_types if not et.startswith("PHI_")]
                if pii_entities:
                    asyncio.create_task(event_producer.publish_security_event(
                        PIIDetectedEvent(
                            event_type="completion.pii_detected",
                            tenant_id=str(tenant_id),
                            request_id=str(api_key_id),
                            direction="OUTBOUND",
                            shadow_mode=True,
                            payload={"entity_types": entity_types, "pii_entities": pii_entities},
                        )
                    ))
                return text, entity_count  # Shadow: return original

            return scan_result.sanitized_text if scan_result.has_detections else text, entity_count

        return scan_fn

    async def stream_response(
        self,
        tenant_id: uuid.UUID,
        api_key_id: uuid.UUID,
        provider_id: uuid.UUID,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        provider_name: str,
        adapter,
        streaming_mode: str = StreamingMode.BUFFERED,
        window_size: int = 20,
    ) -> StreamingResponse:
        stream_id = str(uuid.uuid4())
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        request_payload = adapter.transform_request(self._sanitize_request_payload(payload))
        decision = await self.rate_limiter.acquire_stream(self.db, tenant_id, api_key_id)
        if not decision.allowed:
            await self.audit_engine.publish_stream_failed(
                stream_id=stream_id,
                partial_response_hash=hashlib.sha256(b"").hexdigest(),
                failure_reason="stream_rate_limited",
                policy_violation_details={"scope": decision.scope, "plan": decision.plan},
            )

            async def rate_limited_generator() -> AsyncGenerator[str, None]:
                yield self._safe_sse_payload({
                    "error": {
                        "message": "Rate limit exceeded. Please retry later.",
                        "type": "rate_limit_exceeded",
                        "code": "stream_rate_limited",
                    }
                })
                yield self._done_sse()

            return StreamingResponse(rate_limited_generator(), status_code=429, media_type="text/event-stream")

        async def event_generator() -> AsyncGenerator[str, None]:
            start_time = time.monotonic()

            full_response_chunks = []
            released_response = ""
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    try:
                        async with client.stream("POST", url, headers=headers, json=request_payload) as response:
                            if response.status_code >= 400:
                                await self.audit_engine.publish_stream_failed(
                                    stream_id=stream_id,
                                    partial_response_hash=hashlib.sha256(b"").hexdigest(),
                                    failure_reason="upstream_provider_stream_error",
                                    policy_violation_details={"status_code": response.status_code},
                                )
                                yield self._safe_sse_payload({
                                    "error": {
                                        "message": "Upstream provider streaming failed.",
                                        "type": "provider_error",
                                        "code": "upstream_stream_error",
                                    }
                                })
                                yield self._done_sse()
                                return

                            await self.audit_engine.publish_stream_started(
                                stream_id=stream_id,
                                tenant_id=tenant_id,
                                api_key_id=api_key_id,
                                provider_id=provider_id,
                                security_mode=streaming_mode,
                                prompt_hash=prompt_hash,
                            )

                            from app.core.engine.streaming_state_machine import StreamingRedactionStateMachine

                            decoder = Utf8IncrementalDecoder()
                            parser = SseParser()
                            state_machine = StreamingRedactionStateMachine(max_window_chars=max(window_size, 20) * 1024)
                            completion_chunks_seen = 0
                            done = False

                            async for raw_chunk in adapter.stream_response(response):
                                if isinstance(raw_chunk, str):
                                    decoded_text = raw_chunk
                                else:
                                    decoded_text = decoder.decode(raw_chunk)
                                if not decoded_text:
                                    continue

                                decoded_text = self._normalize_legacy_sse_text(decoded_text)
                                for event in parser.feed(decoded_text):
                                    if event.data is None:
                                        continue
                                    content, done = self._extract_openai_delta_data(event.data.strip())
                                    if done:
                                        break
                                    if content:
                                        completion_chunks_seen += 1
                                        state_machine.append(ParsedSseEvent(data=content))
                                        for window in state_machine.emit_safe():
                                            full_response_chunks.append(window.text)
                                if done:
                                    break

                            if not done:
                                decoded_text = decoder.flush()
                                if decoded_text:
                                    for event in parser.feed(self._normalize_legacy_sse_text(decoded_text)):
                                        if event.data is None:
                                            continue
                                        content, done = self._extract_openai_delta_data(event.data.strip())
                                        if done:
                                            break
                                        if content:
                                            completion_chunks_seen += 1
                                            state_machine.append(ParsedSseEvent(data=content))
                                            for window in state_machine.emit_safe():
                                                full_response_chunks.append(window.text)
                                        if done:
                                            break
                            if not done:
                                parser.flush()
                            state_machine.end_of_stream()
                            for window in state_machine.flush():
                                full_response_chunks.append(window.text)

                            raw_response = "".join(full_response_chunks)
                            try:
                                sanitized_response, entity_count = await self._apply_stream_security(
                                    tenant_id,
                                    api_key_id,
                                    raw_response,
                                )
                            except StreamingSecurityBlocked as blocked_exc:
                                await self.audit_engine.publish_stream_failed(
                                    stream_id=stream_id,
                                    partial_response_hash=hashlib.sha256(b"").hexdigest(),
                                    failure_reason="stream_policy_blocked",
                                    policy_violation_details={"released": False},
                                )
                                yield self._safe_sse_payload({
                                    "error": {
                                        "message": "Response blocked by AuthClaw security policy.",
                                        "type": "security_policy_violation",
                                        "code": "response_blocked",
                                        "block_reason": blocked_exc.reason,
                                    }
                                })
                                yield self._done_sse()
                                return
                            except Exception as scan_exc:
                                logger.error("Streaming response scan failed closed: %s", scan_exc)
                                await self.audit_engine.publish_stream_failed(
                                    stream_id=stream_id,
                                    partial_response_hash=hashlib.sha256(b"").hexdigest(),
                                    failure_reason="stream_security_scan_failed",
                                    policy_violation_details={"released": False},
                                )
                                yield self._safe_sse_payload({
                                    "error": {
                                        "message": "Gateway stream security scan failed. Response was not released.",
                                        "type": "security_pipeline_error",
                                        "code": "stream_security_scan_failed",
                                    }
                                })
                                yield self._done_sse()
                                return

                            released_response = sanitized_response
                            if sanitized_response:
                                yield self._safe_sse_payload({
                                    "choices": [
                                        {
                                            "delta": {"content": sanitized_response},
                                            "index": 0,
                                            "finish_reason": None,
                                        }
                                    ],
                                    "authclaw": {
                                        "streaming_mode": "strict_buffered_safe",
                                        "redaction_applied": entity_count > 0,
                                        "entity_count": entity_count,
                                    },
                                })
                            yield self._done_sse()

                            # Stream complete
                            latency_ms = int((time.monotonic() - start_time) * 1000)
                            response_hash = hashlib.sha256(released_response.encode()).hexdigest()

                            await self.audit_engine.publish_stream_completed(
                                stream_id=stream_id,
                                response_hash=response_hash,
                                prompt_tokens=0,
                                completion_tokens=completion_chunks_seen,
                                latency_ms=latency_ms,
                            )

                    except Exception as e:
                        logger.error("STREAMING EXCEPTION: %s", e)
                        partial_response = released_response
                        partial_hash = hashlib.sha256(partial_response.encode()).hexdigest()
                        await self.audit_engine.publish_stream_failed(
                            stream_id=stream_id,
                            partial_response_hash=partial_hash,
                            failure_reason="streaming_error",
                            policy_violation_details=None,
                        )
                        yield self._safe_sse_payload({
                            "error": {
                                "message": "Gateway streaming failed safely.",
                                "type": "gateway_streaming_error",
                                "code": "streaming_error",
                            }
                        })
                        yield self._done_sse()
            finally:
                await self.rate_limiter.release_stream(tenant_id, api_key_id)

        return StreamingResponse(event_generator(), media_type="text/event-stream")
