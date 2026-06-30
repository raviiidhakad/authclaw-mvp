"""SDK-side streaming client support for AuthClaw chat completions."""

from __future__ import annotations

import codecs
import json
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from .auth import build_authenticated_headers
from .client_contracts import StreamingRequestContract
from .config import AuthClawConfig
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    AuthClawError,
    ConfigurationError,
    RateLimitError,
    ServerError,
    StreamingError,
    TimeoutError,
    ValidationError,
)
from .models import StreamingDelta
from .transport import Transport, TransportRequest, TransportStreamResponse
from .types import FinishReason, StreamEventType
from .version import SDK_VERSION


@dataclass(frozen=True, slots=True)
class SseEvent:
    """Parsed SSE event emitted by the SDK-side parser."""

    data: str
    event: str | None = None
    event_id: str | None = None
    retry: int | None = None
    fields: tuple[tuple[str, str], ...] = field(default_factory=tuple)


class SdkSseParser:
    """Incremental SSE parser for AuthClaw SDK streams."""

    def __init__(self, *, max_event_chars: int = 1_000_000) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._text_buffer = ""
        self._event_fields: list[tuple[str, str]] = []
        self._max_event_chars = max_event_chars

    def feed(self, chunk: bytes | str) -> list[SseEvent]:
        text = self._decode(chunk, final=False)
        return self._feed_text(text)

    def flush(self) -> list[SseEvent]:
        text = self._decode(b"", final=True)
        events = self._feed_text(text)
        if self._text_buffer:
            events.extend(self._feed_text("\n"))
        if self._event_fields:
            raise StreamingError("Unexpected end of stream before SSE event completed")
        return events

    def reset(self) -> None:
        self._decoder.reset()
        self._text_buffer = ""
        self._event_fields = []

    def _decode(self, chunk: bytes | str, *, final: bool) -> str:
        if isinstance(chunk, str):
            return chunk
        try:
            return self._decoder.decode(chunk, final=final)
        except UnicodeDecodeError as exc:
            raise StreamingError("Streaming response contained invalid UTF-8") from exc

    def _feed_text(self, text: str) -> list[SseEvent]:
        self._text_buffer += text
        events: list[SseEvent] = []

        while True:
            line, separator, remainder = self._text_buffer.partition("\n")
            if not separator:
                break
            self._text_buffer = remainder
            line = line.removesuffix("\r")
            event = self._consume_line(line)
            if event is not None:
                events.append(event)

        if len(self._text_buffer) > self._max_event_chars:
            raise StreamingError("SSE line exceeded maximum supported size")
        return events

    def _consume_line(self, line: str) -> SseEvent | None:
        if line == "":
            if not self._event_fields:
                return None
            event = self._build_event()
            self._event_fields = []
            return event
        if line.startswith(":"):
            return None

        if ":" in line:
            field_name, value = line.split(":", 1)
            value = value[1:] if value.startswith(" ") else value
        else:
            field_name = line
            value = ""

        if not field_name:
            raise StreamingError("Malformed SSE field")
        self._event_fields.append((field_name, value))
        if sum(len(name) + len(value) for name, value in self._event_fields) > self._max_event_chars:
            raise StreamingError("SSE event exceeded maximum supported size")
        return None

    def _build_event(self) -> SseEvent:
        data_lines: list[str] = []
        event_name: str | None = None
        event_id: str | None = None
        retry: int | None = None

        for field_name, value in self._event_fields:
            if field_name == "data":
                data_lines.append(value)
            elif field_name == "event":
                event_name = value
            elif field_name == "id":
                event_id = value
            elif field_name == "retry":
                try:
                    retry = int(value)
                except ValueError as exc:
                    raise StreamingError("SSE retry field must be an integer") from exc

        return SseEvent(
            data="\n".join(data_lines),
            event=event_name,
            event_id=event_id,
            retry=retry,
            fields=tuple(self._event_fields),
        )


class StreamingResponseIterator:
    """Iterator over parsed AuthClaw streaming deltas."""

    def __init__(self, chunks: Iterable[bytes | str], parser: SdkSseParser | None = None) -> None:
        self._chunks = iter(chunks)
        self._parser = parser or SdkSseParser()
        self._pending: list[StreamingDelta] = []
        self._done = False
        self._closed = False

    def __iter__(self) -> "StreamingResponseIterator":
        return self

    def __next__(self) -> StreamingDelta:
        if self._closed:
            raise StopIteration
        while not self._pending:
            if self._done:
                self.close()
                raise StopIteration
            try:
                chunk = next(self._chunks)
            except StopIteration:
                self._pending.extend(self._events_to_deltas(self._parser.flush()))
                if not self._pending:
                    self.close()
                    raise StopIteration
                break
            except TimeoutError:
                raise
            except AuthClawError:
                raise
            except Exception as exc:
                raise StreamingError("Streaming connection interrupted") from exc
            self._pending.extend(self._events_to_deltas(self._parser.feed(chunk)))
        return self._pending.pop(0)

    def __enter__(self) -> "StreamingResponseIterator":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def _events_to_deltas(self, events: list[SseEvent]) -> list[StreamingDelta]:
        deltas: list[StreamingDelta] = []
        for event in events:
            if event.data == "[DONE]":
                self._done = True
                continue
            deltas.append(_parse_stream_delta(event))
        return deltas


class StreamingClient:
    """Synchronous SDK streaming client using the public AuthClaw API."""

    def __init__(self, config: AuthClawConfig, transport: Transport) -> None:
        self.config = config
        self.transport = transport

    def stream_chat_completion(
        self,
        request: StreamingRequestContract,
    ) -> StreamingResponseIterator:
        payload = request.to_dict()
        payload["stream"] = True
        response = self.transport.stream(
            TransportRequest(
                method="POST",
                url=self.config.build_url("chat/completions"),
                headers=self._headers(),
                json_body=payload,
                timeout=self.config.timeout,
            )
        )
        _raise_stream_status(response)
        return StreamingResponseIterator(response.chunks)

    def _headers(self) -> dict[str, str]:
        return build_authenticated_headers(
            self.config.auth_manager(),
            self.config.metadata,
            accept="text/event-stream",
        )


def _parse_stream_delta(event: SseEvent) -> StreamingDelta:
    if event.event == "error":
        raise StreamingError(_safe_error_message(event.data))
    try:
        payload = json.loads(event.data)
    except json.JSONDecodeError as exc:
        raise StreamingError("Streaming event payload was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise StreamingError("Streaming event payload must be a JSON object")
    if "error" in payload:
        raise StreamingError(_safe_error_message(payload["error"]))

    choice = _first_choice(payload.get("choices"))
    delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
    content = delta.get("content", "") if isinstance(delta, dict) else ""
    finish_reason = _parse_finish_reason(choice.get("finish_reason"))
    event_type = StreamEventType.MESSAGE_STOP if finish_reason else StreamEventType.CONTENT_DELTA
    return StreamingDelta(
        event_type=event_type,
        content=content if isinstance(content, str) else "",
        index=int(choice.get("index", 0)),
        finish_reason=finish_reason,
    )


def _first_choice(value: object) -> dict[str, object]:
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        raise StreamingError("Streaming payload choices must contain an object")
    return value[0]


def _parse_finish_reason(value: object) -> FinishReason | None:
    if value is None:
        return None
    try:
        return FinishReason(str(value))
    except ValueError as exc:
        raise StreamingError("Streaming payload contained an unsupported finish reason") from exc


def _safe_error_message(value: object) -> str:
    if isinstance(value, dict):
        for key in ("message", "detail", "title", "error"):
            item = value.get(key)
            if isinstance(item, str) and item:
                return item
    if isinstance(value, str) and value:
        return value
    return "AuthClaw streaming error"


def _raise_stream_status(response: TransportStreamResponse) -> None:
    if response.status_code < 400:
        return

    detail = response.text or f"AuthClaw streaming request failed with status {response.status_code}"
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
