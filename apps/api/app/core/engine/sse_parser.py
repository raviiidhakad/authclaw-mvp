"""
E2.3 isolated Server-Sent Events parser.

The parser consumes decoded Unicode text only. UTF-8 reconstruction remains the
responsibility of Utf8IncrementalDecoder. This module is not connected to
Gateway, StreamingEngine, provider adapters, policy enforcement, or
tokenization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import AsyncIterable, AsyncIterator

from app.core.engine.streaming_contracts import SseEvent, SseParserContract


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
