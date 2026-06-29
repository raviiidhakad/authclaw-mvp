"""
E2.3 isolated rolling streaming buffer and redaction state machine.

This module consumes ParsedSseEvent objects from the isolated SSE parser. It is
not connected to Gateway, StreamingEngine, provider adapters, policy
enforcement, OPA, or tokenization.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator

from app.core.engine.sse_parser import ParsedSseEvent
from app.core.engine.streaming_contracts import (
    StreamingContext,
    StreamingRedactionStateMachineContract,
    StreamingTextWindow,
)


class StreamingState(str, Enum):
    INITIAL = "initial"
    BUFFERING = "buffering"
    SCANNING = "scanning"
    READY_TO_EMIT = "ready_to_emit"
    EMITTING = "emitting"
    FLUSHING = "flushing"
    COMPLETE = "complete"
    ERROR = "error"


class StreamingStateMachineError(RuntimeError):
    """Controlled state-machine failure without buffered text disclosure."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"streaming_state_machine_error:{reason}")
        self.reason = reason


@dataclass(frozen=True)
class StreamingBufferSnapshot:
    state: StreamingState
    buffered_chars: int
    sequence: int
    end_seen: bool


class StreamingRedactionStateMachine(StreamingRedactionStateMachineContract):
    """
    Rolling text-window state machine for future streaming redaction.

    It determines which decoded SSE data text is structurally safe to hand to
    later policy/redaction phases. It does not inspect semantics, redact,
    tokenize, detokenize, parse JSON, or evaluate policy.
    """

    _BOUNDARY_CHARS = frozenset(" \t\r\n,;!?)]}\"'")

    def __init__(
        self,
        *,
        look_behind_chars: int = 64,
        look_ahead_chars: int = 64,
        max_window_chars: int = 8192,
    ) -> None:
        if look_behind_chars < 0 or look_ahead_chars < 0:
            raise ValueError("look-behind and look-ahead must be non-negative")
        if max_window_chars <= max(look_behind_chars, look_ahead_chars):
            raise ValueError("max_window_chars must exceed look-behind/look-ahead")

        self._look_behind = look_behind_chars
        self._look_ahead = look_ahead_chars
        self._max_window = max_window_chars
        self._segments: deque[str] = deque()
        self._buffered_chars = 0
        self._state = StreamingState.INITIAL
        self._sequence = 0
        self._end_seen = False

    @property
    def state(self) -> StreamingState:
        return self._state

    def snapshot(self) -> StreamingBufferSnapshot:
        return StreamingBufferSnapshot(
            state=self._state,
            buffered_chars=self._buffered_chars,
            sequence=self._sequence,
            end_seen=self._end_seen,
        )

    def append(self, event: ParsedSseEvent) -> None:
        """Append parsed SSE data text to the rolling buffer."""
        self._require_state(
            {
                StreamingState.INITIAL,
                StreamingState.BUFFERING,
                StreamingState.READY_TO_EMIT,
                StreamingState.EMITTING,
            },
            "append_not_allowed",
        )
        if not isinstance(event, ParsedSseEvent):
            self._fail("invalid_event")
        if self._end_seen:
            self._fail("append_after_end_of_stream")

        text = event.data or ""
        if text:
            self._segments.append(text)
            self._buffered_chars += len(text)
            if self._buffered_chars > self._max_window:
                self._fail("window_overflow")

        self._transition(StreamingState.BUFFERING)
        if self._eligible_emit_len() > 0:
            self._transition(StreamingState.READY_TO_EMIT)

    def emit_safe(self) -> tuple[StreamingTextWindow, ...]:
        """
        Emit structurally safe text windows.

        Returned windows are not redacted and not policy-approved. They are only
        safe to pass to later policy/redaction phases because the retained suffix
        protects unfinished words, regex matches, and entity continuations.
        """
        self._require_state(
            {StreamingState.BUFFERING, StreamingState.READY_TO_EMIT},
            "emit_not_allowed",
        )
        if self._buffered_chars == 0:
            self._transition(StreamingState.BUFFERING)
            return ()

        self._transition(StreamingState.SCANNING)
        emit_len = self._safe_emit_len()
        if emit_len <= 0:
            self._transition(StreamingState.BUFFERING)
            return ()

        self._transition(StreamingState.READY_TO_EMIT)
        safe_prefix = self._consume(emit_len)
        if not safe_prefix:
            self._transition(StreamingState.BUFFERING)
            return ()

        self._transition(StreamingState.EMITTING)
        self._sequence += 1
        retained_suffix = self._buffer_text()
        window = StreamingTextWindow(
            text=safe_prefix,
            safe_prefix=safe_prefix,
            retained_suffix=retained_suffix,
            sequence=self._sequence,
            is_final=False,
        )
        self._transition(StreamingState.BUFFERING if self._buffered_chars else StreamingState.INITIAL)
        return (window,)

    def flush(self) -> tuple[StreamingTextWindow, ...]:
        """Flush remaining buffered text at stream end."""
        self._require_state(
            {
                StreamingState.INITIAL,
                StreamingState.BUFFERING,
                StreamingState.READY_TO_EMIT,
                StreamingState.COMPLETE,
            },
            "flush_not_allowed",
        )
        if self._state == StreamingState.COMPLETE:
            return ()
        if not self._end_seen:
            self._fail("flush_before_end_of_stream")

        self._transition(StreamingState.FLUSHING)
        if self._buffered_chars == 0:
            self._transition(StreamingState.COMPLETE)
            return ()

        final_text = self._consume(self._buffered_chars)
        self._sequence += 1
        window = StreamingTextWindow(
            text=final_text,
            safe_prefix=final_text,
            retained_suffix="",
            sequence=self._sequence,
            is_final=True,
        )
        self._transition(StreamingState.COMPLETE)
        return (window,)

    def end_of_stream(self) -> None:
        self._require_state(
            {
                StreamingState.INITIAL,
                StreamingState.BUFFERING,
                StreamingState.READY_TO_EMIT,
                StreamingState.EMITTING,
            },
            "end_not_allowed",
        )
        self._end_seen = True
        self._transition(StreamingState.BUFFERING if self._buffered_chars else StreamingState.COMPLETE)

    def reset(self) -> None:
        self._segments.clear()
        self._buffered_chars = 0
        self._sequence = 0
        self._end_seen = False
        self._state = StreamingState.INITIAL

    async def process_text(
        self,
        context: StreamingContext,
        text: str,
        *,
        is_final: bool = False,
    ) -> AsyncIterator[StreamingTextWindow]:
        """Compatibility method for the Phase 1 state-machine contract."""
        _ = context
        event = ParsedSseEvent(data=text)
        self.append(event)
        for window in self.emit_safe():
            yield window
        if is_final:
            self.end_of_stream()
            for window in self.flush():
                yield window

    def _safe_emit_len(self) -> int:
        eligible_len = self._eligible_emit_len()
        if eligible_len <= 0:
            return 0

        text = self._buffer_text()
        cut = eligible_len
        while cut > 0 and text[cut - 1] not in self._BOUNDARY_CHARS:
            cut -= 1
        return cut

    def _eligible_emit_len(self) -> int:
        retained = max(self._look_behind, self._look_ahead)
        return max(0, self._buffered_chars - retained)

    def _buffer_text(self) -> str:
        return "".join(self._segments)

    def _consume(self, count: int) -> str:
        if count < 0 or count > self._buffered_chars:
            self._fail("internal_corruption")

        remaining = count
        output: list[str] = []
        while remaining and self._segments:
            segment = self._segments[0]
            if len(segment) <= remaining:
                output.append(self._segments.popleft())
                self._buffered_chars -= len(segment)
                remaining -= len(segment)
            else:
                output.append(segment[:remaining])
                self._segments[0] = segment[remaining:]
                self._buffered_chars -= remaining
                remaining = 0

        if remaining != 0:
            self._fail("internal_corruption")
        return "".join(output)

    def _require_state(self, allowed: set[StreamingState], reason: str) -> None:
        if self._state not in allowed:
            self._fail(reason)

    def _transition(self, next_state: StreamingState) -> None:
        allowed = {
            StreamingState.INITIAL: {StreamingState.BUFFERING, StreamingState.COMPLETE},
            StreamingState.BUFFERING: {
                StreamingState.SCANNING,
                StreamingState.READY_TO_EMIT,
                StreamingState.FLUSHING,
                StreamingState.COMPLETE,
            },
            StreamingState.SCANNING: {StreamingState.BUFFERING, StreamingState.READY_TO_EMIT},
            StreamingState.READY_TO_EMIT: {
                StreamingState.SCANNING,
                StreamingState.EMITTING,
                StreamingState.BUFFERING,
                StreamingState.FLUSHING,
            },
            StreamingState.EMITTING: {StreamingState.BUFFERING, StreamingState.INITIAL},
            StreamingState.FLUSHING: {StreamingState.COMPLETE},
            StreamingState.COMPLETE: set(),
            StreamingState.ERROR: {StreamingState.INITIAL},
        }
        if next_state == self._state:
            return
        if next_state not in allowed[self._state]:
            self._fail("illegal_state_transition")
        self._state = next_state

    def _fail(self, reason: str) -> None:
        self._segments.clear()
        self._buffered_chars = 0
        self._end_seen = False
        self._state = StreamingState.ERROR
        raise StreamingStateMachineError(reason)
