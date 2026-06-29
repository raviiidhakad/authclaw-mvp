"""
E2.3 isolated UTF-8 incremental decoder.

This module does not integrate with Gateway, StreamingEngine, provider adapters,
policy enforcement, or tokenization. It is a reusable building block for later
SSE parsing phases.
"""
from __future__ import annotations

import codecs
from threading import RLock

from app.core.engine.streaming_contracts import Utf8IncrementalDecoderContract


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

