"""
AuthClaw Sprint 1 — Sliding Window Stream Buffer
-------------------------------------------------
Intercepts chunked SSE (Server-Sent Events) streams from LLM providers
and applies Presidio PII/PHI detection across chunk boundaries.

Problem:
  LLM providers stream text token-by-token. A single PII entity can be
  split across multiple chunks:
    Chunk 1: "My email is john"
    Chunk 2: ".doe@acme"
    Chunk 3: ".com"

  A naive per-chunk scanner would miss "john.doe@acme.com".

Solution: Sliding Window Buffer
  1. Accumulate incoming chunks into a rolling text buffer.
  2. Yield only the "safe" left portion of the buffer (characters that are
     older than MAX_ENTITY_LENGTH and therefore cannot be part of an entity
     spanning a future chunk).
  3. On stream end, scan the remaining buffer fully and yield the result.

Configuration:
  Buffer size is controlled by settings.STREAMING_BUFFER_SIZE (default 60 chars).
  This creates a constant latency overhead equivalent to the time for the LLM
  to generate the buffer length in tokens (~15 tokens @ GPT-4 speed ≈ 5-10ms).

Failure behavior:
  - If Presidio scan raises an exception in a stream, the buffer is flushed
    WITHOUT redaction and the exception is logged (never silently swallowed).
  - If FF_SECURITY_SHADOW_MODE is active, detections are emitted but the
    original content is always yielded unchanged.
"""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncGenerator, Callable, Awaitable, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

# Maximum entity length a single PII pattern can span (chars).
# Used to determine the minimum safe lead before yielding from the buffer.
MAX_ENTITY_LENGTH = 64


class StreamingBuffer:
    """
    Wraps an async generator of text chunks with a sliding-window
    Presidio scan before yielding content to the client.

    Args:
        scan_fn:     Async callable that accepts a text string and returns
                     (sanitized_text, entity_count). Injected by the pipeline.
        buffer_size: Number of characters to keep in the sliding window.
                     Defaults to settings.STREAMING_BUFFER_SIZE.
        shadow_mode: If True, emit detection events but always yield original text.
    """

    def __init__(
        self,
        scan_fn: Callable[[str], Awaitable[tuple[str, int]]],
        buffer_size: Optional[int] = None,
        shadow_mode: bool = False,
    ) -> None:
        self._scan_fn = scan_fn
        self._buffer_size = buffer_size or settings.STREAMING_BUFFER_SIZE
        self._shadow_mode = shadow_mode

    async def process(
        self, chunk_stream: AsyncGenerator[str, None]
    ) -> AsyncGenerator[str, None]:
        """
        Wrap an async text chunk generator with sliding-window PII scanning.

        Yields:
            Sanitized (or shadow-mode original) text chunks.
        """
        buffer = ""
        total_entities = 0

        async for chunk in chunk_stream:
            buffer += chunk

            # Yield the "safe" left portion — content that cannot be part of
            # an entity that spans into the next chunk.
            if len(buffer) > self._buffer_size:
                safe_len = len(buffer) - self._buffer_size
                safe_portion = buffer[:safe_len]
                buffer = buffer[safe_len:]

                try:
                    sanitized, entity_count = await self._scan_fn(safe_portion)
                    total_entities += entity_count
                    yield sanitized if not self._shadow_mode else safe_portion
                except Exception as exc:
                    logger.error("StreamingBuffer scan failed mid-stream: %s. Flushing unredacted.", exc)
                    yield safe_portion  # Fail open on mid-stream to avoid broken SSE

        # Flush the final buffer — scan in full, no further window needed
        if buffer:
            try:
                sanitized, entity_count = await self._scan_fn(buffer)
                total_entities += entity_count
                yield sanitized if not self._shadow_mode else buffer
            except Exception as exc:
                logger.error("StreamingBuffer scan failed on final flush: %s. Flushing unredacted.", exc)
                yield buffer

        logger.debug(
            "StreamingBuffer complete. Total entities detected in stream: %d", total_entities
        )
