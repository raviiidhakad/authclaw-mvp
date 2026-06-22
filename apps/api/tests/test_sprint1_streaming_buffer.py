"""
Sprint 1 — Unit Tests: Streaming Buffer
Tests the sliding-window buffer with chunk boundary detection,
shadow mode, and failure handling.
"""
import pytest
import asyncio
from typing import List


async def _make_stream(chunks: List[str]):
    """Helper: turn a list of strings into an async generator."""
    for chunk in chunks:
        yield chunk


class MockScanner:
    """Mock scan function for streaming buffer tests."""
    
    def __init__(self, detected_entity: str = "EMAIL_ADDRESS", mask: str = "<EMAIL>"):
        self.calls = []
        self.detected_entity = detected_entity
        self.mask = mask

    async def scan(self, text: str):
        self.calls.append(text)
        # Simulate: replace any email-like string
        import re
        pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        sanitized = re.sub(pattern, self.mask, text)
        entity_count = len(re.findall(pattern, text))
        return sanitized, entity_count


class FailingScanner:
    """Mock scanner that raises an exception."""
    async def scan(self, text: str):
        raise RuntimeError("Scanner failure")


class TestStreamingBuffer:
    """Unit tests for the sliding-window StreamingBuffer."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_passthrough_when_no_pii(self):
        """Clean text with no PII should pass through unchanged."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        scanner = MockScanner()
        buffer = StreamingBuffer(scan_fn=scanner.scan, buffer_size=20)
        chunks = ["Hello ", "world ", "this is ", "safe content."]

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream(chunks)):
                result.append(chunk)
            return "".join(result)

        output = self._run(run())
        assert "Hello" in output
        assert "safe content" in output

    def test_detects_email_spanning_two_chunks(self):
        """Email split across chunk boundary should be detected and masked."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        scanner = MockScanner()
        buffer = StreamingBuffer(scan_fn=scanner.scan, buffer_size=30)
        # Email is split: "john.doe@" in chunk1, "acme.com" in chunk2
        chunks = ["My email is john.doe@", "acme.com please help."]

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream(chunks)):
                result.append(chunk)
            return "".join(result)

        output = self._run(run())
        # The full email should have been assembled and masked
        assert "john.doe@acme.com" not in output

    def test_shadow_mode_emits_but_does_not_redact(self):
        """In shadow mode, original text should be returned even when PII is detected."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        scanner = MockScanner()
        buffer = StreamingBuffer(scan_fn=scanner.scan, buffer_size=20, shadow_mode=True)
        chunks = ["Email: user@example.com"]

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream(chunks)):
                result.append(chunk)
            return "".join(result)

        output = self._run(run())
        # Shadow mode: original content preserved
        assert "user@example.com" in output

    def test_scan_failure_yields_original(self):
        """If the scanner raises, the buffer should yield the original chunk (fail open on stream)."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        failing = FailingScanner()
        buffer = StreamingBuffer(scan_fn=failing.scan, buffer_size=10)
        chunks = ["some text "] * 5

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream(chunks)):
                result.append(chunk)
            return "".join(result)

        # Should not raise — scanner failure yields original
        output = self._run(run())
        assert len(output) > 0

    def test_empty_stream(self):
        """Empty stream should produce empty output."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        scanner = MockScanner()
        buffer = StreamingBuffer(scan_fn=scanner.scan, buffer_size=20)

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream([])):
                result.append(chunk)
            return "".join(result)

        output = self._run(run())
        assert output == ""

    def test_single_chunk_smaller_than_buffer(self):
        """Single small chunk should be flushed in the final buffer scan."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        scanner = MockScanner()
        buffer = StreamingBuffer(scan_fn=scanner.scan, buffer_size=200)
        chunks = ["tiny"]

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream(chunks)):
                result.append(chunk)
            return "".join(result)

        output = self._run(run())
        assert "tiny" in output
        assert len(scanner.calls) == 1  # Final buffer flush

    def test_buffer_size_controls_window(self):
        """Buffer size should determine when content is yielded vs held."""
        from app.core.detection.streaming_buffer import StreamingBuffer
        
        scanner = MockScanner()
        buffer = StreamingBuffer(scan_fn=scanner.scan, buffer_size=5)
        # Each chunk is 2 chars; after 4 chunks (8 chars), safe portion (3 chars) yielded
        chunks = ["ab", "cd", "ef", "gh", "ij"]

        async def run():
            result = []
            async for chunk in buffer.process(_make_stream(chunks)):
                result.append(chunk)
            return "".join(result)

        output = self._run(run())
        assert len(output) > 0

