import asyncio
import json
import random
import tracemalloc
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.engine.audit import AuditEngine
from app.core.engine.sse_parser import SseParser, SseParserError
from app.core.engine.streaming import StreamingEngine
from app.core.engine.streaming_state_machine import StreamingRedactionStateMachine, StreamingState
from app.core.engine.utf8_decoder import Utf8DecoderError, Utf8IncrementalDecoder


class FakeStreamContext:
    status_code = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeClientContext:
    def __init__(self, timeout=None, **_kwargs):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, *_args, **_kwargs):
        return FakeStreamContext()


def _audit():
    audit = MagicMock(spec=AuditEngine)
    audit.publish_stream_started = AsyncMock()
    audit.publish_stream_completed = AsyncMock()
    audit.publish_stream_failed = AsyncMock()
    return audit


def _adapter(chunks, *, exc_at=None):
    adapter = MagicMock()
    adapter.transform_request.return_value = {"messages": [], "stream": True}

    async def stream_response(_response):
        for index, chunk in enumerate(chunks):
            if exc_at is not None and index == exc_at:
                raise ConnectionError("provider stream interrupted")
            yield chunk

    adapter.stream_response = stream_response
    return adapter


def _event(content: str) -> bytes:
    return f'data: {{"choices":[{{"delta":{{"content":"{content}"}}}}]}}\n\n'.encode("utf-8")


def _first_content(rendered: str) -> str:
    first_line = rendered.split("\n\n", 1)[0]
    assert first_line.startswith("data: ")
    return json.loads(first_line[len("data: "):])["choices"][0]["delta"]["content"]


async def _render(chunks, *, adapter=None):
    engine = StreamingEngine(_audit())
    adapter = adapter or _adapter(chunks)
    with patch("httpx.AsyncClient", FakeClientContext):
        response = await engine.stream_response(
            tenant_id=uuid.uuid4(),
            api_key_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [], "stream": True},
            provider_name="test",
            adapter=adapter,
        )
        return "".join([chunk async for chunk in response.body_iterator])


def _random_chunks(payload: bytes, seed: int = 7):
    rng = random.Random(seed)
    chunks = []
    cursor = 0
    while cursor < len(payload):
        step = rng.randint(1, 23)
        chunks.append(payload[cursor:cursor + step])
        cursor += step
    return chunks


@pytest.mark.asyncio
async def test_long_stream_many_thousands_of_sse_events():
    chunks = [_event(f"word{index} ") for index in range(2500)]
    chunks.append(b"data: [DONE]\n\n")

    rendered = await _render(chunks)

    assert "word0 word1 word2" in rendered
    assert "word2497 word2498 word2499" in rendered


@pytest.mark.asyncio
async def test_large_multilingual_emoji_stream_with_random_boundaries():
    text = ("AuthClaw सुरक्षित 安全 🔐 " * 700).strip()
    payload = _event(text) + b"data: [DONE]\n\n"

    rendered = await _render(_random_chunks(payload))
    content = _first_content(rendered)

    assert "AuthClaw" in content
    assert "सुरक्षित" in content
    assert "安全" in content
    assert "\\ufffd" not in rendered


@pytest.mark.asyncio
async def test_provider_interruption_fails_closed_without_partial_release():
    chunks = [_event("first safe "), _event("second safe "), b"data: [DONE]\n\n"]
    adapter = _adapter(chunks, exc_at=1)

    rendered = await _render(chunks, adapter=adapter)

    assert "first safe" not in rendered
    assert "second safe" not in rendered
    assert "Gateway streaming failed safely" in rendered


@pytest.mark.asyncio
async def test_client_cancellation_does_not_retain_state():
    engine = StreamingEngine(_audit())
    adapter = _adapter([_event("cancel candidate "), b"data: [DONE]\n\n"])
    with patch("httpx.AsyncClient", FakeClientContext):
        response = await engine.stream_response(
            tenant_id=uuid.uuid4(),
            api_key_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [], "stream": True},
            provider_name="test",
            adapter=adapter,
        )
        iterator = response.body_iterator.__aiter__()
        await iterator.aclose()

    assert True


def test_decoder_repeated_malformed_utf8_recovers_after_reset():
    decoder = Utf8IncrementalDecoder()
    with pytest.raises(Utf8DecoderError):
        decoder.decode(b"\x80")

    decoder.reset()
    assert decoder.decode("safe 🔐".encode("utf-8")) == "safe 🔐"


def test_parser_repeated_malformed_sse_recovers_after_reset():
    parser = SseParser(max_event_chars=16)
    with pytest.raises(SseParserError):
        parser.feed("data: this-is-too-large\n")

    parser.reset()
    assert parser.feed("data: ok\n\n")[0].data == "ok"


def test_state_machine_memory_bounds_after_many_repeated_streams():
    for _ in range(100):
        machine = StreamingRedactionStateMachine(look_behind_chars=16, look_ahead_chars=16, max_window_chars=512)
        for _ in range(50):
            machine.append(__import__("app.core.engine.sse_parser", fromlist=["ParsedSseEvent"]).ParsedSseEvent(data="word "))
            machine.emit_safe()
            assert machine.snapshot().buffered_chars <= 512
        machine.end_of_stream()
        machine.flush()
        assert machine.state == StreamingState.COMPLETE
        assert machine.snapshot().buffered_chars == 0


def test_tracemalloc_no_unbounded_state_growth_in_isolated_pipeline():
    tracemalloc.start()
    try:
        before = tracemalloc.take_snapshot()
        for _ in range(50):
            decoder = Utf8IncrementalDecoder()
            parser = SseParser()
            machine = StreamingRedactionStateMachine(max_window_chars=1024)
            text = (_event("memory safe ") + b"data: [DONE]\n\n")
            decoded = decoder.decode(text) + decoder.flush()
            for event in parser.feed(decoded):
                if event.data and event.data != "[DONE]":
                    machine.append(__import__("app.core.engine.sse_parser", fromlist=["ParsedSseEvent"]).ParsedSseEvent(data="memory safe "))
                    machine.emit_safe()
            machine.end_of_stream()
            machine.flush()
        after = tracemalloc.take_snapshot()
        growth = sum(stat.size_diff for stat in after.compare_to(before, "lineno"))
    finally:
        tracemalloc.stop()

    assert growth < 2_000_000


@pytest.mark.asyncio
async def test_concurrent_streams_remain_ordered():
    async def run_stream(index):
        return await _render([_event(f"stream{index}-a "), _event(f"stream{index}-b "), b"data: [DONE]\n\n"])

    results = await asyncio.gather(*(run_stream(index) for index in range(20)))

    for index, rendered in enumerate(results):
        assert f"stream{index}-a stream{index}-b" in rendered
