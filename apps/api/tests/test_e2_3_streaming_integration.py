import uuid
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.engine.audit import AuditEngine
from app.core.engine.streaming import StreamingEngine, StreamingMode


class FakeStreamContext:
    status_code = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeClientContext:
    def __init__(self, timeout):
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


def _adapter(chunks):
    adapter = MagicMock()
    adapter.transform_request.return_value = {"messages": [], "stream": True}

    async def stream_response(_response):
        for chunk in chunks:
            yield chunk

    adapter.stream_response = stream_response
    return adapter


def _first_sse_payload(rendered: str):
    first_line = rendered.split("\n\n", 1)[0]
    assert first_line.startswith("data: ")
    return json.loads(first_line[len("data: "):])


async def _render(chunks):
    engine = StreamingEngine(_audit())
    adapter = _adapter(chunks)
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
            streaming_mode=StreamingMode.BUFFERED,
        )
        return "".join([chunk async for chunk in response.body_iterator])


@pytest.mark.asyncio
async def test_streaming_engine_accepts_sse_split_across_provider_chunks():
    chunks = [
        b'data: {"choices":[{"delta":{"content":"Hel',
        b'lo"}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":" World"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    rendered = await _render(chunks)

    assert "Hello World" in rendered
    assert rendered.endswith("data: [DONE]\n\n")


@pytest.mark.asyncio
async def test_streaming_engine_accepts_utf8_split_across_provider_chunks():
    event = 'data: {"choices":[{"delta":{"content":"safe 🔐"}}]}\n\n'.encode("utf-8")
    lock_start = event.index("🔐".encode("utf-8"))
    chunks = [
        event[:lock_start + 1],
        event[lock_start + 1:lock_start + 3],
        event[lock_start + 3:],
        b"data: [DONE]\n\n",
    ]

    rendered = await _render(chunks)
    payload = _first_sse_payload(rendered)

    assert payload["choices"][0]["delta"]["content"] == "safe 🔐"
    assert "\ufffd" not in rendered


@pytest.mark.asyncio
async def test_streaming_engine_output_remains_single_buffered_delta():
    chunks = [
        b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":" World"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    rendered = await _render(chunks)

    assert rendered.count('"delta"') == 1
    assert "strict_buffered_safe" in rendered
    assert "Hello World" in rendered


@pytest.mark.asyncio
async def test_streaming_engine_large_streaming_response_remains_ordered():
    chunks = [
        f'data: {{"choices":[{{"delta":{{"content":"word{idx} "}}}}]}}\n\n'.encode("utf-8")
        for idx in range(200)
    ]
    chunks.append(b"data: [DONE]\n\n")

    rendered = await _render(chunks)

    assert "word0 word1 word2" in rendered
    assert "word197 word198 word199" in rendered


def test_phase5_does_not_import_provider_adapters_or_gateway_at_module_load():
    import inspect
    import app.core.engine.streaming as streaming_module

    source = inspect.getsource(streaming_module)
    module_preamble = source.split("class StreamingMode:", 1)[0]

    assert "app.core.engine.gateway" not in module_preamble
    assert "app.core.providers.adapters" not in source
