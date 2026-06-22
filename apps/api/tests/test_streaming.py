import pytest
import json
import uuid
from unittest.mock import patch, MagicMock, AsyncMock
from app.core.engine.streaming import StreamingEngine, StreamingMode
from app.core.engine.audit import AuditEngine

@pytest.fixture
def mock_audit_engine():
    engine = MagicMock(spec=AuditEngine)
    engine.publish_stream_started = AsyncMock()
    engine.publish_stream_completed = AsyncMock()
    engine.publish_stream_failed = AsyncMock()
    return engine

@pytest.fixture
def streaming_engine(mock_audit_engine):
    return StreamingEngine(audit_engine=mock_audit_engine)

@pytest.mark.asyncio
async def test_streaming_engine_buffered_success(streaming_engine, mock_audit_engine):
    # Mock httpx client stream
    class MockStreamContext:
        status_code = 200
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        def raise_for_status(self):
            pass
        async def aiter_lines(self):
            lines = [
                'data: {"choices": [{"delta": {"content": "Hello"}}]}',
                'data: {"choices": [{"delta": {"content": " World"}}]}',
                'data: [DONE]'
            ]
            for line in lines:
                yield line

    class MockClientContext:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        def stream(self, *args, **kwargs):
            return MockStreamContext()

    tenant_id = uuid.uuid4()
    api_key_id = uuid.uuid4()
    provider_id = uuid.uuid4()

    mock_adapter = MagicMock()
    mock_adapter.transform_request.return_value = {"messages": []}
    async def mock_stream_response(resp):
        lines = [
            b'data: {"choices": [{"delta": {"content": "Hello"}}]}',
            b'data: {"choices": [{"delta": {"content": " World"}}]}',
            b'data: [DONE]'
        ]
        for line in lines:
            yield line
    mock_adapter.stream_response = mock_stream_response

    with patch('httpx.AsyncClient', return_value=MockClientContext()):
        response = await streaming_engine.stream_response(
            tenant_id=tenant_id,
            api_key_id=api_key_id,
            provider_id=provider_id,
            url="http://test.com",
            headers={},
            payload={"messages": []},
            provider_name="test",
            adapter=mock_adapter,
            streaming_mode=StreamingMode.BUFFERED,
            window_size=2
        )
        
        # Iterate through the async generator
        chunks = [chunk async for chunk in response.body_iterator]
        
        assert len(chunks) == 3
        assert "Hello" in chunks[0]
        assert "World" in chunks[1]
        assert "[DONE]" in chunks[2]

        mock_audit_engine.publish_stream_started.assert_called_once()
        mock_audit_engine.publish_stream_completed.assert_called_once()
        mock_audit_engine.publish_stream_failed.assert_not_called()

@pytest.mark.asyncio
async def test_streaming_engine_passthrough_failure(streaming_engine, mock_audit_engine):
    # Mock httpx client stream that throws exception midway
    class MockStreamContext:
        status_code = 200
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        def raise_for_status(self):
            pass
        async def aiter_lines(self):
            yield 'data: {"choices": [{"delta": {"content": "Hello"}}]}'
            raise ConnectionError("Upstream disconnected")

    class MockClientContext:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        def stream(self, *args, **kwargs):
            return MockStreamContext()

    tenant_id = uuid.uuid4()
    api_key_id = uuid.uuid4()
    provider_id = uuid.uuid4()

    mock_adapter = MagicMock()
    mock_adapter.transform_request.return_value = {"messages": []}
    async def mock_stream_response(resp):
        yield b'data: {"choices": [{"delta": {"content": "Hello"}}]}'
        raise ConnectionError("Upstream disconnected")
    mock_adapter.stream_response = mock_stream_response

    with patch('httpx.AsyncClient', return_value=MockClientContext()):
        response = await streaming_engine.stream_response(
            tenant_id=tenant_id,
            api_key_id=api_key_id,
            provider_id=provider_id,
            url="http://test.com",
            headers={},
            payload={"messages": []},
            provider_name="test",
            adapter=mock_adapter,
            streaming_mode=StreamingMode.PASSTHROUGH,
            window_size=2
        )
        
        chunks = []
        with pytest.raises(ConnectionError):
            async for chunk in response.body_iterator:
                chunks.append(chunk)

        assert len(chunks) == 1
        assert "Hello" in chunks[0]
        
        mock_audit_engine.publish_stream_started.assert_called_once()
        mock_audit_engine.publish_stream_completed.assert_not_called()
        mock_audit_engine.publish_stream_failed.assert_called_once()
