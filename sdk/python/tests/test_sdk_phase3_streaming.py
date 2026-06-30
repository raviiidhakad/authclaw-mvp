from __future__ import annotations

import pytest

from authclaw import (
    AuthClawClient,
    ChatMessage,
    ConfigurationError,
    MessageRole,
    MockTransport,
    RateLimitError,
    SdkSseParser,
    ServerError,
    SseEvent,
    StreamingError,
    StreamingRequestContract,
    StreamingResponseIterator,
    TransportStreamResponse,
)
from authclaw.types import FinishReason, StreamEventType


def _event(content: str, *, finish_reason: str | None = None) -> str:
    payload = {
        "choices": [
            {
                "index": 0,
                "delta": {"content": content},
                "finish_reason": finish_reason,
            }
        ]
    }
    import json

    return f"data: {json.dumps(payload)}\n\n"


def _stream_request() -> StreamingRequestContract:
    return StreamingRequestContract(
        model="llama",
        messages=(ChatMessage(role=MessageRole.USER, content="hello"),),
    )


def test_sse_parser_parses_single_and_done_events() -> None:
    parser = SdkSseParser()

    events = parser.feed("event: message\ndata: hello\n\n")
    events.extend(parser.feed("data: [DONE]\n\n"))

    assert events == [
        SseEvent(data="hello", event="message", event_id=None, retry=None, fields=(("event", "message"), ("data", "hello"))),
        SseEvent(data="[DONE]", event=None, event_id=None, retry=None, fields=(("data", "[DONE]"),)),
    ]


def test_sse_parser_handles_incremental_chunks_and_multiline_data() -> None:
    parser = SdkSseParser()

    assert parser.feed("id: 1\ndata: hel") == []
    events = parser.feed("lo\ndata: world\nretry: 5\n\n")

    assert len(events) == 1
    assert events[0].event_id == "1"
    assert events[0].retry == 5
    assert events[0].data == "hello\nworld"


def test_sse_parser_handles_utf8_split_across_bytes() -> None:
    parser = SdkSseParser()
    data = "data: नमस्ते\n\n".encode("utf-8")

    assert parser.feed(data[:7]) == []
    events = parser.feed(data[7:])

    assert events[0].data == "नमस्ते"


def test_sse_parser_rejects_invalid_retry() -> None:
    parser = SdkSseParser()

    with pytest.raises(StreamingError, match="retry"):
        parser.feed("retry: nope\n\n")


def test_sse_parser_rejects_invalid_utf8() -> None:
    parser = SdkSseParser()

    with pytest.raises(StreamingError, match="UTF-8"):
        parser.feed(b"data: \xff\n\n")


def test_streaming_iterator_yields_deltas_and_stops_on_done() -> None:
    iterator = StreamingResponseIterator(
        [
            _event("hel").encode("utf-8"),
            _event("lo") + "data: [DONE]\n\n",
            _event("ignored"),
        ]
    )

    deltas = list(iterator)

    assert [delta.content for delta in deltas] == ["hel", "lo"]
    assert deltas[0].event_type is StreamEventType.CONTENT_DELTA


def test_streaming_iterator_supports_context_manager() -> None:
    iterator = StreamingResponseIterator([_event("hello"), "data: [DONE]\n\n"])

    with iterator as stream:
        assert next(stream).content == "hello"

    with pytest.raises(StopIteration):
        next(iterator)


def test_streaming_iterator_maps_finish_reason_to_message_stop() -> None:
    iterator = StreamingResponseIterator([_event("", finish_reason="stop"), "data: [DONE]\n\n"])

    delta = next(iterator)

    assert delta.event_type is StreamEventType.MESSAGE_STOP
    assert delta.finish_reason is FinishReason.STOP


def test_streaming_iterator_rejects_malformed_json_payload() -> None:
    iterator = StreamingResponseIterator(["data: {bad json}\n\n"])

    with pytest.raises(StreamingError, match="valid JSON"):
        next(iterator)


def test_streaming_iterator_maps_server_error_event() -> None:
    iterator = StreamingResponseIterator(['event: error\ndata: {"message": "blocked"}\n\n'])

    with pytest.raises(StreamingError, match="blocked"):
        next(iterator)


def test_streaming_iterator_rejects_unexpected_stream_termination() -> None:
    iterator = StreamingResponseIterator([_event("partial").rstrip("\n")])

    with pytest.raises(StreamingError, match="Unexpected end"):
        list(iterator)


def test_streaming_client_serializes_request_and_uses_stream_transport() -> None:
    transport = MockTransport(
        stream_responses=[
            TransportStreamResponse(
                status_code=200,
                chunks=[_event("hello"), "data: [DONE]\n\n"],
            )
        ]
    )
    client = AuthClawClient(api_key="ac_stream_test", transport=transport)

    deltas = list(client.stream_chat_completion(_stream_request()))

    sent = transport.stream_requests[0]
    assert sent.method == "POST"
    assert sent.url == "http://localhost:8000/v1/chat/completions"
    assert sent.headers["Accept"] == "text/event-stream"
    assert sent.headers["Authorization"] == "Bearer ac_stream_test"
    assert sent.json_body is not None
    assert sent.json_body["stream"] is True
    assert deltas[0].content == "hello"


def test_streaming_client_requires_api_key() -> None:
    client = AuthClawClient(transport=MockTransport())

    with pytest.raises(ConfigurationError):
        client.stream_chat_completion(_stream_request())


@pytest.mark.parametrize(
    ("status", "expected"),
    [(429, RateLimitError), (500, ServerError), (504, ServerError)],
)
def test_streaming_client_maps_http_errors(status: int, expected: type[Exception]) -> None:
    transport = MockTransport(
        stream_responses=[
            TransportStreamResponse(
                status_code=status,
                text="stream failed",
            )
        ]
    )
    client = AuthClawClient(api_key="ac_stream_test", transport=transport)

    with pytest.raises(expected, match="stream failed"):
        client.stream_chat_completion(_stream_request())
