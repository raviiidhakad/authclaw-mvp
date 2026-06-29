import pytest

from app.core.engine.sse_parser import ParsedSseEvent, SseField, SseParser, SseParserError


async def _aiter(chunks):
    for chunk in chunks:
        yield chunk


def test_single_event():
    parser = SseParser()

    events = parser.feed("data: hello\n\n")

    assert events == (ParsedSseEvent(data="hello", fields=(SseField("data", "hello"),)),)


def test_multiple_events():
    parser = SseParser()

    events = parser.feed("data: one\n\ndata: two\n\n")

    assert [event.data for event in events] == ["one", "two"]


def test_multiline_data_preserves_semantics():
    parser = SseParser()

    events = parser.feed("data: hello\ndata: world\n\n")

    assert events[0].data == "hello\nworld"


def test_event_id_and_retry_fields():
    parser = SseParser()

    events = parser.feed("event: message\nid: 42\nretry: 1500\ndata: ok\n\n")

    event = events[0]
    assert event.event == "message"
    assert event.event_id == "42"
    assert event.retry_ms == 1500
    assert event.data == "ok"


def test_comments_are_preserved():
    parser = SseParser()

    events = parser.feed(": first\n: second\n\n")

    assert events[0].comment == "first\nsecond"
    assert events[0].fields == (SseField("comment", "first"), SseField("comment", "second"))


def test_empty_lines_without_event_do_not_emit():
    parser = SseParser()

    assert parser.feed("\n\n") == ()


def test_empty_data_field_emits_empty_data():
    parser = SseParser()

    events = parser.feed("data:\n\n")

    assert events[0].data == ""


def test_done_sentinel_is_plain_data_not_interpreted():
    parser = SseParser()

    events = parser.feed("data: [DONE]\n\n")

    assert events[0].data == "[DONE]"


def test_unknown_fields_are_preserved_in_order():
    parser = SseParser()

    events = parser.feed("foo: a\ndata: b\nbar: c\n\n")

    event = events[0]
    assert event.unknown_fields == (SseField("foo", "a"), SseField("bar", "c"))
    assert event.fields == (SseField("foo", "a"), SseField("data", "b"), SseField("bar", "c"))


@pytest.mark.asyncio
async def test_incremental_parse_async_iterable():
    parser = SseParser()

    events = [event async for event in parser.parse(_aiter(["data: he", "llo\n\n"]))]

    assert [event.data for event in events] == ["hello"]


def test_partial_line_across_chunks():
    parser = SseParser()

    assert parser.feed("data: he") == ()
    events = parser.feed("llo\n\n")

    assert events[0].data == "hello"


def test_partial_event_across_chunks():
    parser = SseParser()

    assert parser.feed("event: message\n") == ()
    assert parser.feed("data: hello\n") == ()
    events = parser.feed("\n")

    assert events[0].event == "message"
    assert events[0].data == "hello"


def test_flush_without_pending_state_is_empty():
    parser = SseParser()
    parser.feed("data: complete\n\n")

    assert parser.flush() == ()


def test_flush_rejects_truncated_final_line():
    parser = SseParser()
    parser.feed("data: incomplete")

    with pytest.raises(SseParserError) as exc:
        parser.flush()

    assert exc.value.reason == "truncated_final_event"


def test_flush_rejects_pending_event_without_blank_terminator():
    parser = SseParser()
    parser.feed("data: incomplete\n")

    with pytest.raises(SseParserError) as exc:
        parser.flush()

    assert exc.value.reason == "truncated_final_event"


def test_reset_clears_partial_state():
    parser = SseParser()
    parser.feed("data: partial")
    parser.reset()

    events = parser.feed("data: fresh\n\n")

    assert events[0].data == "fresh"


def test_malformed_field_line_raises_controlled_error_and_clears_state():
    parser = SseParser()

    with pytest.raises(SseParserError) as exc:
        parser.feed("bad field: value\n")

    assert exc.value.reason == "malformed_field"
    assert parser.feed("data: ok\n\n")[0].data == "ok"


def test_invalid_retry_raises_controlled_error():
    parser = SseParser()

    with pytest.raises(SseParserError) as exc:
        parser.feed("retry: soon\n")

    assert exc.value.reason == "invalid_retry"


def test_oversized_event_raises_controlled_error():
    parser = SseParser(max_event_chars=8)

    with pytest.raises(SseParserError) as exc:
        parser.feed("data: too-large\n")

    assert exc.value.reason == "event_too_large"


def test_deterministic_output():
    text = "id: 1\nevent: message\ndata: hello\n\n"

    assert SseParser().feed(text) == SseParser().feed(text)


def test_ordering_preservation():
    parser = SseParser()

    event = parser.feed("id: 1\nfoo: x\ndata: y\nevent: z\n\n")[0]

    assert event.fields == (
        SseField("id", "1"),
        SseField("foo", "x"),
        SseField("data", "y"),
        SseField("event", "z"),
    )


def test_crlf_line_endings_supported():
    parser = SseParser()

    events = parser.feed("data: hello\r\n\r\n")

    assert events[0].data == "hello"

