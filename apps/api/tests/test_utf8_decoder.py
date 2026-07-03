import concurrent.futures

import pytest

from app.core.engine.streaming import Utf8DecoderError, Utf8IncrementalDecoder


def _feed(chunks):
    decoder = Utf8IncrementalDecoder()
    output = []
    for chunk in chunks:
        output.append(decoder.decode(chunk))
    output.append(decoder.flush())
    return "".join(output)


def test_ascii_streaming():
    assert _feed([b"hello", b" ", b"world"]) == "hello world"


def test_two_byte_utf8_split():
    value = "é".encode("utf-8")
    decoder = Utf8IncrementalDecoder()

    assert decoder.decode(value[:1]) == ""
    assert decoder.decode(value[1:]) == "é"
    assert decoder.flush() == ""


def test_three_byte_utf8_split():
    value = "€".encode("utf-8")
    decoder = Utf8IncrementalDecoder()

    assert decoder.decode(value[:1]) == ""
    assert decoder.decode(value[1:2]) == ""
    assert decoder.decode(value[2:]) == "€"


def test_four_byte_utf8_split():
    value = "𐍈".encode("utf-8")
    decoder = Utf8IncrementalDecoder()

    assert decoder.decode(value[:1]) == ""
    assert decoder.decode(value[1:2]) == ""
    assert decoder.decode(value[2:3]) == ""
    assert decoder.decode(value[3:]) == "𐍈"


def test_emoji_split_across_chunks():
    assert _feed([b"status ", "🔐".encode("utf-8")[:2], "🔐".encode("utf-8")[2:]]) == "status 🔐"


def test_japanese_split():
    text = "セキュリティ"
    chunks = [text.encode("utf-8")[i:i + 2] for i in range(0, len(text.encode("utf-8")), 2)]
    assert _feed(chunks) == text


def test_chinese_split():
    text = "安全网关"
    chunks = [text.encode("utf-8")[i:i + 1] for i in range(len(text.encode("utf-8")))]
    assert _feed(chunks) == text


def test_mixed_ascii_and_unicode():
    text = "AuthClaw protects ईमेल and phone 🔒"
    data = text.encode("utf-8")
    chunks = [data[:5], data[5:11], data[11:18], data[18:23], data[23:]]
    assert _feed(chunks) == text


def test_incremental_decoding_multiple_sequential_chunks():
    decoder = Utf8IncrementalDecoder()

    assert decoder.decode(b"Auth") == "Auth"
    assert decoder.decode(" क्ल".encode("utf-8")) == " क्ल"
    assert decoder.decode("aw".encode("utf-8")) == "aw"
    assert decoder.flush() == ""


def test_large_streamed_payload():
    text = ("safe text Δ डेटा 🔐 " * 5000).strip()
    data = text.encode("utf-8")
    chunks = [data[i:i + 17] for i in range(0, len(data), 17)]

    assert _feed(chunks) == text


def test_incomplete_eof_raises_controlled_error():
    decoder = Utf8IncrementalDecoder()
    decoder.decode("🔐".encode("utf-8")[:2])

    with pytest.raises(Utf8DecoderError) as exc:
        decoder.flush()

    assert exc.value.reason == "unexpected_eof"
    assert "🔐" not in str(exc.value)


def test_invalid_continuation_byte_raises_controlled_error():
    decoder = Utf8IncrementalDecoder()

    with pytest.raises(Utf8DecoderError) as exc:
        decoder.decode(b"\xe2\x28\xa1")

    assert exc.value.reason == "invalid_continuation_byte"


def test_overlong_encoding_raises_controlled_error():
    decoder = Utf8IncrementalDecoder()

    with pytest.raises(Utf8DecoderError):
        decoder.decode(b"\xc0\xaf")


def test_illegal_utf8_start_byte_raises_controlled_error():
    decoder = Utf8IncrementalDecoder()

    with pytest.raises(Utf8DecoderError) as exc:
        decoder.decode(b"\x80")

    assert exc.value.reason in {"invalid_start_byte", "invalid_continuation_byte"}


def test_reset_clears_buffered_state():
    decoder = Utf8IncrementalDecoder()
    decoder.decode("€".encode("utf-8")[:1])
    decoder.reset()

    assert decoder.decode(b"A") == "A"
    assert decoder.flush() == ""


def test_flush_returns_completed_buffer_and_repeated_flush_is_empty():
    decoder = Utf8IncrementalDecoder()
    decoder.decode("é".encode("utf-8")[:1])

    assert decoder.decode("é".encode("utf-8")[1:]) == "é"
    assert decoder.flush() == ""
    assert decoder.flush() == ""


def test_deterministic_output():
    chunks = [b"A", "安全".encode("utf-8")[:2], "安全".encode("utf-8")[2:], b"Z"]

    assert _feed(chunks) == _feed(chunks)


def test_independent_instances_are_safe_for_parallel_usage():
    payloads = [
        "tenant one 🔐".encode("utf-8"),
        "tenant two 安全".encode("utf-8"),
        "tenant three ईमेल".encode("utf-8"),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda data: _feed([data[:2], data[2:]]), payloads))

    assert results == ["tenant one 🔐", "tenant two 安全", "tenant three ईमेल"]


def test_same_instance_serialized_by_lock_for_threaded_decodes():
    decoder = Utf8IncrementalDecoder()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(decoder.decode, [b"Auth", b"Claw"]))

    assert "".join(results) in {"AuthClaw", "ClawAuth"}
    assert decoder.flush() == ""

