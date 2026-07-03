import pytest

from app.core.engine.streaming import ParsedSseEvent, StreamingContext, StreamingDirection
from app.core.engine.streaming_state_machine import (
    StreamingRedactionStateMachine,
    StreamingState,
    StreamingStateMachineError,
)


def _event(text: str | None) -> ParsedSseEvent:
    return ParsedSseEvent(data=text)


def test_initial_state():
    machine = StreamingRedactionStateMachine()

    assert machine.state == StreamingState.INITIAL
    assert machine.snapshot().buffered_chars == 0


def test_append_moves_to_buffering():
    machine = StreamingRedactionStateMachine(look_behind_chars=4, look_ahead_chars=4, max_window_chars=64)

    machine.append(_event("hello"))

    assert machine.state == StreamingState.READY_TO_EMIT
    assert machine.snapshot().buffered_chars == 5


def test_emit_safe_holds_look_behind_and_look_ahead():
    machine = StreamingRedactionStateMachine(look_behind_chars=4, look_ahead_chars=6, max_window_chars=64)
    machine.append(_event("alpha beta gamma "))

    windows = machine.emit_safe()

    assert windows[0].safe_prefix == "alpha beta "
    assert windows[0].retained_suffix == "gamma "


def test_chunk_boundary_word_is_not_partially_emitted():
    machine = StreamingRedactionStateMachine(look_behind_chars=3, look_ahead_chars=3, max_window_chars=64)
    machine.append(_event("email per"))
    first = machine.emit_safe()
    assert first[0].safe_prefix == "email "
    assert first[0].retained_suffix == "per"

    machine.append(_event("son@example.test done "))
    windows = machine.emit_safe()

    assert windows
    assert windows[0].safe_prefix == "person@example.test "
    assert windows[0].retained_suffix == "done "


def test_entity_boundary_retains_suffix_until_flush():
    machine = StreamingRedactionStateMachine(look_behind_chars=20, look_ahead_chars=20, max_window_chars=128)
    machine.append(_event("Contact person@example."))
    assert machine.emit_safe() == ()

    machine.append(_event("test after boundary "))
    windows = machine.emit_safe()

    assert windows[0].safe_prefix == "Contact "
    assert "person@example.test" in windows[0].retained_suffix


def test_regex_like_boundary_is_held_when_no_boundary_exists():
    machine = StreamingRedactionStateMachine(look_behind_chars=5, look_ahead_chars=5, max_window_chars=128)
    machine.append(_event("token=abc1234567890"))

    assert machine.emit_safe() == ()


def test_multiple_emits_preserve_ordering():
    machine = StreamingRedactionStateMachine(look_behind_chars=4, look_ahead_chars=4, max_window_chars=128)
    machine.append(_event("one two three four five six "))

    first = machine.emit_safe()
    second = machine.emit_safe()
    machine.end_of_stream()
    final = machine.flush()

    rendered = "".join(window.text for window in first + second + final)
    assert rendered == "one two three four five six "
    assert [window.sequence for window in first + second + final] == list(range(1, len(first + second + final) + 1))


def test_flush_requires_end_of_stream():
    machine = StreamingRedactionStateMachine()
    machine.append(_event("hello"))

    with pytest.raises(StreamingStateMachineError) as exc:
        machine.flush()

    assert exc.value.reason == "flush_before_end_of_stream"


def test_flush_after_eos_emits_final_window():
    machine = StreamingRedactionStateMachine(look_behind_chars=4, look_ahead_chars=4, max_window_chars=64)
    machine.append(_event("tail"))
    machine.end_of_stream()

    windows = machine.flush()

    assert windows[0].text == "tail"
    assert windows[0].is_final is True
    assert machine.state == StreamingState.COMPLETE


def test_reset_clears_state():
    machine = StreamingRedactionStateMachine()
    machine.append(_event("hello"))
    machine.reset()

    assert machine.state == StreamingState.INITIAL
    assert machine.snapshot().buffered_chars == 0


def test_end_of_stream_empty_completes():
    machine = StreamingRedactionStateMachine()

    machine.end_of_stream()

    assert machine.state == StreamingState.COMPLETE
    assert machine.flush() == ()


def test_append_after_eos_is_illegal():
    machine = StreamingRedactionStateMachine()
    machine.append(_event("hello"))
    machine.end_of_stream()

    with pytest.raises(StreamingStateMachineError) as exc:
        machine.append(_event("late"))

    assert exc.value.reason == "append_after_end_of_stream"


def test_overflow_fails_closed_and_clears_buffer():
    machine = StreamingRedactionStateMachine(look_behind_chars=2, look_ahead_chars=2, max_window_chars=8)

    with pytest.raises(StreamingStateMachineError) as exc:
        machine.append(_event("012345678"))

    assert exc.value.reason == "window_overflow"
    assert machine.state == StreamingState.ERROR
    assert machine.snapshot().buffered_chars == 0


def test_corruption_recovery_with_reset():
    machine = StreamingRedactionStateMachine(look_behind_chars=2, look_ahead_chars=2, max_window_chars=8)
    with pytest.raises(StreamingStateMachineError):
        machine.append(_event("overflow!"))

    machine.reset()
    machine.append(_event("ok "))
    machine.end_of_stream()

    assert machine.flush()[0].text == "ok "


def test_invalid_event_type_fails_closed():
    machine = StreamingRedactionStateMachine()

    with pytest.raises(StreamingStateMachineError) as exc:
        machine.append(object())  # type: ignore[arg-type]

    assert exc.value.reason == "invalid_event"


def test_deterministic_output():
    def run_once():
        machine = StreamingRedactionStateMachine(look_behind_chars=4, look_ahead_chars=4, max_window_chars=128)
        machine.append(_event("alpha beta gamma "))
        emitted = machine.emit_safe()
        machine.end_of_stream()
        return emitted + machine.flush()

    assert run_once() == run_once()


def test_large_stream_memory_bounds():
    machine = StreamingRedactionStateMachine(look_behind_chars=16, look_ahead_chars=16, max_window_chars=256)
    emitted = []

    for _ in range(100):
        machine.append(_event("word "))
        emitted.extend(machine.emit_safe())
        assert machine.snapshot().buffered_chars <= 256

    machine.end_of_stream()
    emitted.extend(machine.flush())

    assert "".join(window.text for window in emitted) == "word " * 100


@pytest.mark.asyncio
async def test_process_text_contract_compatibility():
    machine = StreamingRedactionStateMachine(look_behind_chars=4, look_ahead_chars=4, max_window_chars=64)
    context = StreamingContext(
        tenant_id="tenant-1",
        stream_id="stream-1",
        direction=StreamingDirection.OUTBOUND,
    )

    windows = [window async for window in machine.process_text(context, "hello world ", is_final=True)]

    assert "".join(window.text for window in windows) == "hello world "
    assert windows[-1].is_final is True
