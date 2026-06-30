"""
E4.3 high-resolution timing utilities.

This module provides generic timing primitives for future benchmark harnesses.
It does not import or execute AuthClaw runtime paths.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from types import TracebackType


@dataclass(frozen=True)
class TimerReading:
    """One elapsed-time measurement."""

    elapsed_ns: int

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1_000_000


class HighResolutionTimer:
    """Monotonic high-resolution timer with explicit start/stop semantics."""

    def __init__(self) -> None:
        self._started_ns: int | None = None
        self._ended_ns: int | None = None

    @property
    def running(self) -> bool:
        return self._started_ns is not None and self._ended_ns is None

    def start(self) -> "HighResolutionTimer":
        self._started_ns = time.perf_counter_ns()
        self._ended_ns = None
        return self

    def stop(self) -> TimerReading:
        if self._started_ns is None:
            raise RuntimeError("timer_not_started")
        self._ended_ns = time.perf_counter_ns()
        elapsed = max(0, self._ended_ns - self._started_ns)
        return TimerReading(elapsed_ns=elapsed)

    def reset(self) -> None:
        self._started_ns = None
        self._ended_ns = None

    def __enter__(self) -> "HighResolutionTimer":
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.running:
            self.stop()


def measure_elapsed_ms(callable_) -> float:
    """Measure a zero-argument callable and return elapsed milliseconds."""

    timer = HighResolutionTimer().start()
    callable_()
    return timer.stop().elapsed_ms

