"""Retry policy support for the AuthClaw Python SDK."""

from __future__ import annotations

from dataclasses import dataclass

from .client_contracts import RetryConfigurationContract
from .exceptions import ConnectionError, TimeoutError
from .types import RetryBackoff


@dataclass(frozen=True, slots=True)
class RetryContext:
    attempt_index: int
    max_attempts: int
    method: str
    url: str
    status_code: int | None = None
    exception: BaseException | None = None
    stream_started: bool = False


@dataclass(frozen=True, slots=True)
class RetryDecision:
    should_retry: bool
    delay_seconds: float
    reason: str
    next_attempt_index: int


class RetryStrategy:
    """Backoff calculator for retry attempts."""

    def __init__(
        self,
        backoff: RetryBackoff,
        *,
        initial_delay_seconds: float,
        max_delay_seconds: float,
        jitter_ratio: float = 0.0,
    ) -> None:
        self.backoff = backoff
        self.initial_delay_seconds = initial_delay_seconds
        self.max_delay_seconds = max_delay_seconds
        self.jitter_ratio = jitter_ratio

    def delay_for_attempt(self, attempt_index: int) -> float:
        if self.backoff is RetryBackoff.NONE:
            delay = 0.0
        elif self.backoff is RetryBackoff.FIXED:
            delay = self.initial_delay_seconds
        else:
            delay = self.initial_delay_seconds * (2 ** max(attempt_index - 1, 0))
        delay = min(delay, self.max_delay_seconds)
        return _apply_deterministic_jitter(delay, attempt_index, self.jitter_ratio)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    retryable_status_codes: tuple[int, ...] = (408, 409, 425, 429, 500, 502, 503, 504)
    retryable_exception_types: tuple[type[BaseException], ...] = (ConnectionError, TimeoutError)
    strategy: RetryStrategy | None = None

    @classmethod
    def from_contract(
        cls,
        contract: RetryConfigurationContract,
        *,
        jitter_ratio: float = 0.0,
    ) -> "RetryPolicy":
        strategy = RetryStrategy(
            contract.backoff,
            initial_delay_seconds=contract.initial_delay_seconds,
            max_delay_seconds=contract.max_delay_seconds,
            jitter_ratio=jitter_ratio,
        )
        return cls(
            max_attempts=contract.max_attempts,
            retryable_status_codes=contract.retry_on_status_codes,
            strategy=strategy,
        )

    def decide(self, context: RetryContext) -> RetryDecision:
        if context.stream_started:
            return RetryDecision(False, 0.0, "stream_already_started", context.attempt_index)
        if context.attempt_index >= min(self.max_attempts, context.max_attempts):
            return RetryDecision(False, 0.0, "max_attempts_reached", context.attempt_index)

        reason = self._retry_reason(context)
        if reason is None:
            return RetryDecision(False, 0.0, "not_retryable", context.attempt_index)

        delay = self.strategy.delay_for_attempt(context.attempt_index) if self.strategy else 0.0
        return RetryDecision(True, delay, reason, context.attempt_index + 1)

    def _retry_reason(self, context: RetryContext) -> str | None:
        if context.status_code in self.retryable_status_codes:
            return f"status_{context.status_code}"
        if context.exception is not None and isinstance(
            context.exception,
            self.retryable_exception_types,
        ):
            return context.exception.__class__.__name__
        return None


def _apply_deterministic_jitter(delay: float, attempt_index: int, jitter_ratio: float) -> float:
    if delay <= 0 or jitter_ratio <= 0:
        return delay
    bounded_ratio = min(max(jitter_ratio, 0.0), 1.0)
    pseudo_random_fraction = ((attempt_index * 1103515245 + 12345) % 1000) / 1000
    multiplier = 1 - bounded_ratio + (pseudo_random_fraction * bounded_ratio * 2)
    return max(0.0, delay * multiplier)
