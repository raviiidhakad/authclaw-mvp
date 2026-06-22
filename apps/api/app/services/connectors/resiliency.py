"""
AuthClaw Sprint 2 — Connector Resiliency Primitives
-----------------------------------------------------
Provides retry-with-exponential-backoff and an in-process circuit breaker
for all cloud connector I/O operations.

Design principles:
  • `async_retry` — wraps any async callable; handles transient network errors
    and provider rate limits with exponential backoff + full jitter.
  • `CircuitBreaker` — per-provider state machine preventing cascading failures
    when a provider is repeatedly unavailable. States: CLOSED → OPEN → HALF_OPEN.
  • `with_scan_timeout` — enforces MAX_SCAN_DURATION; cancels runaway scans.
  • All utilities are async-native and do not block the event loop.

Circuit Breaker state machine:
  CLOSED      — normal operation; failures accumulate toward threshold.
  OPEN        — provider is failing; calls are rejected immediately for
                `recovery_timeout` seconds. Integration status → ERROR.
  HALF_OPEN   — one probe call is allowed to test recovery. If it succeeds,
                the breaker returns to CLOSED. If it fails, returns to OPEN.

Rate limit handling:
  `async_retry` inspects `RateLimitError` exceptions for a `retry_after`
  attribute (seconds), sleeping exactly that long before retrying.
  Connectors raise `RateLimitError` when they detect HTTP 429 or provider
  throttling exceptions (e.g. AWS ThrottlingException).
"""
from __future__ import annotations

import asyncio
import logging
import time
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Optional, TypeVar

from app.core.config import settings

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ── Custom exceptions ──────────────────────────────────────────────────────────

class RateLimitError(Exception):
    """
    Raised by a connector when the provider returns HTTP 429 or an equivalent
    throttling error (e.g. AWS ThrottlingException).

    Attributes:
        retry_after: Seconds to wait before the next attempt.
                     Extracted from the provider response header or exception.
                     Defaults to 60 if not provided.
    """
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class CircuitOpenError(Exception):
    """
    Raised when a call is rejected because the circuit breaker is OPEN.
    The ConnectorWorker catches this and marks the integration as ERROR
    without recording a new failure (the circuit is already open).
    """


# ── Retry with exponential backoff + full jitter ───────────────────────────────

@dataclass
class RetryConfig:
    """
    Configuration for async_retry.

    Defaults represent reasonable values for cloud API calls:
      - 3 retries covers most transient network blips.
      - 1.0s base delay with 2x multiplier caps at 60s (max_delay).
      - Full jitter avoids thundering-herd on simultaneous connector syncs.
    """
    max_retries: int = 3
    base_delay: float = 1.0       # seconds
    multiplier: float = 2.0
    max_delay: float = 60.0       # seconds — cap before jitter
    jitter: bool = True           # Full jitter: sleep = random(0, computed_delay)


async def async_retry(
    fn: Callable[..., Awaitable[T]],
    *args: Any,
    config: RetryConfig | None = None,
    reraise_types: tuple[type[Exception], ...] = (),
    **kwargs: Any,
) -> T:
    """
    Execute an async callable with exponential backoff retry.

    Args:
        fn:             Async callable to invoke.
        *args:          Positional args forwarded to fn.
        config:         RetryConfig instance (uses defaults if None).
        reraise_types:  Exception types that are re-raised immediately
                        without retrying (e.g. PermissionError, ValueError).
        **kwargs:       Keyword args forwarded to fn.

    Returns:
        The return value of fn on success.

    Raises:
        The last exception encountered after all retries are exhausted.
        RateLimitError: Respected by sleeping for retry_after seconds.
        Any exception in reraise_types: Raised immediately without retry.
    """
    cfg = config or RetryConfig()
    last_exc: Exception | None = None
    delay = cfg.base_delay

    for attempt in range(1, cfg.max_retries + 2):  # +2: 1 initial + N retries
        try:
            return await fn(*args, **kwargs)
        except tuple(reraise_types) as exc:  # type: ignore[misc]
            # Structural / auth failures are not transient — do not retry
            raise
        except RateLimitError as exc:
            last_exc = exc
            wait = exc.retry_after
            logger.warning(
                "Rate limit hit (attempt %d/%d). Sleeping %ds before retry.",
                attempt, cfg.max_retries + 1, wait,
            )
            await asyncio.sleep(wait)
            # Do not apply exponential delay on top of provider-specified wait
            continue
        except Exception as exc:
            last_exc = exc
            if attempt > cfg.max_retries:
                # Retries exhausted
                break
            sleep_time = min(delay, cfg.max_delay)
            if cfg.jitter:
                sleep_time = random.uniform(0, sleep_time)
            logger.warning(
                "Connector call failed (attempt %d/%d): %s. "
                "Retrying in %.2fs.",
                attempt, cfg.max_retries + 1, exc, sleep_time,
            )
            await asyncio.sleep(sleep_time)
            delay *= cfg.multiplier

    raise last_exc  # type: ignore[misc]


# ── Circuit Breaker ────────────────────────────────────────────────────────────

class CircuitState(str, Enum):
    CLOSED    = "CLOSED"     # Normal operation
    OPEN      = "OPEN"       # Failing; calls rejected
    HALF_OPEN = "HALF_OPEN"  # Probe call allowed


class CircuitBreaker:
    """
    Per-provider in-process circuit breaker.

    State transitions:
      CLOSED → OPEN:       failure_count reaches failure_threshold within a scan.
      OPEN   → HALF_OPEN:  recovery_timeout seconds have elapsed.
      HALF_OPEN → CLOSED:  the probe call succeeds.
      HALF_OPEN → OPEN:    the probe call fails; recovery_timeout resets.

    Thread safety:
      Uses asyncio.Lock — safe for concurrent async tasks within the
      dedicated ConnectorWorker container (single event loop).

    Args:
        name:              Human-readable name for logging (e.g. "aws_security_hub").
        failure_threshold: Number of consecutive failures before opening.
        recovery_timeout:  Seconds the breaker stays OPEN before allowing a probe.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 300,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    def _should_attempt_reset(self) -> bool:
        """Return True if recovery_timeout has elapsed since the circuit opened."""
        return time.monotonic() - self._last_failure_time >= self.recovery_timeout

    async def call(self, fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        """
        Execute fn through the circuit breaker.

        Raises:
            CircuitOpenError: If the circuit is OPEN and recovery timeout has not elapsed.
        """
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    logger.info(
                        "CircuitBreaker '%s': transitioning OPEN → HALF_OPEN for probe.",
                        self.name,
                    )
                    self._state = CircuitState.HALF_OPEN
                else:
                    raise CircuitOpenError(
                        f"Circuit breaker '{self.name}' is OPEN. "
                        f"Next probe allowed in "
                        f"{self.recovery_timeout - (time.monotonic() - self._last_failure_time):.0f}s."
                    )

        # Execute outside the lock so other coroutines can check state
        try:
            result = await fn(*args, **kwargs)
            await self._on_success()
            return result
        except CircuitOpenError:
            raise
        except Exception as exc:
            await self._on_failure(exc)
            raise

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info(
                    "CircuitBreaker '%s': probe succeeded — transitioning HALF_OPEN → CLOSED.",
                    self.name,
                )
            self._state = CircuitState.CLOSED
            self._failure_count = 0

    async def _on_failure(self, exc: Exception) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.HALF_OPEN:
                logger.warning(
                    "CircuitBreaker '%s': probe FAILED (%s) — returning to OPEN.",
                    self.name, exc,
                )
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.failure_threshold:
                logger.error(
                    "CircuitBreaker '%s': failure threshold (%d) reached — "
                    "transitioning CLOSED → OPEN.",
                    self.name, self.failure_threshold,
                )
                self._state = CircuitState.OPEN

    def status_dict(self) -> dict:
        """Return a JSON-serializable snapshot for the /health/connectors endpoint."""
        return {
            "state": self._state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_seconds": self.recovery_timeout,
        }

    async def reset(self) -> None:
        """Manually reset the breaker to CLOSED. Used in tests and admin tooling."""
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = 0.0


# ── Scan timeout guard ─────────────────────────────────────────────────────────

async def with_scan_timeout(coro: Awaitable[T]) -> T:
    """
    Execute a coroutine with a hard timeout of settings.MAX_SCAN_DURATION seconds.

    Raises:
        asyncio.TimeoutError: If the scan exceeds MAX_SCAN_DURATION.
                              The ConnectorWorker catches this and transitions
                              the integration to ERROR status.
    """
    timeout = settings.MAX_SCAN_DURATION
    try:
        return await asyncio.wait_for(coro, timeout=float(timeout))
    except asyncio.TimeoutError:
        logger.error(
            "Scan exceeded MAX_SCAN_DURATION (%ds) and was cancelled.",
            timeout,
        )
        raise
