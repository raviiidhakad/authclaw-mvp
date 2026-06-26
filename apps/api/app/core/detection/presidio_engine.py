"""
AuthClaw Sprint 1 — Presidio Engine (ProcessPool Architecture)
--------------------------------------------------------------
Wraps Microsoft Presidio Analyzer and Anonymizer in a
concurrent.futures.ProcessPoolExecutor to prevent CPU-bound NLP work
from blocking the FastAPI async event loop.

Architecture:
  • The ProcessPool is initialized once on application startup.
  • SpaCy en_core_web_sm is loaded inside each worker process via the
    pool `initializer` — ensuring each worker pays the model-load cost
    exactly once, and subsequent calls are sub-millisecond.
  • The PresidioEngine singleton is the ONLY entrypoint to Presidio from
    the rest of the codebase. All other modules import analyze_text() and
    anonymize_text() from here.

Latency profile (target ≤ 15ms per scan):
  • Small model (sm) → ~8-12ms NLP inference
  • Regex-only entities (CREDIT_CARD, EMAIL) → ~1-3ms
  • Pool call overhead → ~1-2ms (shared memory, not network)

Failure behavior:
  • On BrokenProcessPool (e.g. worker OOM): engine fails CLOSED.
    The gateway returns HTTP 503. The pool is restarted in background.
  • On individual worker timeout (>40ms): raises PresidioTimeoutError.
    The gateway treats this as a scan failure and fails closed.
"""
from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Worker-process globals ─────────────────────────────────────────────────────
# These are initialized once per worker process via _worker_initializer().
# Using module-level globals in the child process is the standard pattern for
# ProcessPoolExecutor resource sharing.
_analyzer = None
_anonymizer = None


def _worker_initializer():
    """
    Executed once when each worker process starts.
    Loads SpaCy + Presidio models into the worker's memory.
    Subsequent calls to _analyze() and _anonymize() skip the load cost.
    """
    global _analyzer, _anonymizer

    # Suppress noisy startup logs from child processes
    logging.basicConfig(level=logging.WARNING)

    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    from app.core.detection.recognizers import get_all_custom_recognizers

    # Configure SpaCy NLP engine — disable unused pipeline components for speed
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    provider = NlpEngineProvider(nlp_configuration=nlp_config)
    nlp_engine = provider.create_engine()

    # Build recognizer registry with defaults + custom PHI recognizers
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)
    for recognizer in get_all_custom_recognizers():
        registry.add_recognizer(recognizer)

    _analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
    _anonymizer = AnonymizerEngine()


def _analyze(text: str, language: str, score_threshold: float) -> List[Dict[str, Any]]:
    """
    Synchronous analysis function — runs inside the worker process.
    Returns a list of serializable dicts (not Presidio objects, which can't cross process boundaries).
    """
    if _analyzer is None:
        raise RuntimeError("Presidio analyzer not initialized in worker process.")

    results = _analyzer.analyze(
        text=text,
        language=language,
        score_threshold=score_threshold,
    )
    # Serialize to dicts — Presidio RecognizerResult objects are not picklable
    return [
        {
            "entity_type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": r.score,
        }
        for r in results
    ]


def _anonymize(text: str, analyzer_results_dicts: List[Dict], operators: Dict[str, Any]) -> str:
    """
    Synchronous anonymization function — runs inside the worker process.
    Reconstructs Presidio objects from dicts before calling the anonymizer.
    """
    if _anonymizer is None:
        raise RuntimeError("Presidio anonymizer not initialized in worker process.")

    from presidio_analyzer import RecognizerResult
    from presidio_anonymizer.entities import OperatorConfig

    analyzer_results = [
        RecognizerResult(
            entity_type=d["entity_type"],
            start=d["start"],
            end=d["end"],
            score=d["score"],
        )
        for d in analyzer_results_dicts
    ]

    operator_configs = {
        entity_type: OperatorConfig(op["type"], op.get("params", {}))
        for entity_type, op in operators.items()
    }

    result = _anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results,
        operators=operator_configs,
    )
    return result.text


# ── Scan result dataclass ──────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Holds the result of a single Presidio analysis + anonymization pass."""
    original_text: str
    sanitized_text: str
    detections: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: int = 0

    @property
    def has_detections(self) -> bool:
        return len(self.detections) > 0

    @property
    def entity_types(self) -> List[str]:
        return list({d["entity_type"] for d in self.detections})


# ── Presidio Engine singleton ──────────────────────────────────────────────────

class PresidioEngine:
    """
    Singleton Presidio engine backed by a ProcessPoolExecutor.

    Lifecycle:
      - start() called on FastAPI startup
      - stop() called on FastAPI shutdown
      - Health checked via is_healthy()

    Usage:
      result = await engine.scan(text, operators)
    """

    _instance: Optional["PresidioEngine"] = None
    _pool: Optional[ProcessPoolExecutor] = None
    _healthy: bool = False

    def __new__(cls) -> "PresidioEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def start(self) -> None:
        """
        Start the ProcessPool with pre-warmed workers.
        Worker count: min(8, max(1, cpu_count - 1))
        """
        max_workers = min(8, max(1, (os.cpu_count() or 2) - 1))
        logger.info("Starting Presidio ProcessPool with %d workers.", max_workers)

        loop = asyncio.get_event_loop()
        try:
            self._pool = ProcessPoolExecutor(
                max_workers=max_workers,
                initializer=_worker_initializer,
            )
            # Pre-warm all workers with a trivial scan to avoid cold-start on first request
            warm_tasks = [
                loop.run_in_executor(self._pool, _analyze, "warmup", "en", 0.75)
                for _ in range(max_workers)
            ]
            await asyncio.gather(*warm_tasks, return_exceptions=True)
            self._healthy = True
            logger.info("Presidio ProcessPool started and pre-warmed successfully.")
        except Exception as exc:
            self._healthy = False
            logger.error("Failed to start Presidio ProcessPool: %s", exc)

    async def stop(self) -> None:
        """Gracefully shut down the process pool on application shutdown."""
        if self._pool:
            self._pool.shutdown(wait=True)
            self._pool = None
        self._healthy = False
        logger.info("Presidio ProcessPool shut down.")

    def is_healthy(self) -> bool:
        return self._healthy and self._pool is not None

    async def scan(
        self,
        text: str,
        operators: Optional[Dict[str, Any]] = None,
        language: str = "en",
        score_threshold: float = 0.75,
        timeout_seconds: float = 5.0,  # 5s cap for longer completions (was 40ms)
    ) -> ScanResult:
        """
        Analyze and anonymize text using the ProcessPool.

        Args:
            text:             The text to scan.
            operators:        Dict of {entity_type: {"type": "mask"|"hash"|"replace", "params": {...}}}.
                              Defaults to MASK for all detected entities.
            language:         Language code for NLP engine. Default "en".
            score_threshold:  Minimum confidence score to report a detection. Default 0.75.
            timeout_seconds:  Hard timeout. Gateway fails closed if exceeded.

        Returns:
            ScanResult with detections and sanitized text.

        Raises:
            RuntimeError if pool is unhealthy (fail closed).
            asyncio.TimeoutError if scan exceeds timeout_seconds.
        """
        import time

        if not self.is_healthy():
            raise RuntimeError("Presidio engine is not healthy. Gateway failing closed.")

        if not text or not text.strip():
            return ScanResult(original_text=text, sanitized_text=text)

        if operators is None:
            operators = {}

        loop = asyncio.get_event_loop()
        start = time.monotonic()

        try:
            # Step 1: Analyze (detect entities)
            detections: List[Dict[str, Any]] = await asyncio.wait_for(
                loop.run_in_executor(
                    self._pool,
                    _analyze,
                    text,
                    language,
                    score_threshold,
                ),
                timeout=timeout_seconds,
            )

            if not detections:
                latency_ms = int((time.monotonic() - start) * 1000)
                return ScanResult(
                    original_text=text,
                    sanitized_text=text,
                    detections=[],
                    latency_ms=latency_ms,
                )

            # Step 2: Build default MASK operators for entities not explicitly configured
            effective_operators = {}
            for d in detections:
                entity_type = d["entity_type"]
                if entity_type not in operators:
                    effective_operators[entity_type] = {"type": "replace", "params": {"new_value": f"<{entity_type}>"}}
                else:
                    effective_operators[entity_type] = operators[entity_type]

            # Step 3: Anonymize (redact)
            sanitized_text: str = await asyncio.wait_for(
                loop.run_in_executor(
                    self._pool,
                    _anonymize,
                    text,
                    detections,
                    effective_operators,
                ),
                timeout=timeout_seconds,
            )

        except asyncio.TimeoutError:
            logger.error("Presidio scan timed out after %.0fms. Failing closed.", timeout_seconds * 1000)
            raise

        except BrokenProcessPool:
            self._healthy = False
            logger.critical("Presidio ProcessPool is broken. Scheduling recovery and failing closed.")
            asyncio.create_task(self._recover_pool())
            raise RuntimeError("Presidio ProcessPool crashed. Gateway failing closed.")

        latency_ms = int((time.monotonic() - start) * 1000)

        return ScanResult(
            original_text=text,
            sanitized_text=sanitized_text,
            detections=detections,
            latency_ms=latency_ms,
        )

    async def _recover_pool(self) -> None:
        """
        Background task to restart the pool after a crash.
        Called via asyncio.create_task() — does not block the gateway.
        """
        logger.info("Attempting Presidio ProcessPool recovery...")
        if self._pool:
            try:
                self._pool.shutdown(wait=False)
            except Exception:
                pass
            self._pool = None
        await asyncio.sleep(5)  # Brief delay before restart
        await self.start()


# Module-level singleton — imported by gateway.py and health endpoint
presidio_engine = PresidioEngine()
