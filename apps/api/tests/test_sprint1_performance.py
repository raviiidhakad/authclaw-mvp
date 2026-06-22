"""
Sprint 1 — Performance Benchmark Matrix
----------------------------------------
Measures latency impact of each security pipeline component on
the synchronous gateway path. Target: P99 overhead ≤ 50ms.

Benchmark scenarios:
  1. Baseline        — gateway with FF_SECURITY_PIPELINE=False
  2. PII only        — scan only, no policy evaluation
  3. PII + Policy    — scan + policy evaluation + Redis cache
  4. PII + Policy + Streaming — full pipeline including buffer

Usage (requires running environment):
  docker exec authclawproject-api-1 python -m pytest tests/test_sprint1_performance.py -v -s

WARNING: This test file requires:
  - Presidio installed and en_core_web_sm loaded (Docker rebuild)
  - Redis running (authclawproject-redis-1)
  - FF_SECURITY_PIPELINE=True in .env

All latency measurements are recorded to stdout.
"""
import asyncio
import time
import pytest
import statistics
from typing import List


ITERATIONS = 50  # Number of runs per scenario
WARMUP_RUNS = 5   # Warm-up runs to stabilize JIT / pool workers

# Sample text inputs for benchmark
TEXT_CLEAN = "What is the capital of France? Tell me about the Eiffel Tower and Paris history."
TEXT_WITH_PII = "My email is john.doe@acme.com and my phone is +1-555-123-4567. Please help."
TEXT_WITH_PHI = "Patient MRN: A1234567, NPI: 1234567890, DOB: 1985-03-12. Diagnosis pending."
TEXT_WITH_PHI_AND_PII = (
    "Patient MRN: B9876543. Contact: sarah.jones@hospital.com, +1-555-987-6543. "
    "Insurance ID: PLAN12345. SSN: 123-45-6789."
)


def _pct(values: List[float], pct: int) -> float:
    """Return the Nth percentile of a list of values (in ms)."""
    sorted_vals = sorted(values)
    idx = int(len(sorted_vals) * pct / 100)
    return sorted_vals[min(idx, len(sorted_vals) - 1)] * 1000  # to ms


def _stats(label: str, times: List[float]):
    """Print latency stats for a benchmark scenario."""
    p50 = _pct(times, 50)
    p95 = _pct(times, 95)
    p99 = _pct(times, 99)
    mean = statistics.mean(times) * 1000
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  Iterations: {len(times)}  |  Mean: {mean:.1f}ms")
    print(f"  P50: {p50:.1f}ms  |  P95: {p95:.1f}ms  |  P99: {p99:.1f}ms")
    sprint1_target = 50
    status = "✅ PASS" if p99 <= sprint1_target else "❌ FAIL"
    print(f"  Target P99 ≤ {sprint1_target}ms: {status}")
    print(f"{'='*60}")
    return {"label": label, "mean_ms": mean, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99}


@pytest.mark.skipif(
    True,  # Set to False when running manually with full environment
    reason="Performance benchmarks require Docker rebuild with Presidio installed. Run manually."
)
class TestPerformanceBenchmarks:
    """
    Sprint 1 Performance Benchmark Suite.

    These tests are SKIPPED by default — they require the full Docker environment
    with Presidio installed. To run manually:
      1. Remove the @pytest.mark.skipif decorator
      2. Set FF_SECURITY_PIPELINE=True in .env
      3. docker compose up --build
      4. docker exec authclawproject-api-1 python -m pytest tests/test_sprint1_performance.py -v -s
    """

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    async def _bench_presidio_scan(self, text: str) -> float:
        """Time a single Presidio scan and return elapsed seconds."""
        from app.core.detection.presidio_engine import presidio_engine
        start = time.monotonic()
        await presidio_engine.scan(text)
        return time.monotonic() - start

    async def _bench_policy_eval(self, text: str) -> float:
        """Time Presidio scan + embedded policy evaluation."""
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.policy.evaluator import evaluator as policy_evaluator

        compiled_policy = {
            "entity_actions": {"EMAIL_ADDRESS": "MASK", "PHONE_NUMBER": "MASK", "US_SSN": "BLOCK"},
            "classification_overrides": {},
            "keyword_blocklist": ["confidential"],
        }

        start = time.monotonic()
        scan_result = await presidio_engine.scan(text)
        policy_evaluator.evaluate(
            detections=scan_result.detections,
            text=text,
            compiled_policy=compiled_policy,
        )
        return time.monotonic() - start

    def test_scenario_1_baseline(self):
        """Scenario 1: Measure baseline — classification layer only (no Presidio)."""
        from app.core.detection.classification import classifier

        # Warm up
        for _ in range(WARMUP_RUNS):
            classifier.classify("EMAIL_ADDRESS")

        times = []
        for _ in range(ITERATIONS):
            start = time.monotonic()
            classifier.classify("EMAIL_ADDRESS")
            times.append(time.monotonic() - start)

        result = _stats("Scenario 1: Baseline (Classification Only)", times)
        assert result["p99_ms"] < 1.0, "Classification baseline must be <1ms P99"

    def test_scenario_2_presidio_scan_clean_text(self):
        """Scenario 2: Presidio scan on clean text (no detections expected)."""
        async def run():
            from app.core.detection.presidio_engine import presidio_engine
            # Warm up
            for _ in range(WARMUP_RUNS):
                await presidio_engine.scan(TEXT_CLEAN)

            times = []
            for _ in range(ITERATIONS):
                t = await self._bench_presidio_scan(TEXT_CLEAN)
                times.append(t)
            return times

        times = self._run(run())
        result = _stats("Scenario 2: Presidio Scan — Clean Text", times)
        assert result["p99_ms"] <= 50, "P99 must be ≤50ms"

    def test_scenario_3_presidio_scan_pii_text(self):
        """Scenario 3: Presidio scan on text with email + phone (PII only)."""
        async def run():
            from app.core.detection.presidio_engine import presidio_engine
            for _ in range(WARMUP_RUNS):
                await presidio_engine.scan(TEXT_WITH_PII)

            times = []
            for _ in range(ITERATIONS):
                t = await self._bench_presidio_scan(TEXT_WITH_PII)
                times.append(t)
            return times

        times = self._run(run())
        result = _stats("Scenario 3: Presidio Scan — PII Only (email+phone)", times)
        assert result["p99_ms"] <= 50, "P99 must be ≤50ms"

    def test_scenario_4_presidio_scan_phi_text(self):
        """Scenario 4: Presidio scan on text with PHI (MRN, NPI, DOB)."""
        async def run():
            from app.core.detection.presidio_engine import presidio_engine
            for _ in range(WARMUP_RUNS):
                await presidio_engine.scan(TEXT_WITH_PHI)

            times = []
            for _ in range(ITERATIONS):
                t = await self._bench_presidio_scan(TEXT_WITH_PHI)
                times.append(t)
            return times

        times = self._run(run())
        result = _stats("Scenario 4: Presidio Scan — PHI (MRN+NPI+DOB)", times)
        assert result["p99_ms"] <= 50, "P99 must be ≤50ms"

    def test_scenario_5_pii_plus_policy(self):
        """Scenario 5: Full pipeline — Presidio scan + embedded policy evaluation."""
        async def run():
            for _ in range(WARMUP_RUNS):
                await self._bench_policy_eval(TEXT_WITH_PHI_AND_PII)

            times = []
            for _ in range(ITERATIONS):
                t = await self._bench_policy_eval(TEXT_WITH_PHI_AND_PII)
                times.append(t)
            return times

        times = self._run(run())
        result = _stats("Scenario 5: PII + Policy Evaluation (Full Pipeline)", times)
        assert result["p99_ms"] <= 50, "P99 must be ≤50ms"

    def test_scenario_6_classification_only(self):
        """Scenario 6: Classification layer batch — 20 entity types."""
        from app.core.detection.classification import classifier

        entity_types = [
            "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
            "PHI_MRN", "PHI_NPI", "PHI_INSURANCE_ID", "PERSON",
            "LOCATION", "DATE_TIME", "IP_ADDRESS", "IBAN_CODE",
            "US_PASSPORT", "ADDRESS", "AGE", "NRP",
            "BANK_ACCOUNT", "US_DRIVER_LICENSE", "UK_NHS", "MEDICAL_RECORD",
        ]

        times = []
        for _ in range(ITERATIONS):
            start = time.monotonic()
            classifier.classify_many(entity_types)
            times.append(time.monotonic() - start)

        result = _stats("Scenario 6: Classification — 20 Entity Types Batch", times)
        assert result["p99_ms"] < 1.0, "Classification batch P99 must be <1ms"
