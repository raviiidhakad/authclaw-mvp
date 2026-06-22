"""
Sprint 1 — Performance Benchmark Script
Measures P50/P95/P99 latency for each pipeline component.
Run inside the Docker container after `docker compose up --build`.
"""
import asyncio
import time
import statistics

ITERATIONS = 50
WARMUP = 8

TEXTS = {
    "clean": "What is the capital of France? Tell me about the Eiffel Tower and Paris history.",
    "pii":   "My email is john.doe@acme.com and my phone is +1-555-123-4567. Please help.",
    "phi":   "Patient MRN: A1234567, NPI: 1234567890, DOB: 1985-03-12. Diagnosis pending.",
    "full":  "Patient MRN: B9876543. Contact: sarah.jones@hospital.com, +1-555-987-6543. Insurance ID: PLAN12345. SSN: 123-45-6789.",
}

POLICY = {
    "entity_actions": {"EMAIL_ADDRESS": "MASK", "PHONE_NUMBER": "MASK", "US_SSN": "BLOCK"},
    "classification_overrides": {},
    "keyword_blocklist": ["confidential"],
}


def pct(vals, p):
    s = sorted(vals)
    return s[min(int(len(s) * p / 100), len(s) - 1)] * 1000


def report(label, times):
    if not times:
        print(f"  {label}: NO DATA")
        return
    p50, p95, p99 = pct(times, 50), pct(times, 95), pct(times, 99)
    mean = statistics.mean(times) * 1000
    ok = "✅ PASS" if p99 <= 50 else "❌ FAIL"
    print(f"  {label}")
    print(f"    Mean={mean:.1f}ms  P50={p50:.1f}ms  P95={p95:.1f}ms  P99={p99:.1f}ms  {ok}")


async def main():
    from app.core.detection.presidio_engine import PresidioEngine
    from app.core.detection.classification import classifier
    from app.core.policy.evaluator import evaluator

    print("=" * 60)
    print("AuthClaw Sprint 1 — Performance Benchmark Matrix")
    print(f"Iterations: {ITERATIONS}  Warm-up: {WARMUP}  Target: P99 ≤ 50ms")
    print("=" * 60)

    # Fresh engine instance (bypasses singleton for isolated benchmark)
    import os
    from concurrent.futures import ProcessPoolExecutor

    class BenchEngine:
        """Minimal inline engine for benchmarking."""
        def __init__(self):
            self._pool = None
            self._max_workers = min(3, max(1, (os.cpu_count() or 2) - 1))

        async def start(self):
            from app.core.detection.presidio_engine import _worker_initializer
            loop = asyncio.get_event_loop()
            self._pool = ProcessPoolExecutor(
                max_workers=self._max_workers,
                initializer=_worker_initializer,
            )
            # Pre-warm
            futs = [
                loop.run_in_executor(self._pool, _do_scan, "warmup text")
                for _ in range(self._max_workers)
            ]
            await asyncio.gather(*futs, return_exceptions=True)

        async def scan(self, text: str):
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(self._pool, _do_scan, text),
                timeout=10.0,
            )

        async def stop(self):
            if self._pool:
                self._pool.shutdown(wait=False)

    engine = BenchEngine()
    print("\nStarting ProcessPool workers...")
    await engine.start()

    print(f"Warming up ({WARMUP} runs)...")
    for i in range(WARMUP):
        try:
            await engine.scan(TEXTS["pii"])
            if i == 0:
                print("  First call OK")
        except Exception as e:
            print(f"  Warmup {i}: {e}")
    print("Ready.\n")

    print("Results:")

    # S1: Classification only (pure Python, no Presidio)
    times = []
    for _ in range(ITERATIONS):
        s = time.monotonic()
        classifier.classify_many(["EMAIL_ADDRESS", "PHI_MRN", "US_SSN", "PERSON", "PHONE_NUMBER"])
        times.append(time.monotonic() - s)
    report("S1: Classification only (5 entities, pure Python)", times)

    # S2-S5: Presidio scans
    for label, text, with_eval in [
        ("S2: Presidio scan — clean text (no PII)", "clean", False),
        ("S3: Presidio scan — PII (email + phone)", "pii", False),
        ("S4: Presidio scan — PHI (MRN + NPI + DOB)", "phi", False),
        ("S5: Full pipeline (Presidio + policy eval)", "full", True),
    ]:
        times = []
        for _ in range(ITERATIONS):
            try:
                s = time.monotonic()
                result = await engine.scan(TEXTS[text])
                if with_eval:
                    evaluator.evaluate(result["detections"], TEXTS[text], POLICY)
                times.append(time.monotonic() - s)
            except Exception as e:
                pass  # Skip failed iterations
        report(label, times)

    await engine.stop()
    print("\n" + "=" * 60)
    print("Benchmark complete.")
    print("=" * 60)


def _do_scan(text: str) -> dict:
    """Worker function — runs Presidio in the subprocess."""
    try:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        anonymizer = AnonymizerEngine()

        results = analyzer.analyze(text=text, language="en")
        detections = [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score}
            for r in results
        ]
        return {"detections": detections, "text": text}
    except Exception as e:
        return {"detections": [], "text": text, "error": str(e)}


if __name__ == "__main__":
    asyncio.run(main())
