from __future__ import annotations

import argparse
import json
import statistics
import time
import tracemalloc

from app.core.engine.sse_parser import ParsedSseEvent, SseParser
from app.core.engine.streaming_state_machine import StreamingRedactionStateMachine
from app.core.engine.utf8_decoder import Utf8IncrementalDecoder


def _event(content: str) -> bytes:
    return f'data: {{"choices":[{{"delta":{{"content":"{content}"}}}}]}}\n\n'.encode("utf-8")


def _chunks(events: int) -> list[bytes]:
    chunks = [_event(f"word{index} ") for index in range(events)]
    chunks.append(b"data: [DONE]\n\n")
    return chunks


def _legacy_buffered(chunks: list[bytes]) -> str:
    pieces: list[str] = []
    for chunk in chunks:
        text = chunk.decode("utf-8").strip()
        if not text.startswith("data: "):
            continue
        data = text[len("data: "):].strip()
        if data == "[DONE]":
            break
        payload = json.loads(data)
        content = payload["choices"][0]["delta"].get("content")
        if content:
            pieces.append(content)
    return "".join(pieces)


def _e2_3_pipeline(chunks: list[bytes]) -> str:
    decoder = Utf8IncrementalDecoder()
    parser = SseParser()
    machine = StreamingRedactionStateMachine(max_window_chars=64 * 1024)
    pieces: list[str] = []
    done = False
    for chunk in chunks:
        decoded = decoder.decode(chunk)
        for event in parser.feed(decoded):
            if event.data == "[DONE]":
                done = True
                break
            if event.data:
                payload = json.loads(event.data)
                content = payload["choices"][0]["delta"].get("content")
                if content:
                    machine.append(ParsedSseEvent(data=content))
                    pieces.extend(window.text for window in machine.emit_safe())
        if done:
            break
    if not done:
        parser.flush()
    machine.end_of_stream()
    pieces.extend(window.text for window in machine.flush())
    return "".join(pieces)


def _measure_latency(fn, chunks: list[bytes], iterations: int, warmup: int) -> list[float]:
    for _ in range(warmup):
        fn(chunks)
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn(chunks)
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def _measure_peak_memory(fn, chunks: list[bytes]) -> int:
    tracemalloc.start()
    try:
        fn(chunks)
        _, peak = tracemalloc.get_traced_memory()
        return peak
    finally:
        tracemalloc.stop()


def _stats(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "p99_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))], 3),
        "max_ms": round(max(ordered), 3),
    }


def run_benchmark(events: int, iterations: int, warmup: int) -> dict[str, object]:
    chunks = _chunks(events)
    legacy_samples = _measure_latency(_legacy_buffered, chunks, iterations, warmup)
    pipeline_samples = _measure_latency(_e2_3_pipeline, chunks, iterations, warmup)
    legacy_peak = _measure_peak_memory(_legacy_buffered, chunks)
    pipeline_peak = _measure_peak_memory(_e2_3_pipeline, chunks)
    overhead = [new - old for new, old in zip(pipeline_samples, legacy_samples)]
    return {
        "events": events,
        "iterations": iterations,
        "legacy": {**_stats(legacy_samples), "peak_kb": round(legacy_peak / 1024, 1)},
        "e2_3_pipeline": {**_stats(pipeline_samples), "peak_kb": round(pipeline_peak / 1024, 1)},
        "overhead": _stats(overhead),
        "throughput_events_per_sec": round(events / (statistics.median(pipeline_samples) / 1000), 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=2500)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(run_benchmark(args.events, args.iterations, args.warmup), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
