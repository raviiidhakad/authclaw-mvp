"""
Gateway Performance Validation Script
=======================================
Measures performance overhead of the AuthClaw Gateway:
  - TTFT (Time To First Token)
  - Streaming Chunk Latency
  - Gateway Processing Overhead (measured against direct provider calls)
  - DLP Buffering Overhead (BUFFERED vs PASSTHROUGH latency delta)
  - Memory Consumption

Outputs:
  docs/performance/gateway_baseline.md

Usage (from apps/api directory):
  python tests/performance/measure_gateway.py --host http://localhost:8000 \
         --token <bearer-token> --samples 10

Requirements:
  pip install psutil httpx
"""
import os
import sys
import json
import time
import argparse
import asyncio
import statistics
from typing import List, Optional
from dataclasses import dataclass, field

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SampleResult:
    latency_ms: float
    ttft_ms: Optional[float]
    chunk_count: int
    mode: str
    success: bool
    error: Optional[str] = None


@dataclass
class MeasurementReport:
    mode: str
    samples: int
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    avg_ttft_ms: Optional[float]
    p95_ttft_ms: Optional[float]
    success_rate: float
    error_count: int


# ---------------------------------------------------------------------------
# Measurement functions
# ---------------------------------------------------------------------------

async def measure_sync(
    client: httpx.AsyncClient,
    host: str,
    headers: dict,
    payload: dict,
    n: int,
) -> List[SampleResult]:
    results = []
    for i in range(n):
        start = time.monotonic()
        try:
            resp = await client.post(f"{host}/api/v1/gateway/chat", json=payload, headers=headers)
            latency_ms = (time.monotonic() - start) * 1000
            success = 200 <= resp.status_code < 300
            results.append(SampleResult(
                latency_ms=latency_ms,
                ttft_ms=None,
                chunk_count=0,
                mode="sync",
                success=success,
                error=None if success else f"HTTP {resp.status_code}",
            ))
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            results.append(SampleResult(latency_ms=latency_ms, ttft_ms=None, chunk_count=0,
                                         mode="sync", success=False, error=str(e)))
        await asyncio.sleep(0.1)
    return results


async def measure_stream(
    client: httpx.AsyncClient,
    host: str,
    headers: dict,
    payload: dict,
    mode_name: str,
    n: int,
) -> List[SampleResult]:
    results = []
    for i in range(n):
        start = time.monotonic()
        ttft_ms = None
        chunk_count = 0
        success = True
        error = None

        try:
            async with client.stream("POST", f"{host}/api/v1/gateway/chat",
                                     json=payload, headers=headers) as resp:
                if resp.status_code != 200:
                    success = False
                    error = f"HTTP {resp.status_code}"
                else:
                    async for line in resp.aiter_lines():
                        if line:
                            if ttft_ms is None:
                                ttft_ms = (time.monotonic() - start) * 1000
                            chunk_count += 1
                            if line.strip() == "data: [DONE]":
                                break
        except Exception as e:
            success = False
            error = str(e)

        latency_ms = (time.monotonic() - start) * 1000
        results.append(SampleResult(
            latency_ms=latency_ms,
            ttft_ms=ttft_ms,
            chunk_count=chunk_count,
            mode=mode_name,
            success=success,
            error=error,
        ))
        await asyncio.sleep(0.2)
    return results


def compute_report(results: List[SampleResult], mode: str) -> MeasurementReport:
    latencies = [r.latency_ms for r in results]
    ttfts = [r.ttft_ms for r in results if r.ttft_ms is not None]
    errors = [r for r in results if not r.success]

    def pct(data, p):
        if not data:
            return 0.0
        s = sorted(data)
        idx = max(0, int(len(s) * p / 100) - 1)
        return round(s[idx], 2)

    return MeasurementReport(
        mode=mode,
        samples=len(results),
        avg_latency_ms=round(statistics.mean(latencies), 2) if latencies else 0,
        p50_latency_ms=pct(latencies, 50),
        p95_latency_ms=pct(latencies, 95),
        min_latency_ms=round(min(latencies), 2) if latencies else 0,
        max_latency_ms=round(max(latencies), 2) if latencies else 0,
        avg_ttft_ms=round(statistics.mean(ttfts), 2) if ttfts else None,
        p95_ttft_ms=pct(ttfts, 95) if ttfts else None,
        success_rate=round((len(results) - len(errors)) / len(results) * 100, 1) if results else 0,
        error_count=len(errors),
    )


def get_memory_mb() -> Optional[float]:
    """Get current process memory usage in MB."""
    if not HAS_PSUTIL:
        return None
    proc = psutil.Process(os.getpid())
    return round(proc.memory_info().rss / 1024 / 1024, 2)


def format_report(reports: List[MeasurementReport], memory_mb: Optional[float]) -> str:
    lines = []
    lines.append("# AuthClaw Gateway Performance Baseline\n")
    lines.append(f"> Generated: {time.strftime('%Y-%m-%d %Human:%M:%S UTC', time.gmtime())}")
    lines.append(f"> Measurement Tool: `tests/performance/measure_gateway.py`\n")

    if memory_mb:
        lines.append(f"## Memory Consumption\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"| --- | --- |")
        lines.append(f"| Client Process RSS | {memory_mb} MB |")
        lines.append("")

    lines.append("## Latency Measurements\n")
    lines.append("| Mode | Samples | Avg (ms) | p50 (ms) | p95 (ms) | Min (ms) | Max (ms) | Success% |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")

    for r in reports:
        lines.append(
            f"| {r.mode} | {r.samples} | {r.avg_latency_ms} | {r.p50_latency_ms} | "
            f"{r.p95_latency_ms} | {r.min_latency_ms} | {r.max_latency_ms} | {r.success_rate}% |"
        )

    lines.append("")
    lines.append("## Time To First Token (TTFT)\n")
    lines.append("| Mode | Avg TTFT (ms) | p95 TTFT (ms) |")
    lines.append("| --- | --- | --- |")

    for r in reports:
        if r.avg_ttft_ms is not None:
            lines.append(f"| {r.mode} | {r.avg_ttft_ms} | {r.p95_ttft_ms} |")

    stream_reports = [r for r in reports if "buffered" in r.mode or "passthrough" in r.mode]
    if len(stream_reports) >= 2:
        buf = next((r for r in stream_reports if "buffered" in r.mode), None)
        pas = next((r for r in stream_reports if "passthrough" in r.mode), None)
        if buf and pas and buf.avg_ttft_ms and pas.avg_ttft_ms:
            dlp_overhead = round(buf.avg_ttft_ms - pas.avg_ttft_ms, 2)
            lines.append("")
            lines.append("## DLP Buffering Overhead\n")
            lines.append("| Metric | Value |")
            lines.append("| --- | --- |")
            lines.append(f"| BUFFERED avg TTFT | {buf.avg_ttft_ms} ms |")
            lines.append(f"| PASSTHROUGH avg TTFT | {pas.avg_ttft_ms} ms |")
            lines.append(f"| DLP Overhead (delta) | {dlp_overhead} ms |")

    lines.append("")
    lines.append("## Error Summary\n")
    lines.append("| Mode | Errors |")
    lines.append("| --- | --- |")
    for r in reports:
        lines.append(f"| {r.mode} | {r.error_count} |")

    lines.append("")
    lines.append("---")
    lines.append("> [!NOTE]")
    lines.append("> Measurements taken against local Docker Compose deployment.")
    lines.append("> Live provider latency is included in all measurements.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(description="AuthClaw Gateway Performance Baseline")
    parser.add_argument("--host", default="http://localhost:8000", help="Gateway host")
    parser.add_argument("--token", default=os.getenv("LOCUST_GATEWAY_TOKEN", ""), help="Bearer token")
    parser.add_argument("--samples", type=int, default=5, help="Number of samples per mode")
    parser.add_argument("--output", default="docs/performance/gateway_baseline.md")
    args = parser.parse_args()

    if not args.token:
        print("ERROR: --token or LOCUST_GATEWAY_TOKEN required")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json",
    }

    sync_payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "What is 2+2?"}],
        "max_tokens": 5,
    }
    buffered_payload = {**sync_payload, "stream": True, "streaming_mode": "buffered", "max_tokens": 30}
    passthrough_payload = {**sync_payload, "stream": True, "streaming_mode": "passthrough", "max_tokens": 30}

    memory_before = get_memory_mb()

    print(f"[*] Running {args.samples} samples per mode against {args.host}")
    print("[*] Sync measurements...")
    reports = []

    async with httpx.AsyncClient(timeout=60.0) as client:
        sync_results = await measure_sync(client, args.host, headers, sync_payload, args.samples)
        reports.append(compute_report(sync_results, "sync"))
        print(f"    Done. avg={reports[-1].avg_latency_ms}ms")

        print("[*] BUFFERED stream measurements...")
        buf_results = await measure_stream(client, args.host, headers, buffered_payload, "buffered-stream", args.samples)
        reports.append(compute_report(buf_results, "buffered-stream"))
        print(f"    Done. avg_ttft={reports[-1].avg_ttft_ms}ms")

        print("[*] PASSTHROUGH stream measurements...")
        pt_results = await measure_stream(client, args.host, headers, passthrough_payload, "passthrough-stream", args.samples)
        reports.append(compute_report(pt_results, "passthrough-stream"))
        print(f"    Done. avg_ttft={reports[-1].avg_ttft_ms}ms")

    memory_after = get_memory_mb()
    memory_delta = round((memory_after or 0) - (memory_before or 0), 2) if memory_before and memory_after else None

    md = format_report(reports, memory_after)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(md)

    print(f"\n[+] Baseline report written to: {args.output}")
    if memory_delta:
        print(f"[+] Memory delta during test: {memory_delta} MB")
    print("\n--- Summary ---")
    for r in reports:
        print(f"  {r.mode:25s}  avg={r.avg_latency_ms}ms  p95={r.p95_latency_ms}ms  "
              f"TTFT={r.avg_ttft_ms}ms  errors={r.error_count}")


if __name__ == "__main__":
    asyncio.run(main())
