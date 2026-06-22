"""
AuthClaw Gateway Load Testing - Locust Configuration
=====================================================
Simulates concurrent synchronous, streaming, BUFFERED, and PASSTHROUGH requests
against the running AuthClaw API Gateway.

Usage (from apps/api directory):
  locust -f tests/performance/locustfile.py --host http://localhost:8000 \
         --users 20 --spawn-rate 2 --run-time 60s --headless

Requirements:
  pip install locust

Environment variables:
  LOCUST_GATEWAY_TOKEN   - Bearer token for gateway API key authentication
  LOCUST_TENANT_ID       - Tenant UUID to use in requests
"""
import os
import json
import time
import random
import logging
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner, WorkerRunner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_TOKEN = os.getenv("LOCUST_GATEWAY_TOKEN", "test-token")
HEADERS = {
    "Authorization": f"Bearer {GATEWAY_TOKEN}",
    "Content-Type": "application/json",
}

SYNC_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "What is 2+2? Reply in one word."}],
    "max_tokens": 5,
}

STREAM_BUFFERED_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Count from 1 to 5."}],
    "max_tokens": 50,
    "stream": True,
    "streaming_mode": "buffered",
}

STREAM_PASSTHROUGH_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Count from 1 to 5."}],
    "max_tokens": 50,
    "stream": True,
    "streaming_mode": "passthrough",
}

# Burst payloads to trigger rate limiting
BURST_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Ping"}],
    "max_tokens": 1,
}

# ---------------------------------------------------------------------------
# Metrics tracking
# ---------------------------------------------------------------------------

class GatewayMetrics:
    """Thread-safe metrics accumulator for custom performance data."""
    def __init__(self):
        self.ttft_measurements = []     # Time To First Token (ms)
        self.rate_limit_hits = 0
        self.stream_success = 0
        self.stream_failures = 0

    def record_ttft(self, ms: float):
        self.ttft_measurements.append(ms)

    def record_rate_limit(self):
        self.rate_limit_hits += 1

    def record_stream(self, success: bool):
        if success:
            self.stream_success += 1
        else:
            self.stream_failures += 1

    def summary(self) -> dict:
        ttfts = self.ttft_measurements
        return {
            "ttft_count": len(ttfts),
            "ttft_avg_ms": round(sum(ttfts) / len(ttfts), 2) if ttfts else 0,
            "ttft_p50_ms": round(sorted(ttfts)[len(ttfts) // 2], 2) if ttfts else 0,
            "ttft_p95_ms": round(sorted(ttfts)[int(len(ttfts) * 0.95)], 2) if ttfts else 0,
            "ttft_min_ms": round(min(ttfts), 2) if ttfts else 0,
            "ttft_max_ms": round(max(ttfts), 2) if ttfts else 0,
            "rate_limit_hits": self.rate_limit_hits,
            "stream_success": self.stream_success,
            "stream_failures": self.stream_failures,
        }


metrics = GatewayMetrics()


# ---------------------------------------------------------------------------
# Locust Users
# ---------------------------------------------------------------------------

class SynchronousUser(HttpUser):
    """
    Simulates a user making synchronous (non-streaming) requests.
    Weight=3: 60% of total load.
    """
    weight = 3
    wait_time = between(0.5, 2.0)

    @task(5)
    def sync_chat_completion(self):
        """Standard synchronous chat completion."""
        with self.client.post(
            "/api/v1/gateway/chat",
            json=SYNC_PAYLOAD,
            headers=HEADERS,
            catch_response=True,
            name="POST /gateway/chat [sync]",
        ) as resp:
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if "choices" not in body:
                        resp.failure(f"Missing 'choices' in response: {body}")
                except Exception as e:
                    resp.failure(f"JSON parse error: {e}")
            elif resp.status_code == 429:
                metrics.record_rate_limit()
                resp.success()  # Rate limits are expected under load, not a failure
            else:
                resp.failure(f"Unexpected status {resp.status_code}")

    @task(1)
    def sync_burst_rate_limit(self):
        """Rapid-fire requests to stress-test the rate limiter."""
        for _ in range(5):
            with self.client.post(
                "/api/v1/gateway/chat",
                json=BURST_PAYLOAD,
                headers=HEADERS,
                catch_response=True,
                name="POST /gateway/chat [burst]",
            ) as resp:
                if resp.status_code == 429:
                    metrics.record_rate_limit()
                    resp.success()
                elif resp.status_code != 200:
                    resp.failure(f"Unexpected status {resp.status_code}")


class BufferedStreamUser(HttpUser):
    """
    Simulates BUFFERED streaming requests.
    Weight=2: ~40% of total load.
    """
    weight = 2
    wait_time = between(1.0, 3.0)

    @task
    def buffered_stream(self):
        """BUFFERED streaming request — consumes SSE chunks."""
        start = time.monotonic()
        first_chunk_ms = None
        chunk_count = 0

        with self.client.post(
            "/api/v1/gateway/chat",
            json=STREAM_BUFFERED_PAYLOAD,
            headers=HEADERS,
            stream=True,
            catch_response=True,
            name="POST /gateway/chat [buffered-stream]",
        ) as resp:
            if resp.status_code != 200:
                if resp.status_code == 429:
                    metrics.record_rate_limit()
                    resp.success()
                else:
                    metrics.record_stream(False)
                    resp.failure(f"Unexpected status {resp.status_code}")
                return

            for line in resp.iter_lines():
                if line:
                    if first_chunk_ms is None:
                        first_chunk_ms = (time.monotonic() - start) * 1000
                        metrics.record_ttft(first_chunk_ms)
                    chunk_count += 1
                    if line.strip() == "data: [DONE]":
                        break

            metrics.record_stream(True)
            resp.success()
        logger.debug(f"[BUFFERED] TTFT={first_chunk_ms:.0f}ms chunks={chunk_count}")


class PassthroughStreamUser(HttpUser):
    """
    Simulates PASSTHROUGH streaming requests.
    Weight=1: ~20% of total load.
    """
    weight = 1
    wait_time = between(1.0, 3.0)

    @task
    def passthrough_stream(self):
        """PASSTHROUGH streaming request."""
        start = time.monotonic()
        first_chunk_ms = None
        chunk_count = 0

        with self.client.post(
            "/api/v1/gateway/chat",
            json=STREAM_PASSTHROUGH_PAYLOAD,
            headers=HEADERS,
            stream=True,
            catch_response=True,
            name="POST /gateway/chat [passthrough-stream]",
        ) as resp:
            if resp.status_code != 200:
                if resp.status_code == 429:
                    metrics.record_rate_limit()
                    resp.success()
                else:
                    metrics.record_stream(False)
                    resp.failure(f"Unexpected status {resp.status_code}")
                return

            for line in resp.iter_lines():
                if line:
                    if first_chunk_ms is None:
                        first_chunk_ms = (time.monotonic() - start) * 1000
                        metrics.record_ttft(first_chunk_ms)
                    chunk_count += 1
                    if line.strip() == "data: [DONE]":
                        break

            metrics.record_stream(True)
            resp.success()
        logger.debug(f"[PASSTHROUGH] TTFT={first_chunk_ms:.0f}ms chunks={chunk_count}")


# ---------------------------------------------------------------------------
# Locust event hooks — print metrics on test completion
# ---------------------------------------------------------------------------

@events.quitting.add_listener
def on_quitting(environment, **kwargs):
    summary = metrics.summary()
    print("\n" + "=" * 60)
    print("AUTHCLAW GATEWAY PERFORMANCE METRICS")
    print("=" * 60)
    print(f"  TTFT measurements   : {summary['ttft_count']}")
    print(f"  TTFT avg            : {summary['ttft_avg_ms']} ms")
    print(f"  TTFT p50            : {summary['ttft_p50_ms']} ms")
    print(f"  TTFT p95            : {summary['ttft_p95_ms']} ms")
    print(f"  TTFT min            : {summary['ttft_min_ms']} ms")
    print(f"  TTFT max            : {summary['ttft_max_ms']} ms")
    print(f"  Rate limit hits     : {summary['rate_limit_hits']}")
    print(f"  Stream successes    : {summary['stream_success']}")
    print(f"  Stream failures     : {summary['stream_failures']}")
    print("=" * 60)
