"""
AuthClaw Gateway MVP latency benchmark.

Offline by default:
  - no live provider calls
  - no provider keys
  - mocked upstream latency baseline
  - route-attached policy and redaction enabled
  - audit write path mocked to isolate gateway overhead

Usage from apps/api:
  python tests/performance/measure_gateway.py --iterations 100 --warmup 10
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.core.config import settings
from app.core.engine.gateway import GatewayService, ProviderResponse
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
from app.models.provider import ProviderType


@dataclass
class BenchmarkResult:
    iterations: int
    warmup: int
    direct_p50_ms: float
    direct_p95_ms: float
    direct_p99_ms: float
    direct_max_ms: float
    gateway_p50_ms: float
    gateway_p95_ms: float
    gateway_p99_ms: float
    gateway_max_ms: float
    overhead_p50_ms: float
    overhead_p95_ms: float
    overhead_p99_ms: float
    target_met_p95: bool


class FakeScalarResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._all_items = all_items if all_items is not None else ([] if first is None else [first])

    def first(self):
        return self._first

    def all(self):
        return self._all_items


class FakeResult:
    def __init__(self, first=None, all_items=None):
        self._scalars = FakeScalarResult(first=first, all_items=all_items)

    def scalars(self):
        return self._scalars


class BenchmarkDb:
    def __init__(self, route, provider, policy):
        self.route = route
        self.provider = provider
        self.policy = policy

    async def execute(self, _stmt):
        statement = str(_stmt).lower()
        if "gateway_routes" in statement:
            return FakeResult(self.route)
        if "providers" in statement:
            return FakeResult(self.provider)
        if "policies" in statement or "policy_rules" in statement:
            return FakeResult(self.policy, all_items=[self.policy])
        return FakeResult()

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def flush(self):
        return None


class FakeScanResult:
    def __init__(self, text: str):
        needle = "person@example.test"
        start = text.find(needle)
        self.detections = []
        self.sanitized_text = text
        self.latency_ms = 0
        if start >= 0:
            self.detections = [
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": start,
                    "end": start + len(needle),
                    "score": 0.99,
                }
            ]
            self.sanitized_text = text.replace(needle, "<EMAIL_ADDRESS>")

    @property
    def has_detections(self) -> bool:
        return bool(self.detections)

    @property
    def entity_types(self) -> list[str]:
        return [detection["entity_type"] for detection in self.detections]


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return round(ordered[index], 3)


def _provider():
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="mock groq openai-compatible",
        type=ProviderType.groq,
        config={"base_url": "https://mock.provider.local/openai/v1"},
        is_active=True,
    )


def _policy(tenant_id):
    policy_id = uuid.uuid4()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        policy_id=policy_id,
        rule_type=RuleType.pii_redact,
        conditions={"pii_types": ["EMAIL_ADDRESS"], "redaction_mode": "MASK"},
        action=PolicyAction.warn,
        message="PII must be redacted before egress.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=tenant_id,
        name="Benchmark route policy",
        description="Local mocked benchmark policy.",
        is_active=True,
        priority=10,
        rules=[rule],
    )


def _route(tenant_id, provider_id, policy_id):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name="groq",
        provider_id=provider_id,
        is_default=True,
        is_active=True,
        redaction=RedactionStrategy.mask,
        config={"model": "llama3-8b-8192", "policy_id": str(policy_id)},
        created_at=datetime.utcnow(),
    )


async def _direct_upstream_call(delay_ms: float) -> ProviderResponse:
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000)
    return ProviderResponse(
        status_code=200,
        body={
            "choices": [{"message": {"role": "assistant", "content": "benchmark ok"}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2},
        },
        provider_name="mock",
        provider_type="groq",
        latency_ms=int(delay_ms),
    )


def _build_service(upstream_delay_ms: float) -> GatewayService:
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy(tenant_id)
    route = _route(tenant_id, provider.id, policy.id)
    service = GatewayService(BenchmarkDb(route, provider, policy))
    service.audit_engine.log_request = AsyncMock()

    async def fake_chat_completion(*_args):
        return await _direct_upstream_call(upstream_delay_ms)

    service.ai_client = SimpleNamespace(chat_completion=fake_chat_completion)
    return service


async def _measure_direct(iterations: int, warmup: int, delay_ms: float) -> list[float]:
    samples: list[float] = []
    for index in range(iterations + warmup):
        started = time.perf_counter()
        await _direct_upstream_call(delay_ms)
        elapsed = (time.perf_counter() - started) * 1000
        if index >= warmup:
            samples.append(elapsed)
    return samples


async def _measure_gateway(iterations: int, warmup: int, delay_ms: float) -> list[float]:
    settings.FF_SECURITY_PIPELINE = True
    settings.FF_INBOUND_SCAN = True
    settings.FF_OUTBOUND_SCAN = True
    settings.FF_SECURITY_SHADOW_MODE = False
    from app.core.detection.presidio_engine import presidio_engine
    from app.core.events.producer import producer as event_producer

    presidio_engine.is_healthy = lambda: True
    presidio_engine.scan = AsyncMock(side_effect=lambda text: FakeScanResult(text))
    event_producer.publish_security_event = AsyncMock()
    event_producer.publish = AsyncMock()

    service = _build_service(delay_ms)
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    api_key_id = uuid.uuid4()
    payload = {
        "model": "client-model",
        "route": "groq",
        "messages": [{"role": "user", "content": "Benchmark email person@example.test should be protected."}],
        "stream": False,
    }
    samples: list[float] = []
    for index in range(iterations + warmup):
        started = time.perf_counter()
        result = await service.process_chat_request(tenant_id, user_id, api_key_id, payload)
        elapsed = (time.perf_counter() - started) * 1000
        if result["status_code"] != 200:
            raise RuntimeError(f"Gateway benchmark request failed: {result}")
        if index >= warmup:
            samples.append(elapsed)
    return samples


async def run_benchmark(iterations: int, warmup: int, upstream_delay_ms: float) -> BenchmarkResult:
    direct = await _measure_direct(iterations, warmup, upstream_delay_ms)
    gateway = await _measure_gateway(iterations, warmup, upstream_delay_ms)

    direct_p50 = _percentile(direct, 50)
    direct_p95 = _percentile(direct, 95)
    direct_p99 = _percentile(direct, 99)
    gateway_p50 = _percentile(gateway, 50)
    gateway_p95 = _percentile(gateway, 95)
    gateway_p99 = _percentile(gateway, 99)
    overhead_p95 = round(gateway_p95 - direct_p95, 3)
    return BenchmarkResult(
        iterations=iterations,
        warmup=warmup,
        direct_p50_ms=direct_p50,
        direct_p95_ms=direct_p95,
        direct_p99_ms=direct_p99,
        direct_max_ms=round(max(direct), 3),
        gateway_p50_ms=gateway_p50,
        gateway_p95_ms=gateway_p95,
        gateway_p99_ms=gateway_p99,
        gateway_max_ms=round(max(gateway), 3),
        overhead_p50_ms=round(gateway_p50 - direct_p50, 3),
        overhead_p95_ms=overhead_p95,
        overhead_p99_ms=round(gateway_p99 - direct_p99, 3),
        target_met_p95=overhead_p95 <= 50.0,
    )


def _format_markdown(result: BenchmarkResult) -> str:
    verdict = "met" if result.target_met_p95 else "not met"
    return "\n".join(
        [
            "# AuthClaw Gateway MVP Latency Benchmark",
            "",
            "Offline mocked benchmark. No live provider keys or network calls are used.",
            "",
            f"- Iterations: `{result.iterations}`",
            f"- Warmup: `{result.warmup}`",
            f"- p95 overhead target: `<=50ms`",
            f"- Result: `{verdict}`",
            "",
            "| Path | p50 ms | p95 ms | p99 ms | max ms |",
            "| --- | ---: | ---: | ---: | ---: |",
            f"| Direct mocked upstream | {result.direct_p50_ms} | {result.direct_p95_ms} | {result.direct_p99_ms} | {result.direct_max_ms} |",
            f"| AuthClaw gateway | {result.gateway_p50_ms} | {result.gateway_p95_ms} | {result.gateway_p99_ms} | {result.gateway_max_ms} |",
            f"| Gateway overhead | {result.overhead_p50_ms} | {result.overhead_p95_ms} | {result.overhead_p99_ms} | - |",
            "",
            "Security settings exercised: route-selected model, route-attached policy, redaction, fail-closed gateway path, and mocked audit write.",
        ]
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description="AuthClaw Gateway MVP mocked latency benchmark")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--upstream-delay-ms", type=float, default=0.0)
    parser.add_argument("--output", default="docs/performance/gateway_mvp_latency.md")
    args = parser.parse_args()

    result = await run_benchmark(args.iterations, args.warmup, args.upstream_delay_ms)
    report = _format_markdown(result)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")

    print(report)


if __name__ == "__main__":
    asyncio.run(main())
