"""
E4.3 Phase 3 gateway performance benchmark.

This module benchmarks the existing GatewayService through its public
``process_chat_request`` interface with mocked tenant DB/provider dependencies.
It does not modify Gateway, provider adapters, OPA, TokenVault, Audit, schemas,
APIs, Docker, Terraform, or frontend runtime behavior.

Usage from apps/api:
  python tests/performance/measure_gateway_e4_3.py --iterations 25 --warmups 5
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

API_ROOT = Path(__file__).resolve().parents[2]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.core.config import settings
from app.core.engine.gateway import GatewayService, ProviderResponse
from app.core.performance.benchmark_contracts import (
    BenchmarkEnvironmentContract,
    BenchmarkResultContract,
    BenchmarkScenarioContract,
    DEFAULT_GATEWAY_P95_THRESHOLD,
    LatencyBenchmarkContract,
)
from app.core.performance.benchmark_runner import IterationPlan
from app.core.performance.measurement import (
    CpuSampleCollector,
    LatencySampleCollector,
    MemorySampleCollector,
    ProcessCpuSampler,
    TracemallocMemorySampler,
    throughput_measurement,
)
from app.core.performance.performance_enums import (
    BenchmarkAssessment,
    BenchmarkKind,
    BenchmarkScenarioId,
    BenchmarkTarget,
    BenchmarkUnit,
)
from app.core.performance.performance_types import (
    BenchmarkMetadataContract,
    BenchmarkSummaryContract,
    CpuMeasurementContract,
    MemoryMeasurementContract,
    ThroughputMeasurementContract,
)
from app.core.performance.system_snapshot import environment_snapshot
from app.core.performance.timer import HighResolutionTimer
from app.core.policy.opa_integration import OpaRuntimeIntegration
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
from app.models.provider import ProviderType


DEFAULT_ITERATIONS = 10
DEFAULT_WARMUPS = 2
DEFAULT_UPSTREAM_DELAY_MS = 0.0


@dataclass(frozen=True)
class GatewayBenchmarkScenario:
    """Executable Gateway benchmark scenario metadata."""

    slug: str
    scenario_id: BenchmarkScenarioId
    target: BenchmarkTarget
    name: str
    description: str
    payload_profile: str
    message: str
    rule_type: RuleType
    policy_action: PolicyAction
    pii_types: tuple[str, ...] = ("EMAIL_ADDRESS",)
    keywords: tuple[str, ...] = ()
    redaction_mode: str = "MASK"
    expected_status_code: int = 200
    tenant_label: str = "primary"

    def contract(self, iterations: int, warmups: int) -> BenchmarkScenarioContract:
        return BenchmarkScenarioContract(
            scenario_id=self.scenario_id,
            target=self.target,
            kind=BenchmarkKind.LATENCY,
            name=self.name,
            description=self.description,
            payload_profile=self.payload_profile,
            iterations=iterations,
            warmups=warmups,
            concurrency=1,
            metadata={
                "slug": self.slug,
                "stream": False,
                "provider": "mock",
                "tenant_label": self.tenant_label,
                "policy_action": self.policy_action.value,
                "rule_type": self.rule_type.value,
            },
        )


@dataclass(frozen=True)
class GatewayBenchmarkReport:
    """Serializable report for one Gateway benchmark scenario."""

    scenario: BenchmarkScenarioContract
    latency_result: BenchmarkResultContract
    throughput: ThroughputMeasurementContract
    memory: MemoryMeasurementContract
    cpu: CpuMeasurementContract
    direct_latency_ms: dict[str, float]
    gateway_overhead_ms: dict[str, float]
    policy_contribution_ms: dict[str, float | str]
    tokenization_contribution_ms: str
    provider_call_count: int
    audit_call_count: int

    def as_dict(self) -> dict[str, object]:
        benchmark = self.latency_result.benchmark
        return {
            "scenario": self.scenario.model_dump(mode="json"),
            "latency_result": self.latency_result.model_dump(mode="json"),
            "throughput": self.throughput.model_dump(mode="json"),
            "memory": self.memory.model_dump(mode="json"),
            "cpu": self.cpu.model_dump(mode="json"),
            "direct_latency_ms": self.direct_latency_ms,
            "gateway_overhead_ms": self.gateway_overhead_ms,
            "policy_contribution_ms": self.policy_contribution_ms,
            "tokenization_contribution_ms": self.tokenization_contribution_ms,
            "provider_call_count": self.provider_call_count,
            "audit_call_count": self.audit_call_count,
            "sample_count": benchmark.metadata.sample_count,
        }


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


class GatewayBenchmarkDb:
    """Async DB test double mirroring SQLAlchemy AsyncSession.execute shape."""

    def __init__(self, route, provider, policy):
        self.route = route
        self.provider = provider
        self.policy = policy
        self.execute_calls = 0

    async def execute(self, statement, *args, **kwargs):
        self.execute_calls += 1
        normalized = str(statement).lower()
        if "gateway_routes" in normalized:
            return FakeResult(self.route)
        if "providers" in normalized:
            return FakeResult(self.provider)
        if "policies" in normalized or "policy_rules" in normalized:
            return FakeResult(self.policy, all_items=[self.policy])
        return FakeResult()

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def flush(self):
        return None


class FakeScanResult:
    """Small Presidio-compatible scan result for deterministic benchmark input."""

    _needles = {
        "EMAIL_ADDRESS": "person@example.test",
        "PHONE_NUMBER": "+1 202-555-0100",
        "API_KEY": "token=demo-token-redacted",
    }

    def __init__(self, text: str):
        self.detections: list[dict[str, object]] = []
        self.sanitized_text = text
        self.latency_ms = 0
        for entity_type, needle in self._needles.items():
            start = text.find(needle)
            if start < 0:
                continue
            self.detections.append(
                {
                    "entity_type": entity_type,
                    "start": start,
                    "end": start + len(needle),
                    "score": 0.99,
                }
            )
            self.sanitized_text = self.sanitized_text.replace(needle, f"[{entity_type}]")

    @property
    def has_detections(self) -> bool:
        return bool(self.detections)

    @property
    def entity_types(self) -> list[str]:
        return [str(detection["entity_type"]) for detection in self.detections]


class GatewayBenchmarkPatch:
    """Temporary benchmark-only patches for external side effects."""

    def __init__(self) -> None:
        self._settings: dict[str, object] = {}
        self._presidio_is_healthy = None
        self._presidio_scan = None
        self._publish_security_event = None
        self._publish = None

    def install(self) -> None:
        for name, value in {
            "FF_SECURITY_PIPELINE": True,
            "FF_INBOUND_SCAN": True,
            "FF_OUTBOUND_SCAN": True,
            "FF_SECURITY_SHADOW_MODE": False,
            "ENABLE_OPA_RUNTIME_INTEGRATION": False,
        }.items():
            self._settings[name] = getattr(settings, name)
            setattr(settings, name, value)

        from app.core.detection.presidio_engine import presidio_engine
        from app.core.events.producer import producer as event_producer

        self._presidio_is_healthy = presidio_engine.is_healthy
        self._presidio_scan = presidio_engine.scan
        self._publish_security_event = event_producer.publish_security_event
        self._publish = event_producer.publish

        presidio_engine.is_healthy = lambda: True
        presidio_engine.scan = AsyncMock(side_effect=lambda text: FakeScanResult(text))
        event_producer.publish_security_event = AsyncMock()
        event_producer.publish = AsyncMock()

    def restore(self) -> None:
        for name, value in self._settings.items():
            setattr(settings, name, value)
        self._settings.clear()

        from app.core.detection.presidio_engine import presidio_engine
        from app.core.events.producer import producer as event_producer

        if self._presidio_is_healthy is not None:
            presidio_engine.is_healthy = self._presidio_is_healthy
        if self._presidio_scan is not None:
            presidio_engine.scan = self._presidio_scan
        if self._publish_security_event is not None:
            event_producer.publish_security_event = self._publish_security_event
        if self._publish is not None:
            event_producer.publish = self._publish


class GatewayBenchmarkService:
    def __init__(self, scenario: GatewayBenchmarkScenario, upstream_delay_ms: float) -> None:
        self.tenant_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:{scenario.tenant_label}")
        self.user_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:user:{scenario.tenant_label}")
        self.api_key_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:key:{scenario.tenant_label}")
        self.provider = _provider(self.tenant_id)
        self.policy = _policy(self.tenant_id, scenario)
        self.route = _route(self.tenant_id, self.provider.id, self.policy.id)
        self.db = GatewayBenchmarkDb(self.route, self.provider, self.policy)
        self.service = GatewayService(self.db)
        self.service.opa_integration = OpaRuntimeIntegration(
            enabled=False,
            policy_url="",
            runtime_mode="STRICT",
        )
        self.service.audit_engine.log_request = AsyncMock()
        self.provider_call_count = 0
        self.upstream_delay_ms = upstream_delay_ms

        async def fake_chat_completion(*_args):
            self.provider_call_count += 1
            return await direct_provider_call(upstream_delay_ms)

        self.service.ai_client = SimpleNamespace(chat_completion=fake_chat_completion)

    async def execute(self, scenario: GatewayBenchmarkScenario) -> dict[str, object]:
        result = await self.service.process_chat_request(
            self.tenant_id,
            self.user_id,
            self.api_key_id,
            payload_for_scenario(scenario),
        )
        status_code = int(result.get("status_code", 0))
        if status_code != scenario.expected_status_code:
            raise RuntimeError(
                f"Gateway benchmark scenario {scenario.slug} expected "
                f"{scenario.expected_status_code}, got {status_code}: {result}"
            )
        return result

    @property
    def audit_call_count(self) -> int:
        return int(self.service.audit_engine.log_request.await_count)


def gateway_benchmark_scenarios() -> tuple[GatewayBenchmarkScenario, ...]:
    """Canonical E4.3 Gateway Phase 3 scenario registry."""

    return (
        GatewayBenchmarkScenario(
            slug="small_request",
            scenario_id=BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT,
            target=BenchmarkTarget.GATEWAY_LATENCY,
            name="Gateway small request",
            description="Small non-streaming chat-completions request through the Gateway.",
            payload_profile="small",
            message="Explain machine learning in one sentence.",
            rule_type=RuleType.content_filter,
            policy_action=PolicyAction.allow,
            keywords=("never-match-small",),
        ),
        GatewayBenchmarkScenario(
            slug="medium_request",
            scenario_id=BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT,
            target=BenchmarkTarget.GATEWAY_LATENCY,
            name="Gateway medium request",
            description="Medium non-streaming chat-completions request through the Gateway.",
            payload_profile="medium",
            message="Summarize safe AI gateway controls. " * 25,
            rule_type=RuleType.content_filter,
            policy_action=PolicyAction.allow,
            keywords=("never-match-medium",),
        ),
        GatewayBenchmarkScenario(
            slug="large_request",
            scenario_id=BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT,
            target=BenchmarkTarget.LARGE_PAYLOADS,
            name="Gateway large request",
            description="Large non-streaming chat-completions request through the Gateway.",
            payload_profile="large",
            message="Generate an enterprise security checklist. " * 250,
            rule_type=RuleType.content_filter,
            policy_action=PolicyAction.allow,
            keywords=("never-match-large",),
        ),
        GatewayBenchmarkScenario(
            slug="policy_allow",
            scenario_id=BenchmarkScenarioId.POLICY_YAML_EVALUATION,
            target=BenchmarkTarget.POLICY_EVALUATION,
            name="Gateway policy allow",
            description="Gateway request with an active route policy that allows the request.",
            payload_profile="policy_allow",
            message="This benign request should pass route policy checks.",
            rule_type=RuleType.content_filter,
            policy_action=PolicyAction.allow,
            keywords=("not-present-policy-allow",),
        ),
        GatewayBenchmarkScenario(
            slug="policy_redact",
            scenario_id=BenchmarkScenarioId.GATEWAY_REDACTION,
            target=BenchmarkTarget.GATEWAY_LATENCY,
            name="Gateway policy redact",
            description="Gateway request with fake PII redaction before mocked provider egress.",
            payload_profile="policy_redact",
            message="A demo user shared person@example.test and it should be protected.",
            rule_type=RuleType.pii_redact,
            policy_action=PolicyAction.warn,
            redaction_mode="MASK",
        ),
        GatewayBenchmarkScenario(
            slug="policy_block",
            scenario_id=BenchmarkScenarioId.GATEWAY_POLICY_BLOCK,
            target=BenchmarkTarget.POLICY_EVALUATION,
            name="Gateway policy block",
            description="Gateway request blocked by route policy before provider egress.",
            payload_profile="policy_block",
            message="This prompt contains blocked-term-e43 and must not reach a provider.",
            rule_type=RuleType.content_filter,
            policy_action=PolicyAction.block,
            keywords=("blocked-term-e43",),
            expected_status_code=403,
        ),
        GatewayBenchmarkScenario(
            slug="multiple_tenants",
            scenario_id=BenchmarkScenarioId.CONCURRENT_GATEWAY_REQUESTS,
            target=BenchmarkTarget.CONCURRENCY,
            name="Gateway multiple tenants",
            description="Same Gateway path with an isolated secondary tenant fixture.",
            payload_profile="multi_tenant",
            message="Tenant-isolated request for benchmark validation.",
            rule_type=RuleType.content_filter,
            policy_action=PolicyAction.allow,
            keywords=("not-present-multi-tenant",),
            tenant_label="secondary",
        ),
    )


def payload_for_scenario(scenario: GatewayBenchmarkScenario) -> dict[str, object]:
    return {
        "model": "client-requested-model",
        "route": "groq",
        "messages": [{"role": "user", "content": scenario.message}],
        "stream": False,
    }


def _provider(tenant_id: uuid.UUID):
    return SimpleNamespace(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:provider:{tenant_id}"),
        tenant_id=tenant_id,
        name="mock groq openai-compatible",
        type=ProviderType.groq,
        config={"base_url": "https://mock.provider.local/openai/v1"},
        is_active=True,
    )


def _policy(tenant_id: uuid.UUID, scenario: GatewayBenchmarkScenario):
    policy_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:policy:{scenario.slug}:{tenant_id}")
    if scenario.rule_type == RuleType.content_filter:
        conditions = {"keywords": list(scenario.keywords)}
    else:
        conditions = {
            "pii_types": list(scenario.pii_types),
            "redaction_mode": scenario.redaction_mode,
        }
    rule = SimpleNamespace(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:rule:{scenario.slug}:{tenant_id}"),
        policy_id=policy_id,
        rule_type=scenario.rule_type,
        conditions=conditions,
        action=scenario.policy_action,
        message=f"E4.3 benchmark {scenario.slug} policy.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=tenant_id,
        name=f"E4.3 {scenario.slug}",
        description="Local mocked benchmark policy.",
        is_active=True,
        priority=10,
        rules=[rule],
    )


def _route(tenant_id: uuid.UUID, provider_id: uuid.UUID, policy_id: uuid.UUID):
    return SimpleNamespace(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:route:{tenant_id}"),
        tenant_id=tenant_id,
        name="groq",
        provider_id=provider_id,
        is_default=True,
        is_active=True,
        redaction=RedactionStrategy.mask,
        config={"model": "llama3-8b-8192", "policy_id": str(policy_id)},
        created_at=datetime.now(UTC),
    )


async def direct_provider_call(delay_ms: float) -> ProviderResponse:
    if delay_ms > 0:
        await asyncio.sleep(delay_ms / 1000)
    return ProviderResponse(
        status_code=200,
        body={
            "choices": [{"message": {"role": "assistant", "content": "benchmark ok"}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10},
        },
        provider_name="mock",
        provider_type="groq",
        latency_ms=int(delay_ms),
    )


async def _measure_direct_baseline(
    *,
    iterations: int,
    warmups: int,
    upstream_delay_ms: float,
) -> LatencySampleCollector:
    collector = LatencySampleCollector()
    plan = IterationPlan(warmups=warmups, iterations=iterations)
    for index in range(plan.total_executions):
        timer = HighResolutionTimer().start()
        await direct_provider_call(upstream_delay_ms)
        elapsed = timer.stop().elapsed_ms
        if index >= plan.warmups:
            collector.add(elapsed)
    return collector


async def _measure_gateway_scenario(
    *,
    scenario: GatewayBenchmarkScenario,
    iterations: int,
    warmups: int,
    upstream_delay_ms: float,
    environment: BenchmarkEnvironmentContract,
) -> GatewayBenchmarkReport:
    service = GatewayBenchmarkService(scenario, upstream_delay_ms)
    contract = scenario.contract(iterations=iterations, warmups=warmups)
    plan = IterationPlan(warmups=warmups, iterations=iterations)

    for _ in range(plan.warmups):
        await service.execute(scenario)

    latency = LatencySampleCollector()
    memory = MemorySampleCollector()
    cpu = CpuSampleCollector()
    memory_sampler = TracemallocMemorySampler()
    cpu_sampler = ProcessCpuSampler()
    started_at = datetime.now(UTC)
    memory_sampler.start()
    cpu_sampler.start()
    wall_timer = HighResolutionTimer().start()
    for _ in range(plan.iterations):
        iteration_timer = HighResolutionTimer().start()
        await service.execute(scenario)
        latency.add(iteration_timer.stop().elapsed_ms)
        memory.add(memory_sampler.sample_peak_bytes())
    wall_time_ms = wall_timer.stop().elapsed_ms
    cpu.add(cpu_sampler.sample_percent())
    memory_sampler.stop()
    completed_at = datetime.now(UTC)

    direct = await _measure_direct_baseline(
        iterations=iterations,
        warmups=warmups,
        upstream_delay_ms=upstream_delay_ms,
    )

    gateway_stats = latency.statistics()
    direct_stats = direct.statistics()
    metadata = BenchmarkMetadataContract(
        iterations=iterations,
        warmups=warmups,
        sample_count=len(latency.samples_ms),
        started_at=started_at,
        completed_at=completed_at,
        labels={
            "scenario": scenario.slug,
            "stream": "false",
            "provider": "mock",
            "runtime_mutation": "false",
        },
    )
    benchmark = LatencyBenchmarkContract(
        benchmark_id=uuid.uuid4(),
        scenario=contract,
        environment=environment,
        metadata=metadata,
        thresholds=(DEFAULT_GATEWAY_P95_THRESHOLD,),
        latency=gateway_stats,
    )
    result = BenchmarkResultContract(
        result_id=uuid.uuid4(),
        benchmark=benchmark,
        notes=(
            "Gateway path measured with mocked provider and existing public GatewayService interface.",
            "Policy contribution is reported as gateway overhead versus direct mocked provider baseline.",
        ),
    )

    overhead = {
        "p50_ms": max(0.0, gateway_stats.p50_ms - direct_stats.p50_ms),
        "p90_ms": max(0.0, gateway_stats.p90_ms - direct_stats.p90_ms),
        "p95_ms": max(0.0, gateway_stats.p95_ms - direct_stats.p95_ms),
        "p99_ms": max(0.0, gateway_stats.p99_ms - direct_stats.p99_ms),
    }
    return GatewayBenchmarkReport(
        scenario=contract,
        latency_result=result,
        throughput=throughput_measurement(
            total_operations=iterations,
            wall_time_ms=wall_time_ms,
            unit=BenchmarkUnit.REQUESTS_PER_SECOND,
        ),
        memory=memory.measurement(),
        cpu=cpu.measurement(),
        direct_latency_ms={
            "p50_ms": direct_stats.p50_ms,
            "p90_ms": direct_stats.p90_ms,
            "p95_ms": direct_stats.p95_ms,
            "p99_ms": direct_stats.p99_ms,
            "minimum_ms": direct_stats.minimum_ms,
            "maximum_ms": direct_stats.maximum_ms,
            "average_ms": direct_stats.average_ms,
            "median_ms": direct_stats.median_ms,
        },
        gateway_overhead_ms=overhead,
        policy_contribution_ms={
            "method": "gateway_minus_direct_provider_baseline",
            **overhead,
        },
        tokenization_contribution_ms="not_exercised_by_non_streaming_gateway_phase3_scenarios",
        provider_call_count=service.provider_call_count,
        audit_call_count=service.audit_call_count,
    )


async def run_gateway_benchmarks(
    *,
    iterations: int = DEFAULT_ITERATIONS,
    warmups: int = DEFAULT_WARMUPS,
    upstream_delay_ms: float = DEFAULT_UPSTREAM_DELAY_MS,
    scenarios: Iterable[GatewayBenchmarkScenario] | None = None,
) -> tuple[GatewayBenchmarkReport, ...]:
    if iterations < 1:
        raise ValueError("iterations_must_be_positive")
    if warmups < 0:
        raise ValueError("warmups_must_be_non_negative")

    patch = GatewayBenchmarkPatch()
    patch.install()
    try:
        environment = environment_snapshot(name="e4.3-gateway-performance", authclaw_version="v0.10.0")
        selected = tuple(scenarios or gateway_benchmark_scenarios())
        return tuple(
            [
                await _measure_gateway_scenario(
                    scenario=scenario,
                    iterations=iterations,
                    warmups=warmups,
                    upstream_delay_ms=upstream_delay_ms,
                    environment=environment,
                )
                for scenario in selected
            ]
        )
    finally:
        patch.restore()


def summarize_gateway_benchmarks(reports: Iterable[GatewayBenchmarkReport]) -> BenchmarkSummaryContract:
    reports_tuple = tuple(reports)
    threshold = DEFAULT_GATEWAY_P95_THRESHOLD
    passed = 0
    failed = 0
    for report in reports_tuple:
        p95 = float(report.gateway_overhead_ms["p95_ms"])
        if p95 <= threshold.value:
            passed += 1
        else:
            failed += 1
    assessment = BenchmarkAssessment.PASS if failed == 0 else BenchmarkAssessment.PARTIAL
    return BenchmarkSummaryContract(
        summary_id=uuid.uuid4(),
        assessment=assessment,
        total_scenarios=len(reports_tuple),
        passed_scenarios=passed,
        failed_scenarios=failed,
        thresholds=(threshold,),
        metadata={
            "target": BenchmarkTarget.GATEWAY_LATENCY.value,
            "streaming": "disabled",
            "provider": "mock",
        },
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description="AuthClaw E4.3 Gateway performance benchmark")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument("--upstream-delay-ms", type=float, default=DEFAULT_UPSTREAM_DELAY_MS)
    args = parser.parse_args()

    reports = await run_gateway_benchmarks(
        iterations=args.iterations,
        warmups=args.warmups,
        upstream_delay_ms=args.upstream_delay_ms,
    )
    summary = summarize_gateway_benchmarks(reports)
    print(
        json.dumps(
            {
                "summary": summary.model_dump(mode="json"),
                "results": [report.as_dict() for report in reports],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
