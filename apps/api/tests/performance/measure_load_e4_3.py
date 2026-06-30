"""
E4.3 Phase 6 load, concurrency, and resource profiling benchmark.

The benchmark composes existing public AuthClaw surfaces through the Phase 3-5
benchmark fixtures:

* GatewayService.process_chat_request
* StreamingEngine.stream_response
* E4.4 audit export package builders and verification service

It performs no runtime optimization and does not modify Gateway, Streaming,
Audit Export, OPA, TokenVault, Trust Center, workers, provider adapters,
schemas, database models, APIs, Docker, Terraform, or frontend runtime code.

Usage from apps/api:
  python tests/performance/measure_load_e4_3.py --scenarios gateway_only_c5,mixed_workload_c5
"""
from __future__ import annotations

import argparse
import asyncio
import gc
import json
import sys
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[2]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.core.engine.streaming import StreamingEngine, StreamingMode
from app.core.performance.benchmark_contracts import (
    BenchmarkEnvironmentContract,
    BenchmarkResultContract,
    BenchmarkScenarioContract,
    ConcurrencyBenchmarkContract,
)
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
    PerformanceThresholdContract,
    ThroughputMeasurementContract,
)
from app.core.performance.system_snapshot import environment_snapshot
from app.core.performance.timer import HighResolutionTimer
from tests.performance.measure_audit_export_e4_3 import (
    AuditExportBenchmarkScenario,
    execute_audit_export_operation,
    seed_repository,
)
from tests.performance.measure_gateway_e4_3 import (
    DEFAULT_UPSTREAM_DELAY_MS,
    GatewayBenchmarkPatch,
    GatewayBenchmarkService,
    gateway_benchmark_scenarios,
)
from tests.performance.measure_streaming_e4_3 import (
    FakeAdapter,
    FakeAuditEngine,
    StreamingBenchmarkPatch,
    chunks_for_scenario,
    compiled_policy_for,
    streaming_benchmark_scenarios,
)


CONCURRENCY_LEVELS = (1, 5, 10, 25, 50, 100)
LOAD_P95_THRESHOLD = PerformanceThresholdContract(
    metric="load_benchmark_p95_ms",
    value=5000,
    unit=BenchmarkUnit.MILLISECONDS,
    source_requirement="E4.3",
    description="Observation threshold for local mocked load benchmark latency.",
)


@dataclass(frozen=True)
class LoadBenchmarkScenario:
    slug: str
    name: str
    description: str
    workload: str
    concurrency: int
    payload_profile: str
    record_count: int = 10
    tenant_count: int = 1
    gateway_slug: str = "small_request"
    streaming_slug: str = "small_stream"
    audit_slug: str = "records_10"
    policy_mode: str = "allow"
    tokenization_enabled: bool = False

    def contract(self) -> BenchmarkScenarioContract:
        return BenchmarkScenarioContract(
            scenario_id=BenchmarkScenarioId.CONCURRENT_GATEWAY_REQUESTS,
            target=BenchmarkTarget.CONCURRENCY,
            kind=BenchmarkKind.CONCURRENCY,
            name=self.name,
            description=self.description,
            payload_profile=self.payload_profile,
            iterations=self.concurrency,
            warmups=0,
            concurrency=self.concurrency,
            metadata={
                "slug": self.slug,
                "workload": self.workload,
                "record_count": self.record_count,
                "tenant_count": self.tenant_count,
                "gateway_slug": self.gateway_slug,
                "streaming_slug": self.streaming_slug,
                "audit_slug": self.audit_slug,
                "policy_mode": self.policy_mode,
                "tokenization_enabled": self.tokenization_enabled,
            },
        )


@dataclass(frozen=True)
class LoadBenchmarkReport:
    scenario: BenchmarkScenarioContract
    result: BenchmarkResultContract
    throughput: ThroughputMeasurementContract
    memory: MemoryMeasurementContract
    cpu: CpuMeasurementContract
    wall_time_ms: float
    successful_operations: int
    failed_operations: int
    gc_observations: dict[str, object]
    resource_profile: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        benchmark = self.result.benchmark
        return {
            "scenario": self.scenario.model_dump(mode="json"),
            "result": self.result.model_dump(mode="json"),
            "throughput": self.throughput.model_dump(mode="json"),
            "memory": self.memory.model_dump(mode="json"),
            "cpu": self.cpu.model_dump(mode="json"),
            "wall_time_ms": self.wall_time_ms,
            "successful_operations": self.successful_operations,
            "failed_operations": self.failed_operations,
            "gc_observations": self.gc_observations,
            "resource_profile": self.resource_profile,
            "sample_count": benchmark.metadata.sample_count,
        }


@dataclass(frozen=True)
class PreparedLoadOperation:
    operation: Callable[[int], Awaitable[None]]
    cleanup: Callable[[], None] | None = None


def load_benchmark_scenarios() -> tuple[LoadBenchmarkScenario, ...]:
    scenarios: list[LoadBenchmarkScenario] = []
    for level in CONCURRENCY_LEVELS:
        scenarios.extend(
            [
                LoadBenchmarkScenario(
                    slug=f"gateway_only_c{level}",
                    name=f"Gateway only concurrency {level}",
                    description="Concurrent mocked Gateway requests.",
                    workload="gateway",
                    concurrency=level,
                    payload_profile="gateway_only",
                ),
                LoadBenchmarkScenario(
                    slug=f"streaming_only_c{level}",
                    name=f"Streaming only concurrency {level}",
                    description="Concurrent mocked StreamingEngine sessions.",
                    workload="streaming",
                    concurrency=level,
                    payload_profile="streaming_only",
                ),
                LoadBenchmarkScenario(
                    slug=f"audit_export_only_c{level}",
                    name=f"Audit export only concurrency {level}",
                    description="Concurrent E4.4 audit export package generation.",
                    workload="audit_export",
                    concurrency=level,
                    payload_profile="audit_export_only",
                    record_count=10,
                ),
                LoadBenchmarkScenario(
                    slug=f"mixed_workload_c{level}",
                    name=f"Mixed workload concurrency {level}",
                    description="Concurrent Gateway, Streaming, and Audit Export workload mix.",
                    workload="mixed",
                    concurrency=level,
                    payload_profile="mixed_workload",
                    record_count=10,
                ),
            ]
        )
    scenarios.extend(
        [
            LoadBenchmarkScenario(
                slug="large_payload_c10",
                name="Gateway large payload concurrency 10",
                description="Concurrent Gateway requests with large payload profile.",
                workload="gateway",
                concurrency=10,
                payload_profile="large_payload",
                gateway_slug="large_request",
            ),
            LoadBenchmarkScenario(
                slug="long_running_stream_c5",
                name="Long-running stream concurrency 5",
                description="Concurrent long-running mocked stream sessions.",
                workload="streaming",
                concurrency=5,
                payload_profile="long_running_stream",
                streaming_slug="long_running_stream",
            ),
            LoadBenchmarkScenario(
                slug="large_audit_package_c5",
                name="Large audit package concurrency 5",
                description="Concurrent audit export generation with larger package size.",
                workload="audit_export",
                concurrency=5,
                payload_profile="large_audit_package",
                record_count=250,
                audit_slug="records_250",
            ),
            LoadBenchmarkScenario(
                slug="multiple_tenants_c10",
                name="Multiple tenants concurrency 10",
                description="Concurrent Gateway requests distributed across deterministic tenant fixtures.",
                workload="gateway",
                concurrency=10,
                payload_profile="multiple_tenants",
                gateway_slug="multiple_tenants",
                tenant_count=2,
            ),
            LoadBenchmarkScenario(
                slug="policy_allow_c10",
                name="Policy allow concurrency 10",
                description="Concurrent Gateway policy allow workload.",
                workload="gateway",
                concurrency=10,
                payload_profile="policy_allow",
                gateway_slug="policy_allow",
                policy_mode="allow",
            ),
            LoadBenchmarkScenario(
                slug="policy_block_c10",
                name="Policy block concurrency 10",
                description="Concurrent Gateway policy block workload.",
                workload="gateway",
                concurrency=10,
                payload_profile="policy_block",
                gateway_slug="policy_block",
                policy_mode="block",
            ),
            LoadBenchmarkScenario(
                slug="tokenization_enabled_c5",
                name="Streaming tokenization concurrency 5",
                description="Concurrent streaming sessions with existing reversible tokenization path.",
                workload="streaming",
                concurrency=5,
                payload_profile="tokenization_enabled",
                streaming_slug="tokenization_enabled",
                tokenization_enabled=True,
            ),
        ]
    )
    return tuple(scenarios)


async def run_load_benchmarks(
    *,
    scenarios: Iterable[LoadBenchmarkScenario] | None = None,
) -> tuple[LoadBenchmarkReport, ...]:
    environment = environment_snapshot(name="e4.3-load-performance", authclaw_version="v0.10.0")
    selected = tuple(scenarios or _default_smoke_scenarios())
    return tuple([await _measure_load_scenario(scenario, environment) for scenario in selected])


def summarize_load_benchmarks(reports: Iterable[LoadBenchmarkReport]) -> BenchmarkSummaryContract:
    reports_tuple = tuple(reports)
    passed = sum(1 for report in reports_tuple if report.failed_operations == 0)
    failed = len(reports_tuple) - passed
    return BenchmarkSummaryContract(
        summary_id=uuid.uuid4(),
        assessment=BenchmarkAssessment.PASS if failed == 0 else BenchmarkAssessment.PARTIAL,
        total_scenarios=len(reports_tuple),
        passed_scenarios=passed,
        failed_scenarios=failed,
        thresholds=(LOAD_P95_THRESHOLD,),
        metadata={
            "concurrency_levels": list(CONCURRENCY_LEVELS),
            "workloads": sorted({str(report.scenario.metadata["workload"]) for report in reports_tuple}),
        },
    )


async def _measure_load_scenario(
    scenario: LoadBenchmarkScenario,
    environment: BenchmarkEnvironmentContract,
) -> LoadBenchmarkReport:
    prepared = await _operation_for_scenario(scenario)
    latency = LatencySampleCollector()
    memory = MemorySampleCollector()
    cpu = CpuSampleCollector()
    memory_sampler = TracemallocMemorySampler()
    cpu_sampler = ProcessCpuSampler()
    gc_before = gc.get_count()
    started_at = datetime.now(UTC)
    memory_sampler.start()
    cpu_sampler.start()
    wall_timer = HighResolutionTimer().start()

    async def measured(index: int) -> tuple[bool, float]:
        timer = HighResolutionTimer().start()
        try:
            await prepared.operation(index)
            return True, timer.stop().elapsed_ms
        except Exception:
            return False, timer.stop().elapsed_ms

    try:
        outcomes = await asyncio.gather(*(measured(index) for index in range(scenario.concurrency)))
    finally:
        if prepared.cleanup is not None:
            prepared.cleanup()
    wall_time_ms = wall_timer.stop().elapsed_ms
    memory.add(memory_sampler.sample_peak_bytes())
    cpu.add(cpu_sampler.sample_percent())
    memory_sampler.stop()
    gc_after = gc.get_count()
    completed_at = datetime.now(UTC)

    successes = 0
    failures = 0
    for ok, elapsed_ms in outcomes:
        latency.add(elapsed_ms)
        if ok:
            successes += 1
        else:
            failures += 1

    contract = scenario.contract()
    metadata = BenchmarkMetadataContract(
        iterations=scenario.concurrency,
        warmups=0,
        sample_count=len(latency.samples_ms),
        started_at=started_at,
        completed_at=completed_at,
        labels={
            "scenario": scenario.slug,
            "workload": scenario.workload,
            "runtime_mutation": "false",
        },
    )
    concurrency_result = ConcurrencyBenchmarkContract(
        benchmark_id=uuid.uuid4(),
        scenario=contract,
        environment=environment,
        metadata=metadata,
        thresholds=(LOAD_P95_THRESHOLD,),
        concurrent_clients=scenario.concurrency,
        successful_operations=successes,
        failed_operations=failures,
        latency=latency.statistics(),
        throughput=throughput_measurement(
            total_operations=successes,
            wall_time_ms=wall_time_ms,
            unit=BenchmarkUnit.REQUESTS_PER_SECOND,
        ),
    )
    result = BenchmarkResultContract(
        result_id=uuid.uuid4(),
        benchmark=concurrency_result,
        notes=(
            "Concurrent workload measured with mocked external dependencies.",
            "Runtime implementation code is unchanged.",
        ),
    )
    return LoadBenchmarkReport(
        scenario=contract,
        result=result,
        throughput=concurrency_result.throughput,
        memory=memory.measurement(),
        cpu=cpu.measurement(),
        wall_time_ms=wall_time_ms,
        successful_operations=successes,
        failed_operations=failures,
        gc_observations={
            "before": gc_before,
            "after": gc_after,
            "delta": tuple(after - before for before, after in zip(gc_before, gc_after)),
        },
        resource_profile=_resource_profile(scenario),
    )


async def _operation_for_scenario(
    scenario: LoadBenchmarkScenario,
) -> PreparedLoadOperation:
    if scenario.workload == "gateway":
        return await _gateway_operation_factory(scenario)
    if scenario.workload == "streaming":
        return await _streaming_operation_factory(scenario)
    if scenario.workload == "audit_export":
        return await _audit_export_operation_factory(scenario)
    if scenario.workload == "mixed":
        gateway = await _gateway_operation_factory(scenario)
        streaming = await _streaming_operation_factory(scenario)
        audit_export = await _audit_export_operation_factory(scenario)

        async def mixed(index: int) -> None:
            selected = index % 3
            if selected == 0:
                await gateway.operation(index)
            elif selected == 1:
                await streaming.operation(index)
            else:
                await audit_export.operation(index)

        def cleanup() -> None:
            for prepared in (gateway, streaming, audit_export):
                if prepared.cleanup is not None:
                    prepared.cleanup()

        return PreparedLoadOperation(mixed, cleanup)
    raise ValueError(f"unsupported_load_workload:{scenario.workload}")


async def _gateway_operation_factory(
    scenario: LoadBenchmarkScenario,
) -> PreparedLoadOperation:
    gateway_scenario = _gateway_scenario(scenario.gateway_slug)
    patch = GatewayBenchmarkPatch()
    patch.install()

    async def operation(index: int) -> None:
        service = GatewayBenchmarkService(gateway_scenario, DEFAULT_UPSTREAM_DELAY_MS)
        if scenario.tenant_count > 1:
            service.tenant_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:load:{scenario.slug}:{index % scenario.tenant_count}")
            service.user_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:load-user:{scenario.slug}:{index % scenario.tenant_count}")
            service.api_key_id = uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:load-key:{scenario.slug}:{index}")
        await service.execute(gateway_scenario)

    return PreparedLoadOperation(operation, patch.restore)


async def _streaming_operation_factory(
    scenario: LoadBenchmarkScenario,
) -> PreparedLoadOperation:
    streaming_scenario = _streaming_scenario(scenario.streaming_slug)
    chunks = chunks_for_scenario(streaming_scenario)
    patch = StreamingBenchmarkPatch(compiled_policy_for(streaming_scenario))
    patch.install()

    async def operation(index: int) -> None:
        audit = FakeAuditEngine()
        adapter = FakeAdapter(chunks)
        engine = StreamingEngine(audit)  # type: ignore[arg-type]
        response = await engine.stream_response(
            tenant_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:load-stream:{scenario.slug}:{index}"),
            api_key_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:load-stream-key:{scenario.slug}:{index}"),
            provider_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:load-stream-provider:{scenario.slug}"),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [{"role": "user", "content": "benchmark"}], "stream": True},
            provider_name="mock",
            adapter=adapter,
            streaming_mode=StreamingMode.BUFFERED,
        )
        rendered = "".join([chunk async for chunk in response.body_iterator])
        if streaming_scenario.expected_blocked and "response_blocked" not in rendered:
            raise RuntimeError("expected_stream_block")
        if not streaming_scenario.expected_blocked and "data: [DONE]" not in rendered:
            raise RuntimeError("stream_missing_done")

    return PreparedLoadOperation(operation, patch.restore)


async def _audit_export_operation_factory(
    scenario: LoadBenchmarkScenario,
) -> PreparedLoadOperation:
    audit_scenario = AuditExportBenchmarkScenario(
        slug=scenario.audit_slug,
        name=f"Load {scenario.audit_slug}",
        description="Concurrent audit export load scenario.",
        record_count=scenario.record_count,
        operation="generation_verification",
    )
    repo = await seed_repository(audit_scenario.record_count, multi_tenant=scenario.tenant_count > 1)

    async def operation(_index: int) -> None:
        await execute_audit_export_operation(audit_scenario, repo)

    return PreparedLoadOperation(operation)


def _gateway_scenario(slug: str):
    for scenario in gateway_benchmark_scenarios():
        if scenario.slug == slug:
            return scenario
    raise ValueError(f"gateway_scenario_not_found:{slug}")


def _streaming_scenario(slug: str):
    for scenario in streaming_benchmark_scenarios():
        if scenario.slug == slug:
            return scenario
    raise ValueError(f"streaming_scenario_not_found:{slug}")


def _default_smoke_scenarios() -> tuple[LoadBenchmarkScenario, ...]:
    wanted = {"gateway_only_c5", "streaming_only_c5", "audit_export_only_c5", "mixed_workload_c5"}
    return tuple(scenario for scenario in load_benchmark_scenarios() if scenario.slug in wanted)


def _resource_profile(scenario: LoadBenchmarkScenario) -> dict[str, object]:
    if scenario.workload == "mixed":
        request_count = sum(1 for index in range(scenario.concurrency) if index % 3 == 0)
        stream_count = sum(1 for index in range(scenario.concurrency) if index % 3 == 1)
        export_count = sum(1 for index in range(scenario.concurrency) if index % 3 == 2)
    else:
        request_count = scenario.concurrency if scenario.workload == "gateway" else 0
        stream_count = scenario.concurrency if scenario.workload == "streaming" else 0
        export_count = scenario.concurrency if scenario.workload == "audit_export" else 0
    return {
        "concurrent_request_count": request_count,
        "concurrent_stream_count": stream_count,
        "concurrent_export_count": export_count,
        "tenant_count": scenario.tenant_count,
        "record_count": scenario.record_count,
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="AuthClaw E4.3 load/concurrency benchmark")
    parser.add_argument(
        "--scenarios",
        default="",
        help="Optional comma-separated scenario slugs. Defaults to c5 smoke scenarios.",
    )
    args = parser.parse_args()
    selected = None
    if args.scenarios:
        wanted = {item.strip() for item in args.scenarios.split(",") if item.strip()}
        selected = tuple(scenario for scenario in load_benchmark_scenarios() if scenario.slug in wanted)
    reports = await run_load_benchmarks(scenarios=selected)
    summary = summarize_load_benchmarks(reports)
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
