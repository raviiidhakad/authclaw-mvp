from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.core.performance import benchmark_contracts as contracts
from app.core.performance import performance_enums as enums
from app.core.performance import performance_types as types


BENCHMARK_ID = UUID("11111111-1111-4111-8111-111111111111")
ENVIRONMENT_ID = UUID("22222222-2222-4222-8222-222222222222")
RESULT_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


def _environment() -> contracts.BenchmarkEnvironmentContract:
    return contracts.BenchmarkEnvironmentContract(
        environment_id=ENVIRONMENT_ID,
        name="local-contract-test",
        captured_at=NOW,
        hardware=types.HardwareMetadataContract(cpu_cores=8, memory_bytes=16_000_000_000),
        software=types.SoftwareVersionContract(authclaw_version="0.10.0", python_version="3.12"),
    )


def _scenario() -> contracts.BenchmarkScenarioContract:
    return contracts.BenchmarkScenarioContract(
        scenario_id=enums.BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT,
        target=enums.BenchmarkTarget.GATEWAY_LATENCY,
        kind=enums.BenchmarkKind.LATENCY,
        name="Gateway OpenAI-compatible chat latency",
        description="Contract-only scenario for gateway overhead measurement.",
        iterations=50,
        warmups=5,
        concurrency=1,
    )


def _metadata() -> types.BenchmarkMetadataContract:
    return types.BenchmarkMetadataContract(
        iterations=50,
        warmups=5,
        sample_count=50,
        started_at=NOW,
        completed_at=NOW,
        labels={"release": "v0.10.0"},
    )


def _latency() -> types.PercentileLatencyContract:
    return types.PercentileLatencyContract(
        minimum_ms=1.0,
        maximum_ms=12.0,
        average_ms=6.0,
        median_ms=5.5,
        p50_ms=5.5,
        p90_ms=9.0,
        p95_ms=10.0,
        p99_ms=12.0,
    )


def test_performance_contract_modules_are_non_executing_scaffolding():
    combined = "\n".join(
        inspect.getsource(module)
        for module in (contracts, enums, types)
    )

    assert "from app.core.engine.gateway" not in combined
    assert "from app.core.engine.streaming" not in combined
    assert "from app.core.engine.token_vault" not in combined
    assert "from app.core.policy" not in combined
    assert "from app.core.audit" not in combined
    assert "from app.core.providers" not in combined
    assert "from app.workers" not in combined
    assert "time.perf_counter" not in combined
    assert "tracemalloc" not in combined
    assert "psutil" not in combined


def test_schema_version_constants_are_stable_and_serializable():
    versions = types.VersionIdentifierContract()
    dumped = versions.model_dump(mode="json", by_alias=True)

    assert dumped == {
        "schema": "authclaw.performance.benchmark/v1",
        "schema_version": 1,
        "contract_version": 1,
    }
    json.dumps(dumped)


def test_enum_coverage_includes_pdf_performance_targets():
    assert {item.value for item in enums.BenchmarkTarget} >= {
        "gateway_latency",
        "gateway_throughput",
        "streaming_latency",
        "streaming_throughput",
        "audit_export_generation",
        "audit_verification",
        "opa_evaluation",
        "tokenization",
        "policy_evaluation",
        "provider_response",
        "memory",
        "cpu",
        "concurrency",
        "large_payloads",
        "large_streaming_sessions",
        "large_audit_exports",
    }
    assert enums.BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT.value == "gateway.openai_compat.chat"


def test_latency_benchmark_contract_serializes_required_fields_and_defaults():
    benchmark = contracts.LatencyBenchmarkContract(
        benchmark_id=BENCHMARK_ID,
        scenario=_scenario(),
        environment=_environment(),
        metadata=_metadata(),
        thresholds=(contracts.DEFAULT_GATEWAY_P95_THRESHOLD,),
        latency=_latency(),
    )

    dumped = benchmark.model_dump(mode="json", by_alias=True)
    json.dumps(dumped)

    assert dumped["versions"]["schema"] == "authclaw.performance.benchmark/v1"
    assert dumped["kind"] == "latency"
    assert dumped["scenario"]["scenario_id"] == "gateway.openai_compat.chat"
    assert dumped["scenario"]["target"] == "gateway_latency"
    assert dumped["environment"]["name"] == "local-contract-test"
    assert dumped["metadata"]["iterations"] == 50
    assert dumped["latency"]["p95_ms"] == 10.0
    assert dumped["thresholds"][0]["source_requirement"] == "NFR-1.1"


def test_threshold_defaults_represent_targets_without_enforcement():
    gateway = contracts.DEFAULT_GATEWAY_P95_THRESHOLD
    streaming = contracts.DEFAULT_STREAMING_P95_THRESHOLD

    assert gateway.metric == "gateway_overhead_p95_ms"
    assert gateway.value == 50
    assert gateway.unit == "ms"
    assert gateway.source_requirement == "NFR-1.1"
    assert streaming.metric == "streaming_overhead_p95_ms"
    assert streaming.source_requirement == "NFR-1.2"


def test_benchmark_result_envelope_accepts_latency_contract():
    benchmark = contracts.LatencyBenchmarkContract(
        benchmark_id=BENCHMARK_ID,
        scenario=_scenario(),
        environment=_environment(),
        metadata=_metadata(),
        latency=_latency(),
    )
    result = contracts.BenchmarkResultContract(
        result_id=RESULT_ID,
        benchmark=benchmark,
        notes=("contract-only",),
    )

    dumped = result.model_dump(mode="json", by_alias=True)

    assert dumped["result_id"] == str(RESULT_ID)
    assert dumped["benchmark"]["benchmark_id"] == str(BENCHMARK_ID)
    assert dumped["notes"] == ["contract-only"]


def test_throughput_concurrency_memory_and_cpu_contracts_construct():
    throughput = contracts.ThroughputBenchmarkContract(
        benchmark_id=BENCHMARK_ID,
        scenario=_scenario().model_copy(update={"kind": enums.BenchmarkKind.THROUGHPUT}),
        environment=_environment(),
        metadata=_metadata(),
        throughput=types.ThroughputMeasurementContract(
            unit=enums.BenchmarkUnit.REQUESTS_PER_SECOND,
            value_per_second=125.5,
            total_operations=500,
            wall_time_ms=4000,
        ),
    )
    concurrency = contracts.ConcurrencyBenchmarkContract(
        benchmark_id=BENCHMARK_ID,
        scenario=_scenario().model_copy(update={"kind": enums.BenchmarkKind.CONCURRENCY}),
        environment=_environment(),
        metadata=_metadata(),
        concurrent_clients=25,
        successful_operations=1000,
        failed_operations=0,
    )
    memory = contracts.MemoryBenchmarkContract(
        benchmark_id=BENCHMARK_ID,
        scenario=_scenario().model_copy(update={"kind": enums.BenchmarkKind.MEMORY}),
        environment=_environment(),
        metadata=_metadata(),
        memory=types.MemoryMeasurementContract(
            peak_memory_bytes=4096,
            average_memory_bytes=2048,
            minimum_memory_bytes=1024,
        ),
    )
    cpu = contracts.CpuBenchmarkContract(
        benchmark_id=BENCHMARK_ID,
        scenario=_scenario().model_copy(update={"kind": enums.BenchmarkKind.CPU}),
        environment=_environment(),
        metadata=_metadata(),
        cpu=types.CpuMeasurementContract(peak_cpu_percent=75.5, average_cpu_percent=42.0),
    )

    assert throughput.kind == "throughput"
    assert concurrency.concurrent_clients == 25
    assert memory.memory.peak_memory_bytes == 4096
    assert cpu.cpu.average_cpu_percent == 42.0


def test_summary_and_recommendation_contracts_are_serializable():
    recommendation = types.OptimizationRecommendationContract(
        recommendation_id="perf-rec-001",
        priority=enums.RecommendationPriority.HIGH,
        target_area="gateway",
        summary="Investigate p95 latency if future measurements exceed threshold.",
        evidence="No measurement executed by this contract.",
    )
    summary = types.BenchmarkSummaryContract(
        summary_id=RESULT_ID,
        total_scenarios=1,
        recommendations=(recommendation,),
        thresholds=(contracts.DEFAULT_GATEWAY_P95_THRESHOLD,),
    )

    dumped = summary.model_dump(mode="json", by_alias=True)
    json.dumps(dumped)

    assert dumped["assessment"] == "not_evaluated"
    assert dumped["recommendations"][0]["priority"] == "high"
    assert dumped["thresholds"][0]["metric"] == "gateway_overhead_p95_ms"


def test_contract_models_are_frozen_and_reject_unknown_fields():
    versions = types.VersionIdentifierContract()

    with pytest.raises(ValidationError):
        versions.schema_version = 2

    with pytest.raises(ValidationError):
        types.PercentileLatencyContract(
            minimum_ms=1,
            maximum_ms=2,
            average_ms=1.5,
            median_ms=1.5,
            p50_ms=1.5,
            p90_ms=1.8,
            p95_ms=1.9,
            p99_ms=2,
            unexpected="blocked",
        )

