from __future__ import annotations

import json

import pytest

from app.core.performance.performance_enums import BenchmarkAssessment, BenchmarkScenarioId
from tests.performance.measure_load_e4_3 import (
    CONCURRENCY_LEVELS,
    LoadBenchmarkScenario,
    load_benchmark_scenarios,
    run_load_benchmarks,
    summarize_load_benchmarks,
)


def test_load_benchmark_scenario_registration() -> None:
    scenarios = load_benchmark_scenarios()
    slugs = {scenario.slug for scenario in scenarios}

    for level in CONCURRENCY_LEVELS:
        assert {
            f"gateway_only_c{level}",
            f"streaming_only_c{level}",
            f"audit_export_only_c{level}",
            f"mixed_workload_c{level}",
        }.issubset(slugs)

    assert {
        "large_payload_c10",
        "long_running_stream_c5",
        "large_audit_package_c5",
        "multiple_tenants_c10",
        "policy_allow_c10",
        "policy_block_c10",
        "tokenization_enabled_c5",
    }.issubset(slugs)

    for scenario in scenarios:
        contract = scenario.contract()
        assert contract.scenario_id == BenchmarkScenarioId.CONCURRENT_GATEWAY_REQUESTS
        assert contract.iterations == scenario.concurrency
        assert contract.concurrency == scenario.concurrency
        assert contract.metadata["slug"] == scenario.slug
        assert contract.metadata["workload"] == scenario.workload


@pytest.mark.asyncio
async def test_gateway_load_benchmark_collects_resource_metrics() -> None:
    report = (
        await run_load_benchmarks(
            scenarios=(
                LoadBenchmarkScenario(
                    slug="gateway_test_c2",
                    name="Gateway test concurrency 2",
                    description="Small concurrent Gateway smoke scenario.",
                    workload="gateway",
                    concurrency=2,
                    payload_profile="gateway_only",
                ),
            )
        )
    )[0]

    benchmark = report.result.benchmark
    assert benchmark.concurrent_clients == 2
    assert benchmark.successful_operations == 2
    assert benchmark.failed_operations == 0
    assert benchmark.metadata.sample_count == 2
    assert benchmark.latency is not None
    assert benchmark.latency.p95_ms >= 0
    assert report.throughput.value_per_second >= 0
    assert report.memory.peak_memory_bytes >= report.memory.minimum_memory_bytes
    assert report.cpu.peak_cpu_percent >= report.cpu.average_cpu_percent
    assert report.resource_profile["concurrent_request_count"] == 2
    assert report.gc_observations["delta"] is not None


@pytest.mark.asyncio
async def test_streaming_load_benchmark_collects_stream_counts() -> None:
    report = (
        await run_load_benchmarks(
            scenarios=(
                LoadBenchmarkScenario(
                    slug="streaming_test_c2",
                    name="Streaming test concurrency 2",
                    description="Tiny concurrent StreamingEngine smoke scenario.",
                    workload="streaming",
                    concurrency=2,
                    payload_profile="streaming_only",
                    streaming_slug="tiny_stream",
                ),
            )
        )
    )[0]

    assert report.successful_operations == 2
    assert report.failed_operations == 0
    assert report.resource_profile["concurrent_stream_count"] == 2
    assert report.resource_profile["concurrent_request_count"] == 0
    assert report.result.benchmark.metadata.labels["runtime_mutation"] == "false"


@pytest.mark.asyncio
async def test_audit_export_load_benchmark_collects_export_counts() -> None:
    report = (
        await run_load_benchmarks(
            scenarios=(
                LoadBenchmarkScenario(
                    slug="audit_export_test_c2",
                    name="Audit export test concurrency 2",
                    description="Small concurrent audit export smoke scenario.",
                    workload="audit_export",
                    concurrency=2,
                    payload_profile="audit_export_only",
                    record_count=10,
                    audit_slug="records_10",
                ),
            )
        )
    )[0]

    assert report.successful_operations == 2
    assert report.failed_operations == 0
    assert report.resource_profile["concurrent_export_count"] == 2
    assert report.resource_profile["record_count"] == 10


@pytest.mark.asyncio
async def test_mixed_load_benchmark_splits_workload_counts() -> None:
    report = (
        await run_load_benchmarks(
            scenarios=(
                LoadBenchmarkScenario(
                    slug="mixed_test_c3",
                    name="Mixed test concurrency 3",
                    description="Gateway, StreamingEngine, and audit export smoke scenario.",
                    workload="mixed",
                    concurrency=3,
                    payload_profile="mixed_workload",
                    streaming_slug="tiny_stream",
                    audit_slug="records_10",
                ),
            )
        )
    )[0]

    assert report.successful_operations == 3
    assert report.failed_operations == 0
    assert report.resource_profile["concurrent_request_count"] == 1
    assert report.resource_profile["concurrent_stream_count"] == 1
    assert report.resource_profile["concurrent_export_count"] == 1


@pytest.mark.asyncio
async def test_load_benchmark_policy_block_remains_successful_measurement() -> None:
    report = (
        await run_load_benchmarks(
            scenarios=(
                LoadBenchmarkScenario(
                    slug="policy_block_test_c2",
                    name="Policy block test concurrency 2",
                    description="Concurrent Gateway policy block scenario.",
                    workload="gateway",
                    concurrency=2,
                    payload_profile="policy_block",
                    gateway_slug="policy_block",
                    policy_mode="block",
                ),
            )
        )
    )[0]

    assert report.scenario.metadata["policy_mode"] == "block"
    assert report.successful_operations == 2
    assert report.failed_operations == 0


@pytest.mark.asyncio
async def test_load_benchmark_summary_generation() -> None:
    reports = await run_load_benchmarks(
        scenarios=(
            LoadBenchmarkScenario(
                slug="gateway_summary_c1",
                name="Gateway summary concurrency 1",
                description="Summary Gateway scenario.",
                workload="gateway",
                concurrency=1,
                payload_profile="gateway_only",
            ),
            LoadBenchmarkScenario(
                slug="streaming_summary_c1",
                name="Streaming summary concurrency 1",
                description="Summary StreamingEngine scenario.",
                workload="streaming",
                concurrency=1,
                payload_profile="streaming_only",
                streaming_slug="tiny_stream",
            ),
        )
    )

    summary = summarize_load_benchmarks(reports)

    assert summary.total_scenarios == 2
    assert summary.assessment in {BenchmarkAssessment.PASS, BenchmarkAssessment.PARTIAL}
    assert summary.passed_scenarios + summary.failed_scenarios == 2
    assert summary.metadata["concurrency_levels"] == list(CONCURRENCY_LEVELS)


@pytest.mark.asyncio
async def test_load_benchmark_result_serialization() -> None:
    report = (
        await run_load_benchmarks(
            scenarios=(
                LoadBenchmarkScenario(
                    slug="serialization_test_c1",
                    name="Serialization test concurrency 1",
                    description="Serializable Gateway scenario.",
                    workload="gateway",
                    concurrency=1,
                    payload_profile="gateway_only",
                ),
            )
        )
    )[0]

    payload = report.as_dict()

    assert payload["sample_count"] == 1
    assert payload["resource_profile"]["concurrent_request_count"] == 1
    json.dumps(payload, sort_keys=True)


@pytest.mark.asyncio
async def test_load_benchmark_reproducibility_shape() -> None:
    scenario = LoadBenchmarkScenario(
        slug="reproducible_c1",
        name="Reproducibility concurrency 1",
        description="Shape-stable Gateway scenario.",
        workload="gateway",
        concurrency=1,
        payload_profile="gateway_only",
    )

    first = (await run_load_benchmarks(scenarios=(scenario,)))[0]
    second = (await run_load_benchmarks(scenarios=(scenario,)))[0]

    assert first.scenario.metadata["slug"] == second.scenario.metadata["slug"]
    assert first.result.benchmark.metadata.sample_count == second.result.benchmark.metadata.sample_count
    assert first.resource_profile == second.resource_profile
