from __future__ import annotations

import json

import pytest

from app.core.performance.performance_enums import BenchmarkAssessment, BenchmarkScenarioId
from tests.performance.measure_streaming_e4_3 import (
    StreamingBenchmarkScenario,
    chunks_for_scenario,
    run_streaming_benchmarks,
    streaming_benchmark_scenarios,
    summarize_streaming_benchmarks,
)


def test_streaming_benchmark_scenario_registration() -> None:
    scenarios = streaming_benchmark_scenarios()
    slugs = {scenario.slug for scenario in scenarios}

    assert {
        "tiny_stream",
        "small_stream",
        "medium_stream",
        "large_stream",
        "very_large_stream",
        "long_running_stream",
        "chunk_boundary_stress",
        "utf8_split_boundaries",
        "sse_multiline_events",
        "policy_allow",
        "policy_redact",
        "policy_block",
        "tokenization_enabled",
        "tokenization_disabled",
    }.issubset(slugs)

    for scenario in scenarios:
        contract = scenario.contract(iterations=2, warmups=1)
        assert contract.scenario_id == BenchmarkScenarioId.STREAMING_SAFE_SSE
        assert contract.metadata["provider"] == "mock"
        assert contract.metadata["streaming_mode"] == "buffered"
        assert contract.iterations == 2
        assert contract.warmups == 1


def test_streaming_benchmark_chunk_generation_covers_boundary_cases() -> None:
    utf8 = _scenario("utf8_split_boundaries")
    boundary = _scenario("chunk_boundary_stress")
    multiline = _scenario("sse_multiline_events")

    assert len(chunks_for_scenario(utf8)) > utf8.event_count
    assert len(chunks_for_scenario(boundary)) > boundary.event_count
    assert any(chunk.startswith(b": benchmark-comment") for chunk in chunks_for_scenario(multiline))


@pytest.mark.asyncio
async def test_streaming_benchmark_execution_collects_measurements() -> None:
    reports = await run_streaming_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("tiny_stream"),),
    )

    report = reports[0]
    benchmark = report.latency_result.benchmark
    assert benchmark.metadata.sample_count == 1
    assert benchmark.latency.p50_ms >= 0
    assert report.event_throughput.value_per_second >= 0
    assert report.chunk_throughput.value_per_second >= 0
    assert report.memory.peak_memory_bytes >= report.memory.minimum_memory_bytes
    assert report.cpu.peak_cpu_percent >= report.cpu.average_cpu_percent
    assert report.component_latency_ms["utf8_decode_ms"] >= 0
    assert report.component_latency_ms["sse_parse_ms"] >= 0
    assert report.component_latency_ms["state_machine_ms"] >= 0
    assert report.audit_started_count == 1
    assert report.audit_completed_count == 1
    assert report.audit_failed_count == 0


@pytest.mark.asyncio
async def test_streaming_benchmark_policy_block_records_failed_stream() -> None:
    reports = await run_streaming_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("policy_block"),),
    )

    report = reports[0]
    assert report.scenario.metadata["expected_blocked"] is True
    assert report.audit_started_count == 1
    assert report.audit_completed_count == 0
    assert report.audit_failed_count == 1


@pytest.mark.asyncio
async def test_streaming_benchmark_tokenization_enabled_observes_token_vault() -> None:
    reports = await run_streaming_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("tokenization_enabled"),),
    )

    report = reports[0]
    assert report.tokenization_contribution_ms["enabled"] is True
    assert report.tokenization_contribution_ms["store_batch_calls"] == 1


@pytest.mark.asyncio
async def test_streaming_benchmark_summary_generation() -> None:
    reports = await run_streaming_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("tiny_stream"), _scenario("policy_allow")),
    )

    summary = summarize_streaming_benchmarks(reports)

    assert summary.total_scenarios == 2
    assert summary.assessment in {BenchmarkAssessment.PASS, BenchmarkAssessment.PARTIAL}
    assert summary.passed_scenarios + summary.failed_scenarios == 2
    assert summary.metadata["provider"] == "mock"


@pytest.mark.asyncio
async def test_streaming_benchmark_result_serialization() -> None:
    reports = await run_streaming_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("policy_redact"),),
    )

    payload = reports[0].as_dict()

    assert payload["scenario"]["metadata"]["streaming_mode"] == "buffered"
    assert payload["policy_contribution_ms"]["policy_enabled"] is True
    json.dumps(payload, sort_keys=True)


@pytest.mark.asyncio
async def test_streaming_benchmark_reproducibility_shape() -> None:
    scenario = _scenario("chunk_boundary_stress")

    first = (
        await run_streaming_benchmarks(iterations=1, warmups=0, scenarios=(scenario,))
    )[0]
    second = (
        await run_streaming_benchmarks(iterations=1, warmups=0, scenarios=(scenario,))
    )[0]

    assert first.scenario.metadata["slug"] == second.scenario.metadata["slug"]
    assert first.chunks_processed == second.chunks_processed
    assert first.events_processed == second.events_processed
    assert first.latency_result.benchmark.metadata.sample_count == second.latency_result.benchmark.metadata.sample_count


def _scenario(slug: str) -> StreamingBenchmarkScenario:
    for scenario in streaming_benchmark_scenarios():
        if scenario.slug == slug:
            return scenario
    raise AssertionError(f"scenario_not_found:{slug}")
