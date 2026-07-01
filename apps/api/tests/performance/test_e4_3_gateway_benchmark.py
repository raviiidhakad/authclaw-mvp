from __future__ import annotations

import json

import pytest

from app.core.performance.performance_enums import (
    BenchmarkAssessment,
    BenchmarkScenarioId,
    BenchmarkTarget,
)
from tests.performance.measure_gateway_e4_3 import (
    DEFAULT_UPSTREAM_DELAY_MS,
    GatewayBenchmarkScenario,
    gateway_benchmark_scenarios,
    format_gateway_benchmark_compact,
    run_gateway_benchmarks,
    summarize_gateway_benchmarks,
)


def test_gateway_benchmark_scenario_registration() -> None:
    scenarios = gateway_benchmark_scenarios()
    slugs = {scenario.slug for scenario in scenarios}

    assert {
        "small_request",
        "medium_request",
        "large_request",
        "policy_allow",
        "policy_redact",
        "policy_hash_redact",
        "policy_synthetic_redact",
        "policy_reversible_tokenization",
        "policy_block",
        "multiple_tenants",
        "provider_mock_error",
        "concurrent_requests",
    }.issubset(slugs)

    for scenario in scenarios:
        contract = scenario.contract(iterations=3, warmups=1)
        assert contract.metadata["stream"] is False
        assert contract.metadata["provider"] == "mock"
        assert contract.iterations == 3
        assert contract.warmups == 1


@pytest.mark.asyncio
async def test_gateway_benchmark_compact_formatter_is_stable() -> None:
    report = (
        await run_gateway_benchmarks(
            iterations=1,
            warmups=0,
            upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
            scenarios=(_scenario("small_request"),),
        )
    )[0]

    compact = format_gateway_benchmark_compact((report,))

    assert compact.splitlines()[0].startswith("slug,p50_overhead_ms")
    assert "small_request" in compact


@pytest.mark.asyncio
async def test_gateway_benchmark_execution_collects_measurements() -> None:
    scenario = _scenario("small_request")

    reports = await run_gateway_benchmarks(
        iterations=2,
        warmups=1,
        upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
        scenarios=(scenario,),
    )

    report = reports[0]
    benchmark = report.latency_result.benchmark
    assert benchmark.scenario.scenario_id == BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT
    assert benchmark.scenario.target == BenchmarkTarget.GATEWAY_LATENCY
    assert benchmark.metadata.sample_count == 2
    assert benchmark.latency.p50_ms >= 0
    assert benchmark.latency.p95_ms >= 0
    assert report.throughput.value_per_second >= 0
    assert report.memory.peak_memory_bytes >= report.memory.minimum_memory_bytes
    assert report.cpu.peak_cpu_percent >= report.cpu.average_cpu_percent
    assert report.provider_call_count == 3
    assert report.audit_call_count == 3


@pytest.mark.asyncio
async def test_gateway_benchmark_policy_block_does_not_call_provider() -> None:
    scenario = _scenario("policy_block")

    reports = await run_gateway_benchmarks(
        iterations=2,
        warmups=1,
        upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
        scenarios=(scenario,),
    )

    report = reports[0]
    assert report.latency_result.benchmark.metadata.sample_count == 2
    assert report.provider_call_count == 0
    assert report.audit_call_count == 0
    assert report.gateway_overhead_ms["p95_ms"] >= 0


@pytest.mark.asyncio
async def test_gateway_benchmark_summary_generation() -> None:
    reports = await run_gateway_benchmarks(
        iterations=1,
        warmups=0,
        upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
        scenarios=(_scenario("small_request"), _scenario("policy_redact")),
    )

    summary = summarize_gateway_benchmarks(reports)

    assert summary.total_scenarios == 2
    assert summary.assessment in {BenchmarkAssessment.PASS, BenchmarkAssessment.PARTIAL}
    assert summary.passed_scenarios + summary.failed_scenarios == 2
    assert summary.metadata["provider"] == "mock"


@pytest.mark.asyncio
async def test_gateway_benchmark_result_serialization() -> None:
    reports = await run_gateway_benchmarks(
        iterations=1,
        warmups=0,
        upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
        scenarios=(_scenario("policy_allow"),),
    )

    payload = reports[0].as_dict()

    assert payload["scenario"]["metadata"]["stream"] is False
    assert payload["tokenization_contribution_ms"] == "not_exercised"
    json.dumps(payload, sort_keys=True)


@pytest.mark.asyncio
async def test_gateway_benchmark_reproducibility_shape() -> None:
    scenario = _scenario("multiple_tenants")

    first = (
        await run_gateway_benchmarks(
            iterations=1,
            warmups=0,
            upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
            scenarios=(scenario,),
        )
    )[0]
    second = (
        await run_gateway_benchmarks(
            iterations=1,
            warmups=0,
            upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
            scenarios=(scenario,),
        )
    )[0]

    assert first.scenario.metadata["slug"] == second.scenario.metadata["slug"]
    assert first.scenario.metadata["tenant_label"] == "secondary"
    assert first.latency_result.benchmark.metadata.sample_count == second.latency_result.benchmark.metadata.sample_count
    assert first.provider_call_count == second.provider_call_count == 1


@pytest.mark.asyncio
async def test_gateway_benchmark_reversible_tokenization_uses_mocked_vault_path() -> None:
    report = (
        await run_gateway_benchmarks(
            iterations=1,
            warmups=0,
            upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
            scenarios=(_scenario("policy_reversible_tokenization"),),
        )
    )[0]

    assert report.tokenization_contribution_ms == "mocked_token_vault_store_batch_exercised"
    assert report.provider_call_count == 1


@pytest.mark.asyncio
async def test_gateway_benchmark_provider_error_is_reproducible() -> None:
    report = (
        await run_gateway_benchmarks(
            iterations=1,
            warmups=0,
            upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
            scenarios=(_scenario("provider_mock_error"),),
        )
    )[0]

    assert report.scenario.metadata["provider_status_code"] == 502
    assert report.provider_call_count == 1
    assert report.audit_call_count == 1


@pytest.mark.asyncio
async def test_gateway_benchmark_concurrent_scenario_records_concurrency() -> None:
    report = (
        await run_gateway_benchmarks(
            iterations=1,
            warmups=0,
            upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
            scenarios=(_scenario("concurrent_requests"),),
        )
    )[0]

    assert report.scenario.concurrency == 10
    assert report.scenario.metadata["slug"] == "concurrent_requests"
    assert report.provider_call_count == 10


def _scenario(slug: str) -> GatewayBenchmarkScenario:
    for scenario in gateway_benchmark_scenarios():
        if scenario.slug == slug:
            return scenario
    raise AssertionError(f"scenario_not_found:{slug}")
