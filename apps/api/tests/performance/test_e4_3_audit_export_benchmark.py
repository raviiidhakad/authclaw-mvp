from __future__ import annotations

import json

import pytest

from app.core.audit.export_contracts import VerificationState
from app.core.performance.performance_enums import BenchmarkAssessment, BenchmarkScenarioId
from tests.performance.measure_audit_export_e4_3 import (
    AuditExportBenchmarkScenario,
    audit_export_benchmark_scenarios,
    run_audit_export_benchmarks,
    summarize_audit_export_benchmarks,
)


def test_audit_export_benchmark_scenario_registration() -> None:
    scenarios = audit_export_benchmark_scenarios()
    slugs = {scenario.slug for scenario in scenarios}

    assert {
        "records_10",
        "records_100",
        "records_250",
        "records_1000",
        "records_5000",
        "single_tenant",
        "multiple_tenants",
        "verification_only",
        "package_generation_only",
        "generation_verification",
        "tampered_package_verification",
    }.issubset(slugs)

    for scenario in scenarios:
        contract = scenario.contract(iterations=2, warmups=1)
        assert contract.metadata["record_count"] == scenario.record_count
        assert contract.metadata["operation"] == scenario.operation
        assert contract.metadata["provider"] == "in_memory_audit_repository"


@pytest.mark.asyncio
async def test_audit_export_benchmark_execution_collects_measurements() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("records_10"),),
    )

    report = reports[0]
    benchmark = report.latency_result.benchmark
    assert benchmark.metadata.sample_count == 1
    assert benchmark.latency.p50_ms >= 0
    assert report.throughput.value_per_second >= 0
    assert report.memory.peak_memory_bytes >= report.memory.minimum_memory_bytes
    assert report.cpu.peak_cpu_percent >= report.cpu.average_cpu_percent
    assert report.component_latency_ms["export_generation_ms"] >= 0
    assert report.component_latency_ms["manifest_generation_ms"] >= 0
    assert report.component_latency_ms["chain_proof_generation_ms"] >= 0
    assert report.component_latency_ms["signing_ms"] >= 0
    assert report.component_latency_ms["package_assembly_ms"] >= 0
    assert report.component_latency_ms["zip_generation_ms"] >= 0
    assert report.component_latency_ms["verification_ms"] >= 0
    assert report.package_size_bytes["minimum"] > 0
    assert report.verification_state == VerificationState.VERIFIED.value


@pytest.mark.asyncio
async def test_audit_export_package_generation_only_skips_verification_timing() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("package_generation_only"),),
    )

    report = reports[0]
    assert report.scenario.metadata["operation"] == "package_generation_only"
    assert report.component_latency_ms["package_assembly_ms"] >= 0
    assert report.component_latency_ms["verification_ms"] == 0
    assert report.package_size_bytes["minimum"] > 0


@pytest.mark.asyncio
async def test_audit_export_verification_only_uses_prebuilt_package() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("verification_only"),),
    )

    report = reports[0]
    assert report.scenario.metadata["operation"] == "verification_only"
    assert report.component_latency_ms["export_generation_ms"] == 0
    assert report.component_latency_ms["verification_ms"] >= 0
    assert report.verification_state == VerificationState.VERIFIED.value


@pytest.mark.asyncio
async def test_audit_export_tampered_package_verification_records_tampered_state() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("tampered_package_verification"),),
    )

    report = reports[0]
    assert report.scenario.metadata["expected_state"] == VerificationState.TAMPERED.value
    assert report.verification_state == VerificationState.TAMPERED.value
    assert report.component_latency_ms["verification_ms"] >= 0


@pytest.mark.asyncio
async def test_audit_export_multiple_tenants_remains_tenant_scoped() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("multiple_tenants"),),
    )

    report = reports[0]
    assert report.scenario.metadata["multi_tenant"] is True
    assert report.scenario.metadata["record_count"] == 100
    assert report.records_processed == 100
    assert report.verification_state == VerificationState.VERIFIED.value


@pytest.mark.asyncio
async def test_audit_export_benchmark_summary_generation() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("records_10"), _scenario("verification_only")),
    )

    summary = summarize_audit_export_benchmarks(reports)

    assert summary.total_scenarios == 2
    assert summary.assessment in {BenchmarkAssessment.PASS, BenchmarkAssessment.PARTIAL}
    assert summary.passed_scenarios + summary.failed_scenarios == 2
    assert summary.metadata["repository"] == "in_memory"


@pytest.mark.asyncio
async def test_audit_export_benchmark_result_serialization() -> None:
    reports = await run_audit_export_benchmarks(
        iterations=1,
        warmups=0,
        scenarios=(_scenario("records_10"),),
    )

    payload = reports[0].as_dict()

    assert payload["scenario"]["metadata"]["operation"] == "generation_verification"
    assert payload["package_size_bytes"]["minimum"] > 0
    json.dumps(payload, sort_keys=True)


@pytest.mark.asyncio
async def test_audit_export_benchmark_reproducibility_shape() -> None:
    scenario = _scenario("records_10")

    first = (await run_audit_export_benchmarks(iterations=1, warmups=0, scenarios=(scenario,)))[0]
    second = (await run_audit_export_benchmarks(iterations=1, warmups=0, scenarios=(scenario,)))[0]

    assert first.scenario.metadata["slug"] == second.scenario.metadata["slug"]
    assert first.records_processed == second.records_processed == 10
    assert first.package_size_bytes["minimum"] == second.package_size_bytes["minimum"]
    assert first.latency_result.benchmark.metadata.sample_count == second.latency_result.benchmark.metadata.sample_count


def _scenario(slug: str) -> AuditExportBenchmarkScenario:
    for scenario in audit_export_benchmark_scenarios():
        if scenario.slug == slug:
            return scenario
    raise AssertionError(f"scenario_not_found:{slug}")
