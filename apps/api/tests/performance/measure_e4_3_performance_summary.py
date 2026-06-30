"""
E4.3 Phase 7 consolidated performance closeout benchmark.

This script composes the Phase 3-6 benchmark harnesses and normalizes their
outputs into one release-readiness summary. It does not optimize, tune, cache,
or modify Gateway, Streaming, Audit Export, OPA, TokenVault, Trust Center,
workers, providers, schemas, database models, APIs, Docker, Terraform, or
frontend runtime behavior.

Usage from apps/api:
  python tests/performance/measure_e4_3_performance_summary.py --iterations 2 --warmups 1
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

API_ROOT = Path(__file__).resolve().parents[2]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.core.performance.performance_enums import BenchmarkAssessment
from tests.performance.measure_audit_export_e4_3 import (
    AuditExportBenchmarkReport,
    audit_export_benchmark_scenarios,
    run_audit_export_benchmarks,
    summarize_audit_export_benchmarks,
)
from tests.performance.measure_gateway_e4_3 import (
    DEFAULT_UPSTREAM_DELAY_MS,
    GatewayBenchmarkReport,
    gateway_benchmark_scenarios,
    run_gateway_benchmarks,
    summarize_gateway_benchmarks,
)
from tests.performance.measure_load_e4_3 import (
    LoadBenchmarkReport,
    load_benchmark_scenarios,
    run_load_benchmarks,
    summarize_load_benchmarks,
)
from tests.performance.measure_streaming_e4_3 import (
    StreamingBenchmarkReport,
    run_streaming_benchmarks,
    streaming_benchmark_scenarios,
    summarize_streaming_benchmarks,
)


DEFAULT_GATEWAY_CLOSEOUT_SCENARIOS = (
    "small_request",
    "policy_allow",
    "policy_redact",
    "policy_block",
)
DEFAULT_STREAMING_CLOSEOUT_SCENARIOS = (
    "tiny_stream",
    "utf8_split_boundaries",
    "policy_redact",
    "tokenization_enabled",
)
DEFAULT_AUDIT_CLOSEOUT_SCENARIOS = (
    "records_10",
    "records_250",
    "generation_verification",
    "tampered_package_verification",
)
DEFAULT_LOAD_CLOSEOUT_SCENARIOS = (
    "gateway_only_c5",
    "streaming_only_c5",
    "audit_export_only_c5",
    "mixed_workload_c5",
)


@dataclass(frozen=True)
class AreaPerformanceSummary:
    area: str
    assessment: str
    scenario_count: int
    passed_scenarios: int
    failed_scenarios: int
    metrics: dict[str, Any]
    scenarios: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "area": self.area,
            "assessment": self.assessment,
            "scenario_count": self.scenario_count,
            "passed_scenarios": self.passed_scenarios,
            "failed_scenarios": self.failed_scenarios,
            "metrics": self.metrics,
            "scenarios": list(self.scenarios),
        }


@dataclass(frozen=True)
class RequirementAssessment:
    requirement: str
    status: str
    evidence: str
    limitation: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "requirement": self.requirement,
            "status": self.status,
            "evidence": self.evidence,
            "limitation": self.limitation,
        }


@dataclass(frozen=True)
class E43PerformanceCloseoutSummary:
    generated_at: datetime
    methodology: dict[str, Any]
    gateway: AreaPerformanceSummary
    streaming: AreaPerformanceSummary
    audit_export: AreaPerformanceSummary
    load: AreaPerformanceSummary
    requirement_traceability: tuple[RequirementAssessment, ...]
    limitations: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "methodology": self.methodology,
            "gateway": self.gateway.as_dict(),
            "streaming": self.streaming.as_dict(),
            "audit_export": self.audit_export.as_dict(),
            "load": self.load.as_dict(),
            "requirement_traceability": [item.as_dict() for item in self.requirement_traceability],
            "limitations": list(self.limitations),
        }


async def run_e4_3_closeout_summary(
    *,
    iterations: int = 2,
    warmups: int = 1,
    gateway_slugs: Iterable[str] = DEFAULT_GATEWAY_CLOSEOUT_SCENARIOS,
    streaming_slugs: Iterable[str] = DEFAULT_STREAMING_CLOSEOUT_SCENARIOS,
    audit_slugs: Iterable[str] = DEFAULT_AUDIT_CLOSEOUT_SCENARIOS,
    load_slugs: Iterable[str] = DEFAULT_LOAD_CLOSEOUT_SCENARIOS,
) -> E43PerformanceCloseoutSummary:
    gateway_reports = await run_gateway_benchmarks(
        iterations=iterations,
        warmups=warmups,
        upstream_delay_ms=DEFAULT_UPSTREAM_DELAY_MS,
        scenarios=_select_gateway_scenarios(gateway_slugs),
    )
    streaming_reports = await run_streaming_benchmarks(
        iterations=iterations,
        warmups=warmups,
        scenarios=_select_streaming_scenarios(streaming_slugs),
    )
    audit_reports = await run_audit_export_benchmarks(
        iterations=iterations,
        warmups=warmups,
        scenarios=_select_audit_scenarios(audit_slugs),
    )
    load_reports = await run_load_benchmarks(
        scenarios=_select_load_scenarios(load_slugs),
    )

    gateway_summary = _gateway_area_summary(gateway_reports)
    streaming_summary = _streaming_area_summary(streaming_reports)
    audit_summary = _audit_area_summary(audit_reports)
    load_summary = _load_area_summary(load_reports)
    return E43PerformanceCloseoutSummary(
        generated_at=datetime.now(UTC),
        methodology={
            "authclaw_release": "v0.10.0",
            "branch": "feature/e4.3-performance",
            "iterations": iterations,
            "warmups": warmups,
            "provider_mode": "mocked",
            "audit_repository": "in_memory",
            "runtime_mutation": False,
            "external_network_calls": False,
        },
        gateway=gateway_summary,
        streaming=streaming_summary,
        audit_export=audit_summary,
        load=load_summary,
        requirement_traceability=_requirement_traceability(
            gateway_summary,
            streaming_summary,
            audit_summary,
            load_summary,
        ),
        limitations=(
            "Benchmarks use mocked providers and in-memory audit repositories.",
            "Production network, database, Redis, ClickHouse, Vault, and KMS/HSM latency are not measured by this local harness.",
            "No runtime optimization or algorithm change is performed by E4.3.",
            "Per-scenario standard deviation is not retained by Phase 3-6 reports; closeout reports standard deviation across scenario p95 values.",
        ),
    )


def _gateway_area_summary(reports: tuple[GatewayBenchmarkReport, ...]) -> AreaPerformanceSummary:
    summary = summarize_gateway_benchmarks(reports)
    scenario_metrics = []
    for report in reports:
        latency = report.latency_result.benchmark.latency
        scenario_metrics.append(
            {
                "slug": report.scenario.metadata["slug"],
                "p50_ms": latency.p50_ms,
                "p90_ms": latency.p90_ms,
                "p95_ms": latency.p95_ms,
                "p99_ms": latency.p99_ms,
                "average_ms": latency.average_ms,
                "median_ms": latency.median_ms,
                "minimum_ms": latency.minimum_ms,
                "maximum_ms": latency.maximum_ms,
                "overhead_p95_ms": report.gateway_overhead_ms["p95_ms"],
                "throughput_per_second": report.throughput.value_per_second,
                "peak_memory_bytes": report.memory.peak_memory_bytes,
                "average_memory_bytes": report.memory.average_memory_bytes,
                "peak_cpu_percent": report.cpu.peak_cpu_percent,
                "provider_call_count": report.provider_call_count,
                "audit_call_count": report.audit_call_count,
            }
        )
    return _area_summary("gateway", summary.assessment, summary.passed_scenarios, summary.failed_scenarios, scenario_metrics)


def _streaming_area_summary(reports: tuple[StreamingBenchmarkReport, ...]) -> AreaPerformanceSummary:
    summary = summarize_streaming_benchmarks(reports)
    scenario_metrics = []
    for report in reports:
        latency = report.latency_result.benchmark.latency
        scenario_metrics.append(
            {
                "slug": report.scenario.metadata["slug"],
                "p50_ms": latency.p50_ms,
                "p90_ms": latency.p90_ms,
                "p95_ms": latency.p95_ms,
                "p99_ms": latency.p99_ms,
                "average_ms": latency.average_ms,
                "median_ms": latency.median_ms,
                "minimum_ms": latency.minimum_ms,
                "maximum_ms": latency.maximum_ms,
                "event_throughput_per_second": report.event_throughput.value_per_second,
                "chunk_throughput_per_second": report.chunk_throughput.value_per_second,
                "peak_memory_bytes": report.memory.peak_memory_bytes,
                "average_memory_bytes": report.memory.average_memory_bytes,
                "peak_cpu_percent": report.cpu.peak_cpu_percent,
                "events_processed": report.events_processed,
                "chunks_processed": report.chunks_processed,
                "component_latency_ms": report.component_latency_ms,
            }
        )
    return _area_summary("streaming", summary.assessment, summary.passed_scenarios, summary.failed_scenarios, scenario_metrics)


def _audit_area_summary(reports: tuple[AuditExportBenchmarkReport, ...]) -> AreaPerformanceSummary:
    summary = summarize_audit_export_benchmarks(reports)
    scenario_metrics = []
    for report in reports:
        latency = report.latency_result.benchmark.latency
        scenario_metrics.append(
            {
                "slug": report.scenario.metadata["slug"],
                "p50_ms": latency.p50_ms,
                "p90_ms": latency.p90_ms,
                "p95_ms": latency.p95_ms,
                "p99_ms": latency.p99_ms,
                "average_ms": latency.average_ms,
                "median_ms": latency.median_ms,
                "minimum_ms": latency.minimum_ms,
                "maximum_ms": latency.maximum_ms,
                "throughput_per_second": report.throughput.value_per_second,
                "peak_memory_bytes": report.memory.peak_memory_bytes,
                "average_memory_bytes": report.memory.average_memory_bytes,
                "peak_cpu_percent": report.cpu.peak_cpu_percent,
                "records_processed": report.records_processed,
                "package_size_bytes": report.package_size_bytes,
                "verification_state": report.verification_state,
                "component_latency_ms": report.component_latency_ms,
            }
        )
    return _area_summary("audit_export", summary.assessment, summary.passed_scenarios, summary.failed_scenarios, scenario_metrics)


def _load_area_summary(reports: tuple[LoadBenchmarkReport, ...]) -> AreaPerformanceSummary:
    summary = summarize_load_benchmarks(reports)
    scenario_metrics = []
    for report in reports:
        latency = report.result.benchmark.latency
        if latency is None:
            raise ValueError("load_report_missing_latency")
        scenario_metrics.append(
            {
                "slug": report.scenario.metadata["slug"],
                "workload": report.scenario.metadata["workload"],
                "concurrency": report.scenario.concurrency,
                "p50_ms": latency.p50_ms,
                "p90_ms": latency.p90_ms,
                "p95_ms": latency.p95_ms,
                "p99_ms": latency.p99_ms,
                "average_ms": latency.average_ms,
                "median_ms": latency.median_ms,
                "minimum_ms": latency.minimum_ms,
                "maximum_ms": latency.maximum_ms,
                "throughput_per_second": report.throughput.value_per_second,
                "peak_memory_bytes": report.memory.peak_memory_bytes,
                "average_memory_bytes": report.memory.average_memory_bytes,
                "peak_cpu_percent": report.cpu.peak_cpu_percent,
                "successful_operations": report.successful_operations,
                "failed_operations": report.failed_operations,
                "resource_profile": report.resource_profile,
                "gc_observations": report.gc_observations,
            }
        )
    return _area_summary("load", summary.assessment, summary.passed_scenarios, summary.failed_scenarios, scenario_metrics)


def _area_summary(
    area: str,
    assessment: BenchmarkAssessment | str,
    passed: int,
    failed: int,
    scenarios: list[dict[str, Any]],
) -> AreaPerformanceSummary:
    p95_values = [float(item["p95_ms"]) for item in scenarios]
    p99_values = [float(item["p99_ms"]) for item in scenarios]
    throughput_values = [
        float(item[key])
        for item in scenarios
        for key in ("throughput_per_second", "event_throughput_per_second")
        if key in item
    ]
    memory_values = [int(item["peak_memory_bytes"]) for item in scenarios]
    cpu_values = [float(item["peak_cpu_percent"]) for item in scenarios]
    return AreaPerformanceSummary(
        area=area,
        assessment=str(assessment.value if isinstance(assessment, BenchmarkAssessment) else assessment),
        scenario_count=len(scenarios),
        passed_scenarios=passed,
        failed_scenarios=failed,
        metrics={
            "p95_ms": _aggregate_numeric(p95_values),
            "p99_ms": _aggregate_numeric(p99_values),
            "throughput_per_second": _aggregate_numeric(throughput_values),
            "peak_memory_bytes": _aggregate_numeric(memory_values),
            "peak_cpu_percent": _aggregate_numeric(cpu_values),
            "standard_deviation_ms_across_scenario_p95": _stddev(p95_values),
        },
        scenarios=tuple(scenarios),
    )


def _aggregate_numeric(values: list[float] | list[int]) -> dict[str, float]:
    if not values:
        return {
            "minimum": 0.0,
            "maximum": 0.0,
            "average": 0.0,
            "median": 0.0,
        }
    numeric = [float(item) for item in values]
    return {
        "minimum": min(numeric),
        "maximum": max(numeric),
        "average": statistics.fmean(numeric),
        "median": statistics.median(numeric),
    }


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def _requirement_traceability(
    gateway: AreaPerformanceSummary,
    streaming: AreaPerformanceSummary,
    audit: AreaPerformanceSummary,
    load: AreaPerformanceSummary,
) -> tuple[RequirementAssessment, ...]:
    return (
        RequirementAssessment(
            requirement="Gateway latency and throughput are measured without production behavior changes.",
            status=_pass_if(gateway),
            evidence=f"{gateway.scenario_count} Gateway scenarios; failed={gateway.failed_scenarios}; max p95={gateway.metrics['p95_ms']['maximum']:.3f}ms.",
            limitation="Mocked provider and local process measurements only.",
        ),
        RequirementAssessment(
            requirement="Streaming latency, throughput, UTF-8/SSE/state-machine cost, and tokenization interaction are measured.",
            status=_pass_if(streaming),
            evidence=f"{streaming.scenario_count} Streaming scenarios; failed={streaming.failed_scenarios}; max p95={streaming.metrics['p95_ms']['maximum']:.3f}ms.",
            limitation="Mocked provider chunks; production provider streaming jitter is not measured.",
        ),
        RequirementAssessment(
            requirement="Audit export generation and verification performance are measured.",
            status=_pass_if(audit),
            evidence=f"{audit.scenario_count} Audit Export scenarios; failed={audit.failed_scenarios}; max p95={audit.metrics['p95_ms']['maximum']:.3f}ms.",
            limitation="In-memory repository and deterministic signer; production database/signing latency is not measured.",
        ),
        RequirementAssessment(
            requirement="Concurrent Gateway, Streaming, Audit Export, and mixed workloads are profiled.",
            status=_pass_if(load),
            evidence=f"{load.scenario_count} Load scenarios; failed={load.failed_scenarios}; max p95={load.metrics['p95_ms']['maximum']:.3f}ms.",
            limitation="Local mocked c5 closeout smoke; full production load testing remains a deployment-stage task.",
        ),
    )


def _pass_if(summary: AreaPerformanceSummary) -> str:
    return "PASS" if summary.failed_scenarios == 0 else "PARTIAL"


def _select_gateway_scenarios(slugs: Iterable[str]):
    wanted = set(slugs)
    return tuple(scenario for scenario in gateway_benchmark_scenarios() if scenario.slug in wanted)


def _select_streaming_scenarios(slugs: Iterable[str]):
    wanted = set(slugs)
    return tuple(scenario for scenario in streaming_benchmark_scenarios() if scenario.slug in wanted)


def _select_audit_scenarios(slugs: Iterable[str]):
    wanted = set(slugs)
    return tuple(scenario for scenario in audit_export_benchmark_scenarios() if scenario.slug in wanted)


def _select_load_scenarios(slugs: Iterable[str]):
    wanted = set(slugs)
    return tuple(scenario for scenario in load_benchmark_scenarios() if scenario.slug in wanted)


async def main() -> None:
    parser = argparse.ArgumentParser(description="AuthClaw E4.3 consolidated performance summary")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--warmups", type=int, default=1)
    args = parser.parse_args()
    summary = await run_e4_3_closeout_summary(iterations=args.iterations, warmups=args.warmups)
    print(json.dumps(summary.as_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
