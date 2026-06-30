"""
E4.3 reusable benchmark runner.

The runner executes only caller-provided zero-argument callables. It contains no
knowledge of Gateway, Streaming, OPA, TokenVault, Audit, providers, databases,
workers, APIs, or frontend code.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from app.core.performance.benchmark_contracts import (
    BenchmarkEnvironmentContract,
    BenchmarkResultContract,
    BenchmarkScenarioContract,
    LatencyBenchmarkContract,
)
from app.core.performance.performance_enums import BenchmarkAssessment, BenchmarkUnit
from app.core.performance.performance_types import (
    BenchmarkMetadataContract,
    BenchmarkSummaryContract,
    PerformanceThresholdContract,
    ThroughputMeasurementContract,
)
from app.core.performance.measurement import (
    LatencySampleCollector,
    throughput_measurement,
)
from app.core.performance.system_snapshot import environment_snapshot
from app.core.performance.timer import HighResolutionTimer


@dataclass(frozen=True)
class IterationPlan:
    """Warmup and measured iteration counts."""

    warmups: int
    iterations: int

    def __post_init__(self) -> None:
        if self.warmups < 0:
            raise ValueError("warmups_must_be_non_negative")
        if self.iterations < 1:
            raise ValueError("iterations_must_be_positive")

    @property
    def total_executions(self) -> int:
        return self.warmups + self.iterations


@dataclass
class BenchmarkExecutionContext:
    """Context passed through a benchmark run."""

    scenario: BenchmarkScenarioContract
    environment: BenchmarkEnvironmentContract = field(default_factory=environment_snapshot)
    thresholds: tuple[PerformanceThresholdContract, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def iteration_plan(self) -> IterationPlan:
        return IterationPlan(
            warmups=self.scenario.warmups,
            iterations=max(1, self.scenario.iterations),
        )


@dataclass(frozen=True)
class BenchmarkRunOutput:
    """Latency-focused output from the generic runner."""

    result: BenchmarkResultContract
    summary: BenchmarkSummaryContract
    throughput: ThroughputMeasurementContract
    samples_ms: tuple[float, ...]
    standard_deviation_ms: float


class BenchmarkRunner:
    """Generic warmup/iteration runner for isolated benchmark callables."""

    def run_latency(
        self,
        context: BenchmarkExecutionContext,
        operation: Callable[[], object],
    ) -> BenchmarkRunOutput:
        plan = context.iteration_plan
        for _ in range(plan.warmups):
            operation()

        collector = LatencySampleCollector()
        started_at = datetime.now(UTC)
        wall_timer = HighResolutionTimer().start()
        for _ in range(plan.iterations):
            iteration_timer = HighResolutionTimer().start()
            operation()
            collector.add(iteration_timer.stop().elapsed_ms)
        wall_time_ms = wall_timer.stop().elapsed_ms
        completed_at = datetime.now(UTC)

        metadata = BenchmarkMetadataContract(
            iterations=plan.iterations,
            warmups=plan.warmups,
            sample_count=len(collector.samples_ms),
            started_at=started_at,
            completed_at=completed_at,
            labels=context.labels,
        )
        benchmark = LatencyBenchmarkContract(
            benchmark_id=uuid4(),
            scenario=context.scenario,
            environment=context.environment,
            metadata=metadata,
            thresholds=context.thresholds,
            latency=collector.statistics(),
        )
        result = BenchmarkResultContract(result_id=uuid4(), benchmark=benchmark)
        summary = BenchmarkSummaryContract(
            summary_id=uuid4(),
            assessment=BenchmarkAssessment.NOT_EVALUATED,
            total_scenarios=1,
            thresholds=context.thresholds,
            metadata={
                "scenario_id": context.scenario.scenario_id.value
                if hasattr(context.scenario.scenario_id, "value")
                else str(context.scenario.scenario_id),
                "sample_count": len(collector.samples_ms),
                "standard_deviation_ms": collector.standard_deviation(),
            },
        )
        throughput = throughput_measurement(
            total_operations=plan.iterations,
            wall_time_ms=wall_time_ms,
            unit=BenchmarkUnit.REQUESTS_PER_SECOND,
        )
        return BenchmarkRunOutput(
            result=result,
            summary=summary,
            throughput=throughput,
            samples_ms=tuple(collector.samples_ms),
            standard_deviation_ms=collector.standard_deviation(),
        )

