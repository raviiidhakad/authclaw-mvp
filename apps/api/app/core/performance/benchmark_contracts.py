"""
E4.3 benchmark architecture contracts.

The classes in this module define immutable benchmark scenarios, environments,
results, and summaries. They are specification-only contracts and must not run
benchmarks, profile resources, tune algorithms, or connect to runtime systems.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from app.core.performance.performance_enums import (
    BenchmarkKind,
    BenchmarkScenarioId,
    BenchmarkTarget,
    BenchmarkUnit,
)
from app.core.performance.performance_types import (
    BenchmarkMetadataContract,
    CpuMeasurementContract,
    HardwareMetadataContract,
    MemoryMeasurementContract,
    PercentileLatencyContract,
    PerformanceContractModel,
    PerformanceThresholdContract,
    SoftwareVersionContract,
    ThroughputMeasurementContract,
    VersionIdentifierContract,
)


DEFAULT_GATEWAY_P95_THRESHOLD = PerformanceThresholdContract(
    metric="gateway_overhead_p95_ms",
    value=50,
    unit=BenchmarkUnit.MILLISECONDS,
    source_requirement="NFR-1.1",
    description="AuthClaw gateway processing overhead per request.",
)

DEFAULT_STREAMING_P95_THRESHOLD = PerformanceThresholdContract(
    metric="streaming_overhead_p95_ms",
    value=50,
    unit=BenchmarkUnit.MILLISECONDS,
    source_requirement="NFR-1.2",
    description="Streaming-safe filtering overhead without fragmentation.",
)


class BenchmarkEnvironmentContract(PerformanceContractModel):
    """Environment metadata required to interpret benchmark results."""

    environment_id: UUID
    name: str
    captured_at: datetime
    hardware: HardwareMetadataContract = Field(default_factory=HardwareMetadataContract)
    software: SoftwareVersionContract = Field(default_factory=SoftwareVersionContract)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BenchmarkScenarioContract(PerformanceContractModel):
    """Declarative benchmark scenario configuration."""

    scenario_id: BenchmarkScenarioId
    target: BenchmarkTarget
    kind: BenchmarkKind
    name: str
    description: str
    payload_profile: str | None = None
    iterations: int = Field(default=0, ge=0)
    warmups: int = Field(default=0, ge=0)
    concurrency: int = Field(default=1, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PerformanceBenchmarkContract(PerformanceContractModel):
    """Base contract shared by all benchmark result families."""

    benchmark_id: UUID
    versions: VersionIdentifierContract = Field(default_factory=VersionIdentifierContract)
    scenario: BenchmarkScenarioContract
    environment: BenchmarkEnvironmentContract
    metadata: BenchmarkMetadataContract
    thresholds: tuple[PerformanceThresholdContract, ...] = ()


class LatencyBenchmarkContract(PerformanceBenchmarkContract):
    """Latency benchmark result with percentile measurements."""

    kind: BenchmarkKind = BenchmarkKind.LATENCY
    latency: PercentileLatencyContract


class ThroughputBenchmarkContract(PerformanceBenchmarkContract):
    """Throughput benchmark result."""

    kind: BenchmarkKind = BenchmarkKind.THROUGHPUT
    throughput: ThroughputMeasurementContract


class ConcurrencyBenchmarkContract(PerformanceBenchmarkContract):
    """Concurrency benchmark result."""

    kind: BenchmarkKind = BenchmarkKind.CONCURRENCY
    concurrent_clients: int = Field(ge=1)
    successful_operations: int = Field(ge=0)
    failed_operations: int = Field(ge=0)
    latency: PercentileLatencyContract | None = None
    throughput: ThroughputMeasurementContract | None = None


class MemoryBenchmarkContract(PerformanceBenchmarkContract):
    """Memory benchmark result."""

    kind: BenchmarkKind = BenchmarkKind.MEMORY
    memory: MemoryMeasurementContract


class CpuBenchmarkContract(PerformanceBenchmarkContract):
    """CPU benchmark result."""

    kind: BenchmarkKind = BenchmarkKind.CPU
    cpu: CpuMeasurementContract


class BenchmarkResultContract(PerformanceContractModel):
    """Union-style result envelope for future benchmark harness outputs."""

    result_id: UUID
    benchmark: (
        LatencyBenchmarkContract
        | ThroughputBenchmarkContract
        | ConcurrencyBenchmarkContract
        | MemoryBenchmarkContract
        | CpuBenchmarkContract
    )
    notes: tuple[str, ...] = ()

