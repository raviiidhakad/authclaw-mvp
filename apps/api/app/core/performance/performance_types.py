"""
E4.3 shared performance measurement contracts.

These frozen models represent benchmark inputs and outputs only. They avoid
imports from Gateway, Streaming, OPA, TokenVault, Audit, providers, workers, or
database layers so they cannot alter runtime behavior.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.performance.performance_enums import (
    BenchmarkAssessment,
    BenchmarkUnit,
    PERFORMANCE_CONTRACT_VERSION,
    PERFORMANCE_SCHEMA,
    PERFORMANCE_SCHEMA_VERSION,
    RecommendationPriority,
    ThresholdOperator,
)


class PerformanceContractModel(BaseModel):
    """Frozen base model for E4.3 benchmark contracts."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        populate_by_name=True,
        use_enum_values=True,
    )


class VersionIdentifierContract(PerformanceContractModel):
    """Schema and contract version identifiers for performance artifacts."""

    schema_id: str = Field(PERFORMANCE_SCHEMA, alias="schema")
    schema_version: int = PERFORMANCE_SCHEMA_VERSION
    contract_version: int = PERFORMANCE_CONTRACT_VERSION


class PercentileLatencyContract(PerformanceContractModel):
    """Latency distribution statistics in milliseconds."""

    minimum_ms: float = Field(ge=0)
    maximum_ms: float = Field(ge=0)
    average_ms: float = Field(ge=0)
    median_ms: float = Field(ge=0)
    p50_ms: float = Field(ge=0)
    p90_ms: float = Field(ge=0)
    p95_ms: float = Field(ge=0)
    p99_ms: float = Field(ge=0)


class ThroughputMeasurementContract(PerformanceContractModel):
    """Throughput values for requests, events, or bytes."""

    unit: BenchmarkUnit
    value_per_second: float = Field(ge=0)
    total_operations: int = Field(ge=0)
    wall_time_ms: float = Field(ge=0)


class MemoryMeasurementContract(PerformanceContractModel):
    """Memory usage summary for one benchmark result."""

    peak_memory_bytes: int = Field(ge=0)
    average_memory_bytes: int = Field(ge=0)
    minimum_memory_bytes: int = Field(ge=0)


class CpuMeasurementContract(PerformanceContractModel):
    """CPU usage summary for one benchmark result."""

    peak_cpu_percent: float = Field(ge=0, le=100)
    average_cpu_percent: float = Field(ge=0, le=100)


class BenchmarkMetadataContract(PerformanceContractModel):
    """Execution-shape metadata recorded with future benchmark results."""

    iterations: int = Field(ge=0)
    warmups: int = Field(ge=0)
    sample_count: int = Field(ge=0)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class HardwareMetadataContract(PerformanceContractModel):
    """Hardware metadata captured by benchmark harnesses."""

    cpu_model: str | None = None
    cpu_cores: int | None = Field(default=None, ge=1)
    memory_bytes: int | None = Field(default=None, ge=0)
    machine_type: str | None = None


class SoftwareVersionContract(PerformanceContractModel):
    """Software versions relevant to a benchmark environment."""

    authclaw_version: str | None = None
    python_version: str | None = None
    node_version: str | None = None
    database_version: str | None = None
    redis_version: str | None = None
    clickhouse_version: str | None = None
    opa_version: str | None = None
    os: str | None = None


class PerformanceThresholdContract(PerformanceContractModel):
    """Declarative performance threshold; no enforcement is performed here."""

    metric: str
    operator: ThresholdOperator = ThresholdOperator.LESS_THAN_OR_EQUAL
    value: float
    unit: BenchmarkUnit
    source_requirement: str | None = None
    description: str | None = None


class OptimizationRecommendationContract(PerformanceContractModel):
    """Future recommendation record attached to benchmark summaries."""

    recommendation_id: str
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    target_area: str
    summary: str
    evidence: str | None = None
    requires_runtime_change: bool = True


class BenchmarkSummaryContract(PerformanceContractModel):
    """Top-level summary for a benchmark batch."""

    summary_id: UUID
    assessment: BenchmarkAssessment = BenchmarkAssessment.NOT_EVALUATED
    total_scenarios: int = Field(ge=0)
    passed_scenarios: int = Field(ge=0, default=0)
    failed_scenarios: int = Field(ge=0, default=0)
    partial_scenarios: int = Field(ge=0, default=0)
    thresholds: tuple[PerformanceThresholdContract, ...] = ()
    recommendations: tuple[OptimizationRecommendationContract, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

