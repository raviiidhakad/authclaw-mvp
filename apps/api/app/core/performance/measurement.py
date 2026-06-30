"""
E4.3 measurement and statistics utilities.

The functions and collectors here operate on numeric samples only. They do not
connect to Gateway, Streaming, OPA, TokenVault, Audit, providers, databases, or
workers.
"""
from __future__ import annotations

import math
import statistics
import time
import tracemalloc
from dataclasses import dataclass, field

from app.core.performance.performance_enums import BenchmarkUnit
from app.core.performance.performance_types import (
    CpuMeasurementContract,
    MemoryMeasurementContract,
    PercentileLatencyContract,
    ThroughputMeasurementContract,
)


def percentile(samples: list[float] | tuple[float, ...], percentile_value: float) -> float:
    """Return an interpolated percentile from deterministic sorted samples."""

    if not samples:
        raise ValueError("percentile_requires_samples")
    if percentile_value < 0 or percentile_value > 100:
        raise ValueError("percentile_out_of_range")
    ordered = sorted(float(item) for item in samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (percentile_value / 100)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[int(rank)]
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def latency_statistics(samples_ms: list[float] | tuple[float, ...]) -> PercentileLatencyContract:
    """Build the Phase 1 latency contract from millisecond samples."""

    if not samples_ms:
        raise ValueError("latency_statistics_requires_samples")
    values = [float(item) for item in samples_ms]
    return PercentileLatencyContract(
        minimum_ms=min(values),
        maximum_ms=max(values),
        average_ms=statistics.fmean(values),
        median_ms=statistics.median(values),
        p50_ms=percentile(values, 50),
        p90_ms=percentile(values, 90),
        p95_ms=percentile(values, 95),
        p99_ms=percentile(values, 99),
    )


def standard_deviation(samples: list[float] | tuple[float, ...]) -> float:
    """Return sample standard deviation, or zero for fewer than two samples."""

    if len(samples) < 2:
        return 0.0
    return statistics.stdev(float(item) for item in samples)


def throughput_measurement(
    *,
    total_operations: int,
    wall_time_ms: float,
    unit: BenchmarkUnit,
) -> ThroughputMeasurementContract:
    """Build a throughput contract from operation count and wall time."""

    if total_operations < 0:
        raise ValueError("total_operations_must_be_non_negative")
    if wall_time_ms < 0:
        raise ValueError("wall_time_must_be_non_negative")
    value = 0.0 if wall_time_ms == 0 else total_operations / (wall_time_ms / 1000)
    return ThroughputMeasurementContract(
        unit=unit,
        value_per_second=value,
        total_operations=total_operations,
        wall_time_ms=wall_time_ms,
    )


@dataclass
class LatencySampleCollector:
    """Collect latency samples and emit deterministic statistics."""

    samples_ms: list[float] = field(default_factory=list)

    def add(self, elapsed_ms: float) -> None:
        if elapsed_ms < 0:
            raise ValueError("elapsed_ms_must_be_non_negative")
        self.samples_ms.append(float(elapsed_ms))

    def extend(self, samples_ms: list[float] | tuple[float, ...]) -> None:
        for sample in samples_ms:
            self.add(sample)

    def statistics(self) -> PercentileLatencyContract:
        return latency_statistics(tuple(self.samples_ms))

    def standard_deviation(self) -> float:
        return standard_deviation(tuple(self.samples_ms))


@dataclass
class MemorySampleCollector:
    """Collect memory samples in bytes."""

    samples_bytes: list[int] = field(default_factory=list)

    def add(self, value_bytes: int) -> None:
        if value_bytes < 0:
            raise ValueError("memory_sample_must_be_non_negative")
        self.samples_bytes.append(int(value_bytes))

    def measurement(self) -> MemoryMeasurementContract:
        if not self.samples_bytes:
            raise ValueError("memory_measurement_requires_samples")
        return MemoryMeasurementContract(
            peak_memory_bytes=max(self.samples_bytes),
            average_memory_bytes=round(statistics.fmean(self.samples_bytes)),
            minimum_memory_bytes=min(self.samples_bytes),
        )


@dataclass
class CpuSampleCollector:
    """Collect CPU utilization samples in percent."""

    samples_percent: list[float] = field(default_factory=list)

    def add(self, value_percent: float) -> None:
        if value_percent < 0 or value_percent > 100:
            raise ValueError("cpu_sample_out_of_range")
        self.samples_percent.append(float(value_percent))

    def measurement(self) -> CpuMeasurementContract:
        if not self.samples_percent:
            raise ValueError("cpu_measurement_requires_samples")
        return CpuMeasurementContract(
            peak_cpu_percent=max(self.samples_percent),
            average_cpu_percent=statistics.fmean(self.samples_percent),
        )


class TracemallocMemorySampler:
    """Optional memory sampler backed by Python tracemalloc."""

    def __init__(self) -> None:
        self._started_here = False

    def start(self) -> None:
        if not tracemalloc.is_tracing():
            tracemalloc.start()
            self._started_here = True

    def sample_peak_bytes(self) -> int:
        if not tracemalloc.is_tracing():
            return 0
        _current, peak = tracemalloc.get_traced_memory()
        return int(peak)

    def stop(self) -> None:
        if self._started_here and tracemalloc.is_tracing():
            tracemalloc.stop()
        self._started_here = False


class ProcessCpuSampler:
    """CPU-time sampler based on process_time; no third-party dependency needed."""

    def __init__(self) -> None:
        self._started_cpu: float | None = None
        self._started_wall: float | None = None

    def start(self) -> None:
        self._started_cpu = time.process_time()
        self._started_wall = time.perf_counter()

    def sample_percent(self) -> float:
        if self._started_cpu is None or self._started_wall is None:
            return 0.0
        cpu_delta = max(0.0, time.process_time() - self._started_cpu)
        wall_delta = max(0.0, time.perf_counter() - self._started_wall)
        if wall_delta == 0:
            return 0.0
        return min(100.0, (cpu_delta / wall_delta) * 100)

