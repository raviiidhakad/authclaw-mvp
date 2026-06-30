from __future__ import annotations

import inspect
import json
from uuid import UUID

import pytest

from app.core.performance import benchmark_contracts
from app.core.performance import benchmark_runner
from app.core.performance import measurement
from app.core.performance import performance_enums as enums
from app.core.performance import system_snapshot
from app.core.performance import timer


ENVIRONMENT_ID = UUID("11111111-1111-4111-8111-111111111111")


def _scenario(iterations: int = 3, warmups: int = 2) -> benchmark_contracts.BenchmarkScenarioContract:
    return benchmark_contracts.BenchmarkScenarioContract(
        scenario_id=enums.BenchmarkScenarioId.GATEWAY_OPENAI_COMPAT_CHAT,
        target=enums.BenchmarkTarget.GATEWAY_LATENCY,
        kind=enums.BenchmarkKind.LATENCY,
        name="Harness unit scenario",
        description="Generic callable harness test; no AuthClaw runtime path.",
        iterations=iterations,
        warmups=warmups,
    )


def test_harness_modules_do_not_import_authclaw_runtime_paths():
    combined = "\n".join(
        inspect.getsource(module)
        for module in (benchmark_runner, measurement, system_snapshot, timer)
    )

    assert "from app.core.engine.gateway" not in combined
    assert "from app.core.engine.streaming" not in combined
    assert "from app.core.engine.token_vault" not in combined
    assert "from app.core.policy" not in combined
    assert "from app.core.audit" not in combined
    assert "from app.core.providers" not in combined
    assert "from app.workers" not in combined


def test_high_resolution_timer_records_elapsed_time_and_resets():
    high_res_timer = timer.HighResolutionTimer().start()
    reading = high_res_timer.stop()

    assert reading.elapsed_ns >= 0
    assert reading.elapsed_ms >= 0
    high_res_timer.reset()
    assert high_res_timer.running is False


def test_percentile_calculation_is_deterministic():
    samples = [10, 20, 30, 40, 50]

    assert measurement.percentile(samples, 50) == 30
    assert measurement.percentile(samples, 90) == 46
    assert measurement.percentile(samples, 95) == 48
    assert measurement.percentile(tuple(reversed(samples)), 95) == 48


def test_latency_statistics_and_standard_deviation_aggregate_samples():
    stats = measurement.latency_statistics([1, 2, 3, 4])

    assert stats.minimum_ms == 1
    assert stats.maximum_ms == 4
    assert stats.average_ms == 2.5
    assert stats.median_ms == 2.5
    assert stats.p95_ms == pytest.approx(3.85)
    assert measurement.standard_deviation([1]) == 0
    assert measurement.standard_deviation([1, 2, 3]) > 0


def test_memory_and_cpu_measurement_serialization():
    memory = measurement.MemorySampleCollector()
    memory.add(100)
    memory.add(300)
    memory_contract = memory.measurement()

    cpu = measurement.CpuSampleCollector()
    cpu.add(10.0)
    cpu.add(25.0)
    cpu_contract = cpu.measurement()

    assert memory_contract.peak_memory_bytes == 300
    assert memory_contract.average_memory_bytes == 200
    assert cpu_contract.peak_cpu_percent == 25.0
    json.dumps(memory_contract.model_dump(mode="json", by_alias=True))
    json.dumps(cpu_contract.model_dump(mode="json", by_alias=True))


def test_tracemalloc_and_cpu_samplers_are_generic_abstractions():
    memory_sampler = measurement.TracemallocMemorySampler()
    memory_sampler.start()
    allocated = [object() for _ in range(10)]
    assert allocated
    assert memory_sampler.sample_peak_bytes() >= 0
    memory_sampler.stop()

    cpu_sampler = measurement.ProcessCpuSampler()
    cpu_sampler.start()
    assert 0 <= cpu_sampler.sample_percent() <= 100


def test_environment_snapshot_constructs_serializable_contract():
    environment = system_snapshot.environment_snapshot(
        name="unit-test",
        authclaw_version="0.10.0",
    )

    dumped = environment.model_dump(mode="json", by_alias=True)
    json.dumps(dumped)

    assert dumped["name"] == "unit-test"
    assert dumped["software"]["authclaw_version"] == "0.10.0"
    assert dumped["metadata"]["snapshot_source"] == "standard_library"


def test_iteration_plan_and_context_validate_warmups_and_iterations():
    plan = benchmark_runner.IterationPlan(warmups=2, iterations=5)
    assert plan.total_executions == 7

    context = benchmark_runner.BenchmarkExecutionContext(scenario=_scenario(iterations=4, warmups=1))
    assert context.iteration_plan.warmups == 1
    assert context.iteration_plan.iterations == 4

    with pytest.raises(ValueError):
        benchmark_runner.IterationPlan(warmups=0, iterations=0)


def test_benchmark_runner_honors_warmups_iterations_and_generates_summary():
    calls: list[str] = []

    def operation() -> None:
        calls.append("called")

    context = benchmark_runner.BenchmarkExecutionContext(
        scenario=_scenario(iterations=3, warmups=2),
        thresholds=(benchmark_contracts.DEFAULT_GATEWAY_P95_THRESHOLD,),
        labels={"phase": "e4.3-phase2"},
    )
    output = benchmark_runner.BenchmarkRunner().run_latency(context, operation)

    assert len(calls) == 5
    assert len(output.samples_ms) == 3
    assert output.result.benchmark.metadata.iterations == 3
    assert output.result.benchmark.metadata.warmups == 2
    assert output.result.benchmark.metadata.labels == {"phase": "e4.3-phase2"}
    assert output.summary.total_scenarios == 1
    assert output.summary.assessment == "not_evaluated"
    assert output.throughput.total_operations == 3
    json.dumps(output.result.model_dump(mode="json", by_alias=True))
    json.dumps(output.summary.model_dump(mode="json", by_alias=True))

