from __future__ import annotations

import json

import pytest

from tests.performance.measure_e4_3_performance_summary import (
    E43PerformanceCloseoutSummary,
    run_e4_3_closeout_summary,
)


@pytest.mark.asyncio
async def test_e4_3_closeout_summary_collects_all_benchmark_areas() -> None:
    summary = await _small_summary()

    assert summary.methodology["runtime_mutation"] is False
    assert summary.gateway.area == "gateway"
    assert summary.streaming.area == "streaming"
    assert summary.audit_export.area == "audit_export"
    assert summary.load.area == "load"
    assert summary.gateway.scenario_count == 1
    assert summary.streaming.scenario_count == 1
    assert summary.audit_export.scenario_count == 1
    assert summary.load.scenario_count == 1


@pytest.mark.asyncio
async def test_e4_3_closeout_summary_serializes_required_metrics() -> None:
    payload = (await _small_summary()).as_dict()

    for area in ("gateway", "streaming", "audit_export", "load"):
        assert payload[area]["metrics"]["p95_ms"]["maximum"] >= 0
        assert payload[area]["metrics"]["p99_ms"]["maximum"] >= 0
        assert payload[area]["metrics"]["peak_memory_bytes"]["maximum"] >= 0
        assert payload[area]["metrics"]["peak_cpu_percent"]["maximum"] >= 0
        assert "standard_deviation_ms_across_scenario_p95" in payload[area]["metrics"]

    json.dumps(payload, sort_keys=True)


@pytest.mark.asyncio
async def test_e4_3_closeout_requirement_traceability_uses_evidence() -> None:
    summary = await _small_summary()

    assert len(summary.requirement_traceability) == 4
    for item in summary.requirement_traceability:
        assert item.status in {"PASS", "PARTIAL", "NOT VERIFIED"}
        assert item.evidence
        assert item.limitation


@pytest.mark.asyncio
async def test_e4_3_closeout_reproducibility_shape_is_stable() -> None:
    first = await _small_summary()
    second = await _small_summary()

    assert _slugs(first) == _slugs(second)
    assert first.gateway.scenario_count == second.gateway.scenario_count
    assert first.streaming.scenario_count == second.streaming.scenario_count
    assert first.audit_export.scenario_count == second.audit_export.scenario_count
    assert first.load.scenario_count == second.load.scenario_count


@pytest.mark.asyncio
async def test_e4_3_closeout_limitations_distinguish_local_from_production() -> None:
    summary = await _small_summary()
    limitations = " ".join(summary.limitations).lower()

    assert "mocked providers" in limitations
    assert "production" in limitations
    assert "runtime optimization" in limitations


async def _small_summary() -> E43PerformanceCloseoutSummary:
    return await run_e4_3_closeout_summary(
        iterations=1,
        warmups=0,
        gateway_slugs=("small_request",),
        streaming_slugs=("tiny_stream",),
        audit_slugs=("records_10",),
        load_slugs=("gateway_only_c1",),
    )


def _slugs(summary: E43PerformanceCloseoutSummary) -> tuple[str, ...]:
    areas = (summary.gateway, summary.streaming, summary.audit_export, summary.load)
    return tuple(str(item["slug"]) for area in areas for item in area.scenarios)
