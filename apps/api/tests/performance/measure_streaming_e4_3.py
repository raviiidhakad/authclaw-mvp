"""
E4.3 Phase 4 streaming performance benchmark.

This module benchmarks the existing E2.3 StreamingEngine through its public
``stream_response`` interface with mocked provider streaming input. It also
measures the existing UTF-8 decoder, SSE parser, and streaming state machine
components in isolation against the same chunks. No StreamingEngine, Gateway,
OPA, TokenVault, Audit, provider adapter, API, schema, database, Docker,
Terraform, or frontend runtime code is modified.

Usage from apps/api:
  python tests/performance/measure_streaming_e4_3.py --iterations 10 --warmups 2
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from collections.abc import AsyncGenerator, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

API_ROOT = Path(__file__).resolve().parents[2]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

import httpx

from app.core.engine.audit import AuditEngine
from app.core.engine.sse_parser import ParsedSseEvent, SseParser
from app.core.engine.streaming import StreamingEngine, StreamingMode
from app.core.engine.streaming_state_machine import StreamingRedactionStateMachine
from app.core.engine.utf8_decoder import Utf8IncrementalDecoder
from app.core.performance.benchmark_contracts import (
    BenchmarkEnvironmentContract,
    BenchmarkResultContract,
    BenchmarkScenarioContract,
    DEFAULT_STREAMING_P95_THRESHOLD,
    LatencyBenchmarkContract,
)
from app.core.performance.benchmark_runner import IterationPlan
from app.core.performance.measurement import (
    CpuSampleCollector,
    LatencySampleCollector,
    MemorySampleCollector,
    ProcessCpuSampler,
    TracemallocMemorySampler,
    throughput_measurement,
)
from app.core.performance.performance_enums import (
    BenchmarkAssessment,
    BenchmarkKind,
    BenchmarkScenarioId,
    BenchmarkTarget,
    BenchmarkUnit,
)
from app.core.performance.performance_types import (
    BenchmarkMetadataContract,
    BenchmarkSummaryContract,
    CpuMeasurementContract,
    MemoryMeasurementContract,
    ThroughputMeasurementContract,
)
from app.core.performance.system_snapshot import environment_snapshot
from app.core.performance.timer import HighResolutionTimer


DEFAULT_ITERATIONS = 5
DEFAULT_WARMUPS = 1


@dataclass(frozen=True)
class StreamingBenchmarkScenario:
    slug: str
    scenario_id: BenchmarkScenarioId
    target: BenchmarkTarget
    name: str
    description: str
    payload_profile: str
    event_count: int
    content_pattern: str = "ascii"
    split_mode: str = "event"
    compiled_policy: dict[str, object] | None = None
    tokenization_enabled: bool = False
    expected_blocked: bool = False

    def contract(self, iterations: int, warmups: int) -> BenchmarkScenarioContract:
        return BenchmarkScenarioContract(
            scenario_id=self.scenario_id,
            target=self.target,
            kind=BenchmarkKind.LATENCY,
            name=self.name,
            description=self.description,
            payload_profile=self.payload_profile,
            iterations=iterations,
            warmups=warmups,
            concurrency=1,
            metadata={
                "slug": self.slug,
                "streaming_mode": StreamingMode.BUFFERED,
                "provider": "mock",
                "event_count": self.event_count,
                "split_mode": self.split_mode,
                "tokenization_enabled": self.tokenization_enabled,
                "expected_blocked": self.expected_blocked,
            },
        )


@dataclass(frozen=True)
class ComponentTiming:
    utf8_decode_ms: float
    sse_parse_ms: float
    state_machine_ms: float
    event_count: int


@dataclass(frozen=True)
class StreamingBenchmarkReport:
    scenario: BenchmarkScenarioContract
    latency_result: BenchmarkResultContract
    event_throughput: ThroughputMeasurementContract
    chunk_throughput: ThroughputMeasurementContract
    memory: MemoryMeasurementContract
    cpu: CpuMeasurementContract
    component_latency_ms: dict[str, float]
    policy_contribution_ms: dict[str, float | str]
    tokenization_contribution_ms: dict[str, float | str]
    chunks_processed: int
    events_processed: int
    audit_started_count: int
    audit_completed_count: int
    audit_failed_count: int

    def as_dict(self) -> dict[str, object]:
        benchmark = self.latency_result.benchmark
        return {
            "scenario": self.scenario.model_dump(mode="json"),
            "latency_result": self.latency_result.model_dump(mode="json"),
            "event_throughput": self.event_throughput.model_dump(mode="json"),
            "chunk_throughput": self.chunk_throughput.model_dump(mode="json"),
            "memory": self.memory.model_dump(mode="json"),
            "cpu": self.cpu.model_dump(mode="json"),
            "component_latency_ms": self.component_latency_ms,
            "policy_contribution_ms": self.policy_contribution_ms,
            "tokenization_contribution_ms": self.tokenization_contribution_ms,
            "chunks_processed": self.chunks_processed,
            "events_processed": self.events_processed,
            "audit_started_count": self.audit_started_count,
            "audit_completed_count": self.audit_completed_count,
            "audit_failed_count": self.audit_failed_count,
            "sample_count": benchmark.metadata.sample_count,
        }


class FakeScanResult:
    def __init__(self, text: str):
        self.original_text = text
        self.sanitized_text = text
        self.detections: list[dict[str, object]] = []
        self.latency_ms = 0
        for entity_type, value in {
            "EMAIL_ADDRESS": "person@example.test",
            "PHONE_NUMBER": "+1 202-555-0100",
            "API_KEY": "token=demo-token-redacted",
        }.items():
            start = text.find(value)
            if start < 0:
                continue
            self.detections.append(
                {
                    "entity_type": entity_type,
                    "start": start,
                    "end": start + len(value),
                    "score": 0.99,
                }
            )
            self.sanitized_text = self.sanitized_text.replace(value, f"[{entity_type}]")

    @property
    def has_detections(self) -> bool:
        return bool(self.detections)

    @property
    def entity_types(self) -> list[str]:
        return [str(item["entity_type"]) for item in self.detections]


class FakeDbContext:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *_args):
        return None


class FakeProducer:
    async def publish_security_event(self, _event):
        return None

    async def publish(self, *_args, **_kwargs):
        return None


class FakeStreamContext:
    status_code = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeHttpClient:
    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, *_args, **_kwargs):
        return FakeStreamContext()


class FakeAdapter:
    def __init__(self, chunks: tuple[bytes, ...]):
        self.chunks = chunks
        self.stream_calls = 0
        self.transform_request_calls = 0

    def transform_request(self, payload):
        self.transform_request_calls += 1
        return dict(payload)

    async def stream_response(self, _response) -> AsyncGenerator[bytes, None]:
        self.stream_calls += 1
        for chunk in self.chunks:
            yield chunk


class FakeAuditEngine:
    def __init__(self):
        self.publish_stream_started = AsyncMock()
        self.publish_stream_completed = AsyncMock()
        self.publish_stream_failed = AsyncMock()


class StreamingBenchmarkPatch:
    def __init__(self, compiled_policy: dict[str, object]) -> None:
        self.compiled_policy = compiled_policy
        self.token_vault_store = AsyncMock()
        self._settings: dict[str, object] = {}
        self._async_client = None
        self._db_session_local = None
        self._policy_cache_get = None
        self._presidio_is_healthy = None
        self._presidio_scan = None
        self._producer = None
        self._token_store_batch = None

    def install(self) -> None:
        from app.core.config import settings
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.engine.token_vault import TokenVaultService
        from app.core.policy.cache import policy_cache
        import app.core.database as database_module
        import app.core.events.producer as producer_module

        for name, value in {
            "FF_SECURITY_PIPELINE": True,
            "FF_STREAM_SCAN": True,
            "FF_SECURITY_SHADOW_MODE": False,
        }.items():
            self._settings[name] = getattr(settings, name)
            setattr(settings, name, value)

        self._async_client = httpx.AsyncClient
        self._db_session_local = database_module.AsyncSessionLocal
        self._policy_cache_get = policy_cache.get
        self._presidio_is_healthy = presidio_engine.is_healthy
        self._presidio_scan = presidio_engine.scan
        self._producer = producer_module.producer
        self._token_store_batch = TokenVaultService.store_batch

        httpx.AsyncClient = FakeHttpClient
        database_module.AsyncSessionLocal = lambda: FakeDbContext()
        policy_cache.get = AsyncMock(return_value=self.compiled_policy)
        presidio_engine.is_healthy = lambda: True
        presidio_engine.scan = AsyncMock(side_effect=lambda text: FakeScanResult(text))
        producer_module.producer = FakeProducer()
        TokenVaultService.store_batch = self.token_vault_store

    def restore(self) -> None:
        from app.core.config import settings
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.engine.token_vault import TokenVaultService
        from app.core.policy.cache import policy_cache
        import app.core.database as database_module
        import app.core.events.producer as producer_module

        for name, value in self._settings.items():
            setattr(settings, name, value)
        self._settings.clear()
        if self._async_client is not None:
            httpx.AsyncClient = self._async_client
        if self._db_session_local is not None:
            database_module.AsyncSessionLocal = self._db_session_local
        if self._policy_cache_get is not None:
            policy_cache.get = self._policy_cache_get
        if self._presidio_is_healthy is not None:
            presidio_engine.is_healthy = self._presidio_is_healthy
        if self._presidio_scan is not None:
            presidio_engine.scan = self._presidio_scan
        if self._producer is not None:
            producer_module.producer = self._producer
        if self._token_store_batch is not None:
            TokenVaultService.store_batch = self._token_store_batch


def streaming_benchmark_scenarios() -> tuple[StreamingBenchmarkScenario, ...]:
    return (
        _scenario("tiny_stream", "Tiny stream", "Tiny one-event stream.", 1),
        _scenario("small_stream", "Small stream", "Small mocked provider stream.", 16),
        _scenario("medium_stream", "Medium stream", "Medium mocked provider stream.", 128),
        _scenario("large_stream", "Large stream", "Large mocked provider stream.", 512),
        _scenario("very_large_stream", "Very large stream", "Very large mocked provider stream.", 1500),
        _scenario("long_running_stream", "Long-running stream", "Long stream shape without real sleeps.", 1000),
        _scenario(
            "chunk_boundary_stress",
            "Chunk boundary stress",
            "SSE event bytes split across many small provider chunks.",
            64,
            split_mode="small_chunks",
        ),
        _scenario(
            "utf8_split_boundaries",
            "UTF-8 split boundaries",
            "Unicode-heavy stream with UTF-8 code points split across chunks.",
            64,
            content_pattern="unicode",
            split_mode="utf8_split",
        ),
        _scenario(
            "sse_multiline_events",
            "SSE multiline events",
            "SSE parser stress with comments and multiline data before valid OpenAI events.",
            32,
            split_mode="multiline",
        ),
        _scenario(
            "policy_allow",
            "Streaming policy allow",
            "Streaming security scan with allow policy.",
            32,
            compiled_policy={"entity_actions": {}, "keyword_blocklist": [], "policy_ids": ["policy-allow"]},
        ),
        _scenario(
            "policy_redact",
            "Streaming policy redact",
            "Streaming security scan redacts fake PII after safe reassembly.",
            16,
            content_pattern="pii",
            compiled_policy={
                "entity_actions": {"EMAIL_ADDRESS": "MASK"},
                "keyword_blocklist": [],
                "policy_ids": ["policy-redact"],
            },
        ),
        _scenario(
            "policy_block",
            "Streaming policy block",
            "Streaming security scan blocks policy-matching content.",
            16,
            content_pattern="blocked",
            compiled_policy={"entity_actions": {}, "keyword_blocklist": ["blocked-term-e43"], "policy_ids": ["policy-block"]},
            expected_blocked=True,
        ),
        _scenario(
            "tokenization_enabled",
            "Streaming tokenization enabled",
            "Streaming security scan uses existing reversible tokenization helper.",
            16,
            content_pattern="pii",
            compiled_policy={
                "entity_actions": {"EMAIL_ADDRESS": "MASK"},
                "reversible_entities": ["EMAIL_ADDRESS"],
                "keyword_blocklist": [],
                "policy_ids": ["policy-token"],
            },
            tokenization_enabled=True,
        ),
        _scenario(
            "tokenization_disabled",
            "Streaming tokenization disabled",
            "Streaming security scan masks fake PII without reversible tokenization.",
            16,
            content_pattern="pii",
            compiled_policy={
                "entity_actions": {"EMAIL_ADDRESS": "MASK"},
                "reversible_entities": [],
                "keyword_blocklist": [],
                "policy_ids": ["policy-no-token"],
            },
            tokenization_enabled=False,
        ),
    )


def _scenario(
    slug: str,
    name: str,
    description: str,
    event_count: int,
    *,
    content_pattern: str = "ascii",
    split_mode: str = "event",
    compiled_policy: dict[str, object] | None = None,
    tokenization_enabled: bool = False,
    expected_blocked: bool = False,
) -> StreamingBenchmarkScenario:
    return StreamingBenchmarkScenario(
        slug=slug,
        scenario_id=BenchmarkScenarioId.STREAMING_SAFE_SSE,
        target=BenchmarkTarget.STREAMING_LATENCY,
        name=name,
        description=description,
        payload_profile=slug,
        event_count=event_count,
        content_pattern=content_pattern,
        split_mode=split_mode,
        compiled_policy=compiled_policy,
        tokenization_enabled=tokenization_enabled,
        expected_blocked=expected_blocked,
    )


def compiled_policy_for(scenario: StreamingBenchmarkScenario) -> dict[str, object]:
    return scenario.compiled_policy or {"entity_actions": {}, "keyword_blocklist": [], "policy_ids": [scenario.slug]}


def chunks_for_scenario(scenario: StreamingBenchmarkScenario) -> tuple[bytes, ...]:
    events = [_openai_event(_content_for(scenario, index)) for index in range(scenario.event_count)]
    if scenario.split_mode == "multiline":
        events.insert(0, b": benchmark-comment\n")
        events.insert(1, b"data: ignored\n")
        events.insert(2, b"data: multiline\n\n")
    events.append(b"data: [DONE]\n\n")
    if scenario.split_mode == "small_chunks":
        return tuple(piece for event in events for piece in _split_bytes(event, 7))
    if scenario.split_mode == "utf8_split":
        return tuple(piece for event in events for piece in _split_bytes(event, 3))
    return tuple(events)


def _content_for(scenario: StreamingBenchmarkScenario, index: int) -> str:
    if scenario.content_pattern == "unicode":
        values = ("safe 🔐 ", "東京 ", "数据 ", "emoji 😀 ")
        return f"{values[index % len(values)]}{index} "
    if scenario.content_pattern == "pii":
        return "email person@example.test " if index == scenario.event_count // 2 else f"safe{index} "
    if scenario.content_pattern == "blocked":
        return "blocked-term-e43 " if index == scenario.event_count // 2 else f"safe{index} "
    return f"word{index} "


def _openai_event(content: str) -> bytes:
    return ("data: " + json.dumps({"choices": [{"delta": {"content": content}}]}, separators=(",", ":")) + "\n\n").encode("utf-8")


def _split_bytes(value: bytes, size: int) -> tuple[bytes, ...]:
    return tuple(value[index:index + size] for index in range(0, len(value), size))


async def render_streaming_response(
    scenario: StreamingBenchmarkScenario,
) -> tuple[str, FakeAuditEngine, FakeAdapter, StreamingBenchmarkPatch]:
    chunks = chunks_for_scenario(scenario)
    patch = StreamingBenchmarkPatch(compiled_policy_for(scenario))
    patch.install()
    audit = FakeAuditEngine()
    adapter = FakeAdapter(chunks)
    engine = StreamingEngine(audit)  # type: ignore[arg-type]
    try:
        response = await engine.stream_response(
            tenant_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:stream:{scenario.slug}"),
            api_key_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:stream-key:{scenario.slug}"),
            provider_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:stream-provider:{scenario.slug}"),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [{"role": "user", "content": "benchmark"}], "stream": True},
            provider_name="mock",
            adapter=adapter,
            streaming_mode=StreamingMode.BUFFERED,
        )
        rendered = "".join([chunk async for chunk in response.body_iterator])
        return rendered, audit, adapter, patch
    except Exception:
        patch.restore()
        raise


def measure_component_timing(chunks: tuple[bytes, ...]) -> ComponentTiming:
    decode_timer = HighResolutionTimer().start()
    decoder = Utf8IncrementalDecoder()
    decoded_chunks = []
    for chunk in chunks:
        text = decoder.decode(chunk)
        if text:
            decoded_chunks.append(text)
    tail = decoder.flush()
    if tail:
        decoded_chunks.append(tail)
    decode_ms = decode_timer.stop().elapsed_ms

    parse_timer = HighResolutionTimer().start()
    parser = SseParser()
    events = []
    for text in decoded_chunks:
        events.extend(parser.feed(text))
    try:
        events.extend(parser.flush())
    except Exception:
        pass
    parse_ms = parse_timer.stop().elapsed_ms

    state_timer = HighResolutionTimer().start()
    machine = StreamingRedactionStateMachine(max_window_chars=1024 * 1024)
    content_events = 0
    for event in events:
        if event.data is None:
            continue
        content = _extract_content(event.data.strip())
        if content is None:
            continue
        content_events += 1
        machine.append(ParsedSseEvent(data=content))
        machine.emit_safe()
    machine.end_of_stream()
    machine.flush()
    state_ms = state_timer.stop().elapsed_ms
    return ComponentTiming(
        utf8_decode_ms=decode_ms,
        sse_parse_ms=parse_ms,
        state_machine_ms=state_ms,
        event_count=content_events,
    )


def _extract_content(data: str) -> str | None:
    if data == "[DONE]":
        return None
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return None
    choices = payload.get("choices") or []
    if not choices:
        return None
    content = (choices[0].get("delta") or {}).get("content")
    return content if isinstance(content, str) else None


async def _measure_streaming_scenario(
    *,
    scenario: StreamingBenchmarkScenario,
    iterations: int,
    warmups: int,
    environment: BenchmarkEnvironmentContract,
) -> StreamingBenchmarkReport:
    plan = IterationPlan(warmups=warmups, iterations=iterations)
    chunks = chunks_for_scenario(scenario)
    component_samples = {
        "utf8_decode_ms": LatencySampleCollector(),
        "sse_parse_ms": LatencySampleCollector(),
        "state_machine_ms": LatencySampleCollector(),
    }

    for _ in range(plan.warmups):
        rendered, _audit, _adapter, patch = await render_streaming_response(scenario)
        patch.restore()
        _assert_rendered_shape(scenario, rendered)

    latency = LatencySampleCollector()
    memory = MemorySampleCollector()
    cpu = CpuSampleCollector()
    memory_sampler = TracemallocMemorySampler()
    cpu_sampler = ProcessCpuSampler()
    started_at = datetime.now(UTC)
    memory_sampler.start()
    cpu_sampler.start()
    wall_timer = HighResolutionTimer().start()
    last_audit = None
    last_patch = None
    last_adapter = None
    for _ in range(plan.iterations):
        timer = HighResolutionTimer().start()
        rendered, audit, adapter, patch = await render_streaming_response(scenario)
        latency.add(timer.stop().elapsed_ms)
        _assert_rendered_shape(scenario, rendered)
        memory.add(memory_sampler.sample_peak_bytes())
        component = measure_component_timing(chunks)
        component_samples["utf8_decode_ms"].add(component.utf8_decode_ms)
        component_samples["sse_parse_ms"].add(component.sse_parse_ms)
        component_samples["state_machine_ms"].add(component.state_machine_ms)
        if last_patch is not None:
            last_patch.restore()
        last_audit = audit
        last_patch = patch
        last_adapter = adapter
    wall_time_ms = wall_timer.stop().elapsed_ms
    cpu.add(cpu_sampler.sample_percent())
    memory_sampler.stop()
    completed_at = datetime.now(UTC)
    if last_patch is not None:
        tokenization_calls = int(last_patch.token_vault_store.await_count)
        last_patch.restore()
    else:
        tokenization_calls = 0

    contract = scenario.contract(iterations=iterations, warmups=warmups)
    metadata = BenchmarkMetadataContract(
        iterations=iterations,
        warmups=warmups,
        sample_count=len(latency.samples_ms),
        started_at=started_at,
        completed_at=completed_at,
        labels={
            "scenario": scenario.slug,
            "streaming_mode": StreamingMode.BUFFERED,
            "provider": "mock",
            "runtime_mutation": "false",
        },
    )
    benchmark = LatencyBenchmarkContract(
        benchmark_id=uuid.uuid4(),
        scenario=contract,
        environment=environment,
        metadata=metadata,
        thresholds=(DEFAULT_STREAMING_P95_THRESHOLD,),
        latency=latency.statistics(),
    )
    result = BenchmarkResultContract(
        result_id=uuid.uuid4(),
        benchmark=benchmark,
        notes=(
            "StreamingEngine measured via public stream_response interface with mocked provider chunks.",
            "Component contribution timings use existing UTF-8 decoder, SSE parser, and state machine directly.",
        ),
    )
    chunks_per_iteration = len(chunks)
    events_per_iteration = scenario.event_count
    return StreamingBenchmarkReport(
        scenario=contract,
        latency_result=result,
        event_throughput=throughput_measurement(
            total_operations=iterations * events_per_iteration,
            wall_time_ms=wall_time_ms,
            unit=BenchmarkUnit.EVENTS_PER_SECOND,
        ),
        chunk_throughput=throughput_measurement(
            total_operations=iterations * chunks_per_iteration,
            wall_time_ms=wall_time_ms,
            unit=BenchmarkUnit.EVENTS_PER_SECOND,
        ),
        memory=memory.measurement(),
        cpu=cpu.measurement(),
        component_latency_ms={
            name: collector.statistics().p50_ms
            for name, collector in component_samples.items()
        },
        policy_contribution_ms={
            "method": "included_in_stream_security_scan_path",
            "policy_enabled": bool(scenario.compiled_policy),
            "p50_ms": latency.statistics().p50_ms,
        },
        tokenization_contribution_ms={
            "method": "observed_existing_token_vault_store_batch_calls",
            "enabled": scenario.tokenization_enabled,
            "store_batch_calls": tokenization_calls,
        },
        chunks_processed=chunks_per_iteration * iterations,
        events_processed=events_per_iteration * iterations,
        audit_started_count=int(last_audit.publish_stream_started.await_count) if last_audit else 0,
        audit_completed_count=int(last_audit.publish_stream_completed.await_count) if last_audit else 0,
        audit_failed_count=int(last_audit.publish_stream_failed.await_count) if last_audit else 0,
    )


def _assert_rendered_shape(scenario: StreamingBenchmarkScenario, rendered: str) -> None:
    if scenario.expected_blocked:
        if "response_blocked" not in rendered:
            raise RuntimeError(f"expected_blocked_stream:{scenario.slug}")
        return
    if "data: [DONE]" not in rendered:
        raise RuntimeError(f"missing_done_sentinel:{scenario.slug}")
    if scenario.content_pattern == "pii" and "person@example.test" in rendered:
        raise RuntimeError(f"raw_pii_leaked:{scenario.slug}")


async def run_streaming_benchmarks(
    *,
    iterations: int = DEFAULT_ITERATIONS,
    warmups: int = DEFAULT_WARMUPS,
    scenarios: Iterable[StreamingBenchmarkScenario] | None = None,
) -> tuple[StreamingBenchmarkReport, ...]:
    if iterations < 1:
        raise ValueError("iterations_must_be_positive")
    if warmups < 0:
        raise ValueError("warmups_must_be_non_negative")
    environment = environment_snapshot(name="e4.3-streaming-performance", authclaw_version="v0.10.0")
    selected = tuple(scenarios or streaming_benchmark_scenarios())
    return tuple(
        [
            await _measure_streaming_scenario(
                scenario=scenario,
                iterations=iterations,
                warmups=warmups,
                environment=environment,
            )
            for scenario in selected
        ]
    )


def summarize_streaming_benchmarks(reports: Iterable[StreamingBenchmarkReport]) -> BenchmarkSummaryContract:
    reports_tuple = tuple(reports)
    threshold = DEFAULT_STREAMING_P95_THRESHOLD
    passed = 0
    failed = 0
    for report in reports_tuple:
        p95 = report.latency_result.benchmark.latency.p95_ms
        if p95 <= threshold.value:
            passed += 1
        else:
            failed += 1
    return BenchmarkSummaryContract(
        summary_id=uuid.uuid4(),
        assessment=BenchmarkAssessment.PASS if failed == 0 else BenchmarkAssessment.PARTIAL,
        total_scenarios=len(reports_tuple),
        passed_scenarios=passed,
        failed_scenarios=failed,
        thresholds=(threshold,),
        metadata={
            "target": BenchmarkTarget.STREAMING_LATENCY.value,
            "provider": "mock",
            "streaming_mode": StreamingMode.BUFFERED,
        },
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description="AuthClaw E4.3 Streaming performance benchmark")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    args = parser.parse_args()
    reports = await run_streaming_benchmarks(iterations=args.iterations, warmups=args.warmups)
    summary = summarize_streaming_benchmarks(reports)
    print(
        json.dumps(
            {
                "summary": summary.model_dump(mode="json"),
                "results": [report.as_dict() for report in reports],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
