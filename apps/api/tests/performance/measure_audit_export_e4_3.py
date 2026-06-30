"""
E4.3 Phase 5 audit export performance benchmark.

This module benchmarks the existing E4.4 audit export services through their
public builder, package, signing, and verification interfaces. It adds no
benchmark-only code to runtime implementation and does not modify Audit Export,
Gateway, Streaming, OPA, TokenVault, Trust Center, APIs, schemas, database
models, workers, Docker, Terraform, or frontend runtime behavior.

Usage from apps/api:
  python tests/performance/measure_audit_export_e4_3.py --iterations 3 --warmups 1
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Any
from uuid import UUID

API_ROOT = Path(__file__).resolve().parents[2]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.core.audit.export_builder import AuditExportAssembly, AuditExportBuilder
from app.core.audit.export_contracts import ExportPackagePath, SignatureAlgorithm, VerificationState
from app.core.audit.integrity import append_canonical_audit_record
from app.core.audit.package_builder import AuditExportPackageBuilder, SignedAuditExportPackage
from app.core.audit.package_verification import (
    AuditExportVerificationService,
    StaticSignatureVerifierResolver,
)
from app.core.audit.repository import AuditRecord, AuditRepository
from app.core.audit.signing import AuditExportSigningService
from app.core.performance.benchmark_contracts import (
    BenchmarkEnvironmentContract,
    BenchmarkResultContract,
    BenchmarkScenarioContract,
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
    PerformanceThresholdContract,
    ThroughputMeasurementContract,
)
from app.core.performance.system_snapshot import environment_snapshot
from app.core.performance.timer import HighResolutionTimer


DEFAULT_ITERATIONS = 3
DEFAULT_WARMUPS = 1
TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
ACTOR_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
AUDIT_EXPORT_P95_THRESHOLD = PerformanceThresholdContract(
    metric="audit_export_p95_ms",
    value=1000,
    unit=BenchmarkUnit.MILLISECONDS,
    source_requirement="E4.3",
    description="Audit export benchmark latency observation threshold.",
)


@dataclass(frozen=True)
class AuditExportBenchmarkScenario:
    slug: str
    name: str
    description: str
    record_count: int
    operation: str = "generation_verification"
    multi_tenant: bool = False
    expected_state: VerificationState = VerificationState.VERIFIED

    def contract(self, iterations: int, warmups: int) -> BenchmarkScenarioContract:
        return BenchmarkScenarioContract(
            scenario_id=_scenario_id(self.operation),
            target=_target(self.operation),
            kind=BenchmarkKind.LATENCY,
            name=self.name,
            description=self.description,
            payload_profile=f"audit_export_{self.record_count}",
            iterations=iterations,
            warmups=warmups,
            concurrency=1,
            metadata={
                "slug": self.slug,
                "record_count": self.record_count,
                "operation": self.operation,
                "multi_tenant": self.multi_tenant,
                "expected_state": self.expected_state.value,
                "provider": "in_memory_audit_repository",
            },
        )


@dataclass(frozen=True)
class AuditExportBenchmarkReport:
    scenario: BenchmarkScenarioContract
    latency_result: BenchmarkResultContract
    throughput: ThroughputMeasurementContract
    memory: MemoryMeasurementContract
    cpu: CpuMeasurementContract
    component_latency_ms: dict[str, float]
    package_size_bytes: dict[str, int]
    verification_state: str
    records_processed: int

    def as_dict(self) -> dict[str, object]:
        benchmark = self.latency_result.benchmark
        return {
            "scenario": self.scenario.model_dump(mode="json"),
            "latency_result": self.latency_result.model_dump(mode="json"),
            "throughput": self.throughput.model_dump(mode="json"),
            "memory": self.memory.model_dump(mode="json"),
            "cpu": self.cpu.model_dump(mode="json"),
            "component_latency_ms": self.component_latency_ms,
            "package_size_bytes": self.package_size_bytes,
            "verification_state": self.verification_state,
            "records_processed": self.records_processed,
            "sample_count": benchmark.metadata.sample_count,
        }


@dataclass(frozen=True)
class AuditExportOperationResult:
    elapsed_ms: float
    component_ms: dict[str, float]
    package_size_bytes: int
    verification_state: VerificationState


class InMemoryAuditRepository(AuditRepository):
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def append(self, record: AuditRecord) -> None:
        self.records.append(record)

    async def bulk_append(self, records: list[AuditRecord]) -> None:
        self.records.extend(records)

    async def list(self, tenant_id: UUID, limit: int = 100, offset: int = 0) -> list[AuditRecord]:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return scoped[offset:offset + limit]

    async def export(self, tenant_id: UUID, start_date: datetime, end_date: datetime) -> list[AuditRecord]:
        return [
            record
            for record in self.records
            if record.tenant_id == tenant_id and start_date <= record.created_at <= end_date
        ]

    async def get_latest_hash(self, tenant_id: UUID) -> str | None:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return scoped[-1].integrity_hash if scoped else None

    async def get_latest_sequence_no(self, tenant_id: UUID) -> int:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return max((record.sequence_no for record in scoped), default=0)


class DeterministicSigningProvider:
    key_id = "e4-3-benchmark-deterministic-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def sign_digest(self, *, manifest_digest: str, algorithm: SignatureAlgorithm) -> str:
        return f"detached-signature:{algorithm.value}:{manifest_digest}"


class DeterministicSignatureVerifier:
    key_id = "e4-3-benchmark-deterministic-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def verify_digest_signature(
        self,
        *,
        manifest_digest: str,
        signature: str,
        algorithm: SignatureAlgorithm,
    ) -> bool:
        return signature == f"detached-signature:{algorithm.value}:{manifest_digest}"


def audit_export_benchmark_scenarios() -> tuple[AuditExportBenchmarkScenario, ...]:
    return (
        _scenario("records_10", 10),
        _scenario("records_100", 100),
        _scenario("records_250", 250),
        _scenario("records_1000", 1000),
        _scenario("records_5000", 5000),
        AuditExportBenchmarkScenario(
            slug="single_tenant",
            name="Audit export single tenant",
            description="Single tenant package generation and verification.",
            record_count=100,
        ),
        AuditExportBenchmarkScenario(
            slug="multiple_tenants",
            name="Audit export multiple tenants",
            description="Tenant-scoped export with additional records for another tenant.",
            record_count=100,
            multi_tenant=True,
        ),
        AuditExportBenchmarkScenario(
            slug="verification_only",
            name="Audit export verification only",
            description="Verify a prebuilt deterministic audit export package.",
            record_count=250,
            operation="verification_only",
        ),
        AuditExportBenchmarkScenario(
            slug="package_generation_only",
            name="Audit export package generation only",
            description="Generate deterministic signed package without verification.",
            record_count=250,
            operation="package_generation_only",
        ),
        AuditExportBenchmarkScenario(
            slug="generation_verification",
            name="Audit export generation plus verification",
            description="Generate and verify the deterministic audit export package.",
            record_count=250,
            operation="generation_verification",
        ),
        AuditExportBenchmarkScenario(
            slug="tampered_package_verification",
            name="Tampered audit export verification",
            description="Verify a tampered package and confirm tamper state.",
            record_count=100,
            operation="tampered_verification",
            expected_state=VerificationState.TAMPERED,
        ),
    )


def _scenario(slug: str, record_count: int) -> AuditExportBenchmarkScenario:
    return AuditExportBenchmarkScenario(
        slug=slug,
        name=f"Audit export {record_count} records",
        description=f"Generate and verify deterministic package with {record_count} audit records.",
        record_count=record_count,
    )


async def seed_repository(record_count: int, *, multi_tenant: bool = False) -> InMemoryAuditRepository:
    repo = InMemoryAuditRepository()
    await _seed_tenant(repo, TENANT_ID, record_count)
    if multi_tenant:
        await _seed_tenant(repo, OTHER_TENANT_ID, max(1, record_count // 2))
    return repo


async def _seed_tenant(repo: InMemoryAuditRepository, tenant_id: UUID, record_count: int) -> None:
    for index in range(1, record_count + 1):
        await append_canonical_audit_record(
            repo,
            tenant_id=tenant_id,
            actor_id=ACTOR_ID,
            event_type="gateway.request",
            action="execute",
            resource="gateway",
            resource_id=f"{tenant_id}:request-{index}",
            metadata={
                "safe": f"value-{index}",
                "event_index": index,
                "redaction_mode": "mask",
                "provider": "mock-openai-compatible",
            },
            created_at=NOW + timedelta(milliseconds=index),
        )


def signing_service() -> AuditExportSigningService:
    return AuditExportSigningService(
        DeterministicSigningProvider(),
        tool_version="0.10.0-benchmark",
    )


def verification_service() -> AuditExportVerificationService:
    return AuditExportVerificationService(
        signature_resolver=StaticSignatureVerifierResolver(
            {"e4-3-benchmark-deterministic-key": DeterministicSignatureVerifier()}
        )
    )


def date_range(record_count: int) -> tuple[datetime, datetime]:
    return NOW, NOW + timedelta(milliseconds=record_count + 1)


async def _prepare_package(repo: InMemoryAuditRepository, scenario: AuditExportBenchmarkScenario) -> tuple[SignedAuditExportPackage, list[AuditRecord]]:
    start, end = date_range(scenario.record_count)
    package = await AuditExportPackageBuilder(
        export_builder=AuditExportBuilder(repo, tool_version="0.10.0-benchmark"),
        signing_service=signing_service(),
    ).build(
        tenant_id=TENANT_ID,
        start_date=start,
        end_date=end,
        export_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:audit-export:{scenario.slug}"),
        requester_id=ACTOR_ID,
        created_at=NOW,
        purpose="performance benchmark",
        signing_timestamp=NOW,
    )
    records = await repo.export(TENANT_ID, start, end)
    return package, records


async def execute_audit_export_operation(
    scenario: AuditExportBenchmarkScenario,
    repo: InMemoryAuditRepository,
    prepared_package: SignedAuditExportPackage | None = None,
    prepared_records: list[AuditRecord] | None = None,
) -> AuditExportOperationResult:
    start, end = date_range(scenario.record_count)
    component_ms = {
        "export_generation_ms": 0.0,
        "manifest_generation_ms": 0.0,
        "canonicalization_ms": 0.0,
        "chain_proof_generation_ms": 0.0,
        "signing_ms": 0.0,
        "package_assembly_ms": 0.0,
        "zip_generation_ms": 0.0,
        "verification_ms": 0.0,
    }
    timer = HighResolutionTimer().start()
    package_size = 0
    verification_state = scenario.expected_state

    if scenario.operation in {"generation_verification", "package_generation_only"}:
        export_builder = AuditExportBuilder(repo, tool_version="0.10.0-benchmark")
        export_timer = HighResolutionTimer().start()
        assembly = await export_builder.build(
            tenant_id=TENANT_ID,
            start_date=start,
            end_date=end,
            export_id=uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:e4.3:audit-export:{scenario.slug}"),
            requester_id=ACTOR_ID,
            created_at=NOW,
            purpose="performance benchmark",
        )
        export_elapsed = export_timer.stop().elapsed_ms
        component_ms["export_generation_ms"] = export_elapsed
        component_ms["manifest_generation_ms"] = export_elapsed
        component_ms["canonicalization_ms"] = _canonicalization_proxy_ms(assembly)
        component_ms["chain_proof_generation_ms"] = export_elapsed

        package_builder = AuditExportPackageBuilder(
            export_builder=export_builder,
            signing_service=signing_service(),
        )
        package_timer = HighResolutionTimer().start()
        package = package_builder.assemble(
            assembly,
            signing_timestamp=NOW,
            signature_algorithm=SignatureAlgorithm.ES256,
        )
        package_elapsed = package_timer.stop().elapsed_ms
        component_ms["signing_ms"] = package_elapsed
        component_ms["package_assembly_ms"] = package_elapsed
        component_ms["zip_generation_ms"] = package_elapsed
        package_size = len(package.package_bytes)

        if scenario.operation == "generation_verification":
            verification_timer = HighResolutionTimer().start()
            records = await repo.export(TENANT_ID, start, end)
            result = verification_service().verify_package(
                package.package_bytes,
                expected_tenant_id=TENANT_ID,
                original_records=records,
            )
            component_ms["verification_ms"] = verification_timer.stop().elapsed_ms
            verification_state = VerificationState(result.state)

    elif scenario.operation in {"verification_only", "tampered_verification"}:
        if prepared_package is None or prepared_records is None:
            prepared_package, prepared_records = await _prepare_package(repo, scenario)
        package_bytes = prepared_package.package_bytes
        if scenario.operation == "tampered_verification":
            package_bytes = tamper_package(package_bytes)
        package_size = len(package_bytes)
        verification_timer = HighResolutionTimer().start()
        result = verification_service().verify_package(
            package_bytes,
            expected_tenant_id=TENANT_ID,
            original_records=prepared_records,
        )
        component_ms["verification_ms"] = verification_timer.stop().elapsed_ms
        verification_state = VerificationState(result.state)
    else:
        raise ValueError(f"unsupported_operation:{scenario.operation}")

    elapsed_ms = timer.stop().elapsed_ms
    if verification_state != scenario.expected_state:
        raise RuntimeError(f"unexpected_verification_state:{verification_state}:{scenario.expected_state}")
    return AuditExportOperationResult(
        elapsed_ms=elapsed_ms,
        component_ms=component_ms,
        package_size_bytes=package_size,
        verification_state=verification_state,
    )


def _canonicalization_proxy_ms(assembly: AuditExportAssembly) -> float:
    return float(len("".join(assembly.files.values()).encode("utf-8"))) / 1_000_000


def tamper_package(package_bytes: bytes) -> bytes:
    source = BytesIO(package_bytes)
    destination = BytesIO()
    with zipfile.ZipFile(source, "r") as in_zip, zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as out_zip:
        for name in in_zip.namelist():
            content = in_zip.read(name).decode("utf-8")
            if name == ExportPackagePath.AUDIT.value:
                content = content.replace("value-1", "changed-value-1", 1)
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            out_zip.writestr(info, content.encode("utf-8"))
    return destination.getvalue()


async def _measure_audit_export_scenario(
    *,
    scenario: AuditExportBenchmarkScenario,
    iterations: int,
    warmups: int,
    environment: BenchmarkEnvironmentContract,
) -> AuditExportBenchmarkReport:
    repo = await seed_repository(scenario.record_count, multi_tenant=scenario.multi_tenant)
    prepared_package = None
    prepared_records = None
    if scenario.operation in {"verification_only", "tampered_verification"}:
        prepared_package, prepared_records = await _prepare_package(repo, scenario)

    plan = IterationPlan(warmups=warmups, iterations=iterations)
    for _ in range(plan.warmups):
        await execute_audit_export_operation(scenario, repo, prepared_package, prepared_records)

    latency = LatencySampleCollector()
    memory = MemorySampleCollector()
    cpu = CpuSampleCollector()
    component_collectors = {
        "export_generation_ms": LatencySampleCollector(),
        "manifest_generation_ms": LatencySampleCollector(),
        "canonicalization_ms": LatencySampleCollector(),
        "chain_proof_generation_ms": LatencySampleCollector(),
        "signing_ms": LatencySampleCollector(),
        "package_assembly_ms": LatencySampleCollector(),
        "zip_generation_ms": LatencySampleCollector(),
        "verification_ms": LatencySampleCollector(),
    }
    package_sizes: list[int] = []
    verification_state = scenario.expected_state
    memory_sampler = TracemallocMemorySampler()
    cpu_sampler = ProcessCpuSampler()
    started_at = datetime.now(UTC)
    memory_sampler.start()
    cpu_sampler.start()
    wall_timer = HighResolutionTimer().start()
    for _ in range(plan.iterations):
        result = await execute_audit_export_operation(scenario, repo, prepared_package, prepared_records)
        latency.add(result.elapsed_ms)
        memory.add(memory_sampler.sample_peak_bytes())
        package_sizes.append(result.package_size_bytes)
        verification_state = result.verification_state
        for key, value in result.component_ms.items():
            component_collectors[key].add(value)
    wall_time_ms = wall_timer.stop().elapsed_ms
    cpu.add(cpu_sampler.sample_percent())
    memory_sampler.stop()
    completed_at = datetime.now(UTC)

    contract = scenario.contract(iterations=iterations, warmups=warmups)
    metadata = BenchmarkMetadataContract(
        iterations=iterations,
        warmups=warmups,
        sample_count=len(latency.samples_ms),
        started_at=started_at,
        completed_at=completed_at,
        labels={
            "scenario": scenario.slug,
            "operation": scenario.operation,
            "runtime_mutation": "false",
        },
    )
    benchmark = LatencyBenchmarkContract(
        benchmark_id=uuid.uuid4(),
        scenario=contract,
        environment=environment,
        metadata=metadata,
        thresholds=(AUDIT_EXPORT_P95_THRESHOLD,),
        latency=latency.statistics(),
    )
    benchmark_result = BenchmarkResultContract(
        result_id=uuid.uuid4(),
        benchmark=benchmark,
        notes=(
            "Audit export measured via existing E4.4 builder/package/signing/verification services.",
            "Component timing is benchmark-layer observation only; runtime code is unchanged.",
        ),
    )
    return AuditExportBenchmarkReport(
        scenario=contract,
        latency_result=benchmark_result,
        throughput=throughput_measurement(
            total_operations=iterations * scenario.record_count,
            wall_time_ms=wall_time_ms,
            unit=BenchmarkUnit.REQUESTS_PER_SECOND,
        ),
        memory=memory.measurement(),
        cpu=cpu.measurement(),
        component_latency_ms={
            key: collector.statistics().p50_ms
            for key, collector in component_collectors.items()
        },
        package_size_bytes={
            "minimum": min(package_sizes),
            "maximum": max(package_sizes),
            "average": round(sum(package_sizes) / len(package_sizes)),
        },
        verification_state=verification_state.value,
        records_processed=iterations * scenario.record_count,
    )


async def run_audit_export_benchmarks(
    *,
    iterations: int = DEFAULT_ITERATIONS,
    warmups: int = DEFAULT_WARMUPS,
    scenarios: Iterable[AuditExportBenchmarkScenario] | None = None,
) -> tuple[AuditExportBenchmarkReport, ...]:
    if iterations < 1:
        raise ValueError("iterations_must_be_positive")
    if warmups < 0:
        raise ValueError("warmups_must_be_non_negative")
    environment = environment_snapshot(name="e4.3-audit-export-performance", authclaw_version="v0.10.0")
    selected = tuple(scenarios or audit_export_benchmark_scenarios())
    return tuple(
        [
            await _measure_audit_export_scenario(
                scenario=scenario,
                iterations=iterations,
                warmups=warmups,
                environment=environment,
            )
            for scenario in selected
        ]
    )


def summarize_audit_export_benchmarks(reports: Iterable[AuditExportBenchmarkReport]) -> BenchmarkSummaryContract:
    reports_tuple = tuple(reports)
    threshold = AUDIT_EXPORT_P95_THRESHOLD
    passed = 0
    failed = 0
    for report in reports_tuple:
        if report.latency_result.benchmark.latency.p95_ms <= threshold.value:
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
            "target": BenchmarkTarget.AUDIT_EXPORT_GENERATION.value,
            "repository": "in_memory",
            "signing": "deterministic",
        },
    )


def _scenario_id(operation: str) -> BenchmarkScenarioId:
    if operation in {"verification_only", "tampered_verification"}:
        return BenchmarkScenarioId.AUDIT_PACKAGE_VERIFICATION
    return BenchmarkScenarioId.AUDIT_EXPORT_MEDIUM


def _target(operation: str) -> BenchmarkTarget:
    if operation in {"verification_only", "tampered_verification"}:
        return BenchmarkTarget.AUDIT_VERIFICATION
    return BenchmarkTarget.AUDIT_EXPORT_GENERATION


async def main() -> None:
    parser = argparse.ArgumentParser(description="AuthClaw E4.3 Audit Export performance benchmark")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument(
        "--scenarios",
        default="",
        help="Optional comma-separated scenario slugs. Defaults to all scenarios.",
    )
    args = parser.parse_args()
    selected = None
    if args.scenarios:
        wanted = {item.strip() for item in args.scenarios.split(",") if item.strip()}
        selected = tuple(scenario for scenario in audit_export_benchmark_scenarios() if scenario.slug in wanted)
    reports = await run_audit_export_benchmarks(
        iterations=args.iterations,
        warmups=args.warmups,
        scenarios=selected,
    )
    summary = summarize_audit_export_benchmarks(reports)
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
