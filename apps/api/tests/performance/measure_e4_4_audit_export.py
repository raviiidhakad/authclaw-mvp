from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.core.audit.export_builder import AuditExportBuilder
from app.core.audit.integrity import append_canonical_audit_record
from app.core.audit.package_builder import AuditExportPackageBuilder
from app.core.audit.package_verification import (
    AuditExportVerificationService,
    StaticSignatureVerifierResolver,
)
from app.core.audit.repository import AuditRecord, AuditRepository
from app.core.audit.signing import AuditExportSigningService
from app.core.audit.export_contracts import SignatureAlgorithm


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
ACTOR_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


class InMemoryAuditRepository(AuditRepository):
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def append(self, record: AuditRecord) -> None:
        self.records.append(record)

    async def bulk_append(self, records: list[AuditRecord]) -> None:
        self.records.extend(records)

    async def list(self, tenant_id: UUID, limit: int = 100, offset: int = 0) -> list[AuditRecord]:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return scoped[offset : offset + limit]

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
    key_id = "benchmark-deterministic-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def sign_digest(self, *, manifest_digest: str, algorithm: SignatureAlgorithm) -> str:
        return f"detached-signature:{algorithm.value}:{manifest_digest}"


class DeterministicSignatureVerifier:
    key_id = "benchmark-deterministic-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def verify_digest_signature(
        self,
        *,
        manifest_digest: str,
        signature: str,
        algorithm: SignatureAlgorithm,
    ) -> bool:
        return signature == f"detached-signature:{algorithm.value}:{manifest_digest}"


async def _seed_records(record_count: int) -> InMemoryAuditRepository:
    repo = InMemoryAuditRepository()
    for index in range(1, record_count + 1):
        await append_canonical_audit_record(
            repo,
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_type="gateway.request",
            action="execute",
            resource="gateway",
            resource_id=f"request-{index}",
            metadata={
                "safe": f"value-{index}",
                "event_index": index,
                "redaction_mode": "mask",
                "provider": "mock-openai-compatible",
            },
            created_at=NOW + timedelta(milliseconds=index),
        )
    return repo


async def _build_and_verify(record_count: int) -> dict[str, object]:
    repo = await _seed_records(record_count)
    start = NOW
    end = NOW + timedelta(minutes=10)
    signing_service = AuditExportSigningService(
        DeterministicSigningProvider(),
        tool_version="0.9.0-benchmark",
    )
    package_builder = AuditExportPackageBuilder(
        export_builder=AuditExportBuilder(repo, tool_version="0.9.0-benchmark"),
        signing_service=signing_service,
    )
    verifier = AuditExportVerificationService(
        signature_resolver=StaticSignatureVerifierResolver(
            {"benchmark-deterministic-key": DeterministicSignatureVerifier()}
        )
    )

    generation_started = time.perf_counter()
    package = await package_builder.build(
        tenant_id=TENANT_ID,
        start_date=start,
        end_date=end,
        created_at=NOW,
        signing_timestamp=NOW,
    )
    generation_ms = (time.perf_counter() - generation_started) * 1000

    records = await repo.export(TENANT_ID, start, end)
    verification_started = time.perf_counter()
    verification_result = verifier.verify_package(
        package.package_bytes,
        expected_tenant_id=TENANT_ID,
        original_records=records,
    )
    verification_ms = (time.perf_counter() - verification_started) * 1000

    return {
        "record_count": record_count,
        "generation_ms": generation_ms,
        "verification_ms": verification_ms,
        "package_size_bytes": len(package.package_bytes),
        "verification_state": verification_result.state,
        "manifest_digest_present": bool(verification_result.manifest_digest),
    }


def _stats(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "p99_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))], 3),
        "max_ms": round(max(ordered), 3),
    }


async def run_benchmark(record_counts: list[int], iterations: int, warmup: int) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for record_count in record_counts:
        for _ in range(warmup):
            await _build_and_verify(record_count)
        generation_samples: list[float] = []
        verification_samples: list[float] = []
        package_sizes: list[int] = []
        tracemalloc.start()
        try:
            for _ in range(iterations):
                result = await _build_and_verify(record_count)
                generation_samples.append(float(result["generation_ms"]))
                verification_samples.append(float(result["verification_ms"]))
                package_sizes.append(int(result["package_size_bytes"]))
                if result["verification_state"] != "Verified":
                    raise RuntimeError("benchmark package verification failed")
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        results.append(
            {
                "record_count": record_count,
                "iterations": iterations,
                "generation": _stats(generation_samples),
                "verification": _stats(verification_samples),
                "package_size_bytes": {
                    "min": min(package_sizes),
                    "max": max(package_sizes),
                    "median": int(statistics.median(package_sizes)),
                },
                "peak_memory_kb": round(peak_bytes / 1024, 1),
            }
        )
    return {
        "benchmark": "e4.4-audit-export",
        "record_counts": record_counts,
        "iterations": iterations,
        "warmup": warmup,
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-counts", default="10,250,1000")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    args = parser.parse_args()
    record_counts = [int(value.strip()) for value in args.record_counts.split(",") if value.strip()]
    output = asyncio.run(run_benchmark(record_counts, args.iterations, args.warmup))
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
