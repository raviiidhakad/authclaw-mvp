from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.core.audit.chain_proof import ChainProofService
from app.core.audit.export_builder import AuditExportBuilder
from app.core.audit.integrity import (
    append_canonical_audit_record,
    compute_canonical_record_hash,
    validate_canonical_record,
)
from app.core.audit.package_builder import AuditExportPackageBuilder
from app.core.audit.package_verification import (
    AuditExportVerificationService,
    StaticSignatureVerifierResolver,
)
from app.core.audit.repository import AuditRecord, AuditRepository
from app.core.audit.signing import AuditExportSigningService
from app.core.events.audit_hash import GENESIS_HASH
from app.core.audit.export_contracts import SignatureAlgorithm, VerificationState


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
ACTOR_ID = UUID("33333333-3333-4333-8333-333333333333")
EXPORT_ID = UUID("22222222-2222-4222-8222-222222222222")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


class InMemoryCanonicalAuditRepository(AuditRepository):
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def append(self, record: AuditRecord) -> None:
        validate_canonical_record(record)
        self.records.append(record)

    async def bulk_append(self, records: list[AuditRecord]) -> None:
        for record in records:
            await self.append(record)

    async def list(self, tenant_id: UUID, limit: int = 100, offset: int = 0) -> list[AuditRecord]:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return scoped[offset : offset + limit]

    async def export(
        self,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> list[AuditRecord]:
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
    key_id = "phase7-deterministic-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def sign_digest(self, *, manifest_digest: str, algorithm: SignatureAlgorithm) -> str:
        return f"detached-signature:{algorithm.value}:{manifest_digest}"


class DeterministicSignatureVerifier:
    key_id = "phase7-deterministic-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def verify_digest_signature(
        self,
        *,
        manifest_digest: str,
        signature: str,
        algorithm: SignatureAlgorithm,
    ) -> bool:
        return signature == f"detached-signature:{algorithm.value}:{manifest_digest}"


async def _append(
    repo: InMemoryCanonicalAuditRepository,
    suffix: int,
    *,
    tenant_id: UUID = TENANT_ID,
    event_type: str = "gateway.request",
) -> AuditRecord:
    return await append_canonical_audit_record(
        repo,
        tenant_id=tenant_id,
        actor_id=ACTOR_ID,
        event_type=event_type,
        action="execute",
        resource="gateway",
        resource_id=f"request-{suffix}",
        metadata={"safe": f"value-{suffix}"},
        created_at=NOW + timedelta(seconds=suffix),
    )


def _direct_valid_legacy_record() -> AuditRecord:
    record = AuditRecord(
        record_id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-000000000001"),
        tenant_id=TENANT_ID,
        sequence_no=1,
        created_at=NOW,
        actor_id=ACTOR_ID,
        actor_type="user",
        action="execute",
        frameworks_affected=[],
        resource="legacy",
        resource_id="legacy-1",
        execution_trace=None,
        metadata={"event_type": "gateway_request", "safe": "legacy"},
        ip_address=None,
        user_agent=None,
        previous_hash=GENESIS_HASH,
        integrity_hash="",
    )
    return record.model_copy(update={"integrity_hash": compute_canonical_record_hash(record)})


def _assert_continuous(records: list[AuditRecord]) -> None:
    ordered = sorted(records, key=lambda record: record.sequence_no)
    expected_previous = GENESIS_HASH
    for record in ordered:
        assert record.previous_hash == expected_previous
        assert record.integrity_hash == compute_canonical_record_hash(record)
        expected_previous = record.integrity_hash


@pytest.mark.asyncio
async def test_canonical_audit_write_path_populates_integrity_fields():
    repo = InMemoryCanonicalAuditRepository()

    record = await _append(repo, 1)

    assert record.previous_hash == GENESIS_HASH
    assert record.integrity_hash == compute_canonical_record_hash(record)
    assert record.sequence_no == 1
    assert record.metadata["event_type"] == "gateway_request"
    assert repo.records == [record]


@pytest.mark.asyncio
async def test_mixed_write_path_regression_preserves_chain_continuity():
    repo = InMemoryCanonicalAuditRepository()
    legacy = _direct_valid_legacy_record()
    await repo.append(legacy)

    next_record = await _append(repo, 2)

    assert next_record.previous_hash == legacy.integrity_hash
    _assert_continuous(repo.records)


@pytest.mark.asyncio
async def test_chain_continuity_for_multiple_exportable_records():
    repo = InMemoryCanonicalAuditRepository()
    for suffix in range(1, 8):
        await _append(repo, suffix)

    assert len(repo.records) == 7
    _assert_continuous(repo.records)


@pytest.mark.asyncio
async def test_concurrent_writes_remain_linear_with_tenant_serialization():
    repo = InMemoryCanonicalAuditRepository()
    tenant_lock = asyncio.Lock()

    async def write(suffix: int) -> AuditRecord:
        async with tenant_lock:
            return await _append(repo, suffix)

    await asyncio.gather(*(write(suffix) for suffix in range(1, 26)))

    assert len(repo.records) == 25
    previous_hashes = [record.previous_hash for record in repo.records]
    assert len(previous_hashes) == len(set(previous_hashes))
    _assert_continuous(repo.records)


@pytest.mark.asyncio
async def test_large_export_consistency_verifies_chain_proof():
    repo = InMemoryCanonicalAuditRepository()
    for suffix in range(1, 151):
        await _append(repo, suffix)

    records = await repo.export(TENANT_ID, NOW, NOW + timedelta(minutes=5))
    assembly = await AuditExportBuilder(repo, tool_version="0.9.0-test").build(
        tenant_id=TENANT_ID,
        start_date=NOW,
        end_date=NOW + timedelta(minutes=5),
        export_id=EXPORT_ID,
        created_at=NOW,
    )
    result = ChainProofService().verify(
        proof=assembly.chain_proof,
        records=records,
        expected_tenant_id=TENANT_ID,
    )

    assert len(records) == 150
    assert result.chain_valid is True
    assert result.record_count == 150


@pytest.mark.asyncio
async def test_tenant_isolation_keeps_independent_chain_roots():
    repo = InMemoryCanonicalAuditRepository()

    tenant_a = await _append(repo, 1, tenant_id=TENANT_ID)
    tenant_b = await _append(repo, 1, tenant_id=OTHER_TENANT_ID)
    tenant_a_next = await _append(repo, 2, tenant_id=TENANT_ID)

    assert tenant_a.previous_hash == GENESIS_HASH
    assert tenant_b.previous_hash == GENESIS_HASH
    assert tenant_a_next.previous_hash == tenant_a.integrity_hash


@pytest.mark.asyncio
async def test_legacy_event_type_compatibility_normalizes_exportable_metadata():
    repo = InMemoryCanonicalAuditRepository()

    record = await _append(repo, 1, event_type="gateway.stream.started")

    assert record.metadata["event_type"] == "gateway_stream_started"
    validate_canonical_record(record)


@pytest.mark.asyncio
async def test_export_verification_after_audit_path_hardening():
    repo = InMemoryCanonicalAuditRepository()
    for suffix in range(1, 4):
        await _append(repo, suffix)

    export_builder = AuditExportBuilder(repo, tool_version="0.9.0-test")
    signing_service = AuditExportSigningService(
        DeterministicSigningProvider(),
        tool_version="0.9.0-test",
    )
    package = await AuditExportPackageBuilder(
        export_builder=export_builder,
        signing_service=signing_service,
    ).build(
        tenant_id=TENANT_ID,
        start_date=NOW,
        end_date=NOW + timedelta(minutes=1),
        export_id=EXPORT_ID,
        created_at=NOW,
        signing_timestamp=NOW,
    )
    verifier = AuditExportVerificationService(
        signature_resolver=StaticSignatureVerifierResolver(
            {"phase7-deterministic-key": DeterministicSignatureVerifier()}
        )
    )

    result = verifier.verify_package(
        package.package_bytes,
        expected_tenant_id=TENANT_ID,
        original_records=await repo.export(TENANT_ID, NOW, NOW + timedelta(minutes=1)),
    )

    assert result.state == VerificationState.VERIFIED
    assert result.chain_valid is True
    assert result.signature_valid is True
