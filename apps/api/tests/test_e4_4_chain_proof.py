from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.audit.chain_proof import (
    CHAIN_PROOF_SCHEMA_VERSION,
    MANIFEST_DIGEST_PLACEHOLDER,
    ChainProofService,
    compute_record_hash,
)
from app.core.audit.export_contracts import HashAlgorithm, TimeRangeContract
from app.core.audit.repository import AuditRecord
from app.core.events.audit_hash import GENESIS_HASH


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
ACTOR_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


def _time_range() -> TimeRangeContract:
    return TimeRangeContract(start_at=NOW, end_at=NOW + timedelta(minutes=5))


def _record(
    suffix: int,
    *,
    tenant_id: UUID = TENANT_ID,
    sequence_no: int | None = None,
    previous_hash: str = GENESIS_HASH,
    metadata: dict | None = None,
    integrity_hash: str | None = None,
) -> AuditRecord:
    record = AuditRecord(
        record_id=UUID(f"aaaaaaaa-aaaa-4aaa-8aaa-{suffix:012d}"),
        tenant_id=tenant_id,
        sequence_no=sequence_no if sequence_no is not None else suffix,
        created_at=NOW + timedelta(seconds=suffix),
        actor_id=ACTOR_ID,
        actor_type="user",
        action="execute",
        frameworks_affected=["SOC2"],
        resource="gateway",
        resource_id=f"route-{suffix}",
        execution_trace=None,
        metadata=metadata or {"event_type": "gateway.request", "safe": f"value-{suffix}"},
        ip_address=None,
        user_agent=None,
        previous_hash=previous_hash,
        integrity_hash=integrity_hash or "",
    )
    return record.model_copy(update={"integrity_hash": integrity_hash or compute_record_hash(record)})


def _valid_chain(count: int = 3) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    previous_hash = GENESIS_HASH
    for suffix in range(1, count + 1):
        record = _record(suffix, previous_hash=previous_hash)
        records.append(record)
        previous_hash = record.integrity_hash
    return records


def test_chain_proof_generates_and_verifies_valid_multi_record_chain():
    service = ChainProofService()
    records = _valid_chain(3)

    proof = service.generate(
        tenant_id=TENANT_ID,
        records=records,
        time_range=_time_range(),
    )
    result = service.verify(proof=proof, records=records)

    assert proof.schema_version == CHAIN_PROOF_SCHEMA_VERSION
    assert proof.chain_proof.tenant_id == TENANT_ID
    assert proof.chain_proof.record_range.record_count == 3
    assert proof.chain_proof.start_previous_hash == GENESIS_HASH
    assert proof.chain_proof.expected_final_integrity_hash == records[-1].integrity_hash
    assert proof.chain_proof.manifest_digest == MANIFEST_DIGEST_PLACEHOLDER
    assert result.chain_valid is True
    assert result.tampered_records == ()
    assert result.missing_records == ()
    assert result.chain_breaks == ()
    assert result.errors == ()


def test_chain_proof_verifies_single_record_chain():
    service = ChainProofService()
    records = _valid_chain(1)

    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    result = service.verify(proof=proof, records=records)

    assert result.chain_valid is True
    assert result.start_record_id == str(records[0].record_id)
    assert result.end_record_id == str(records[0].record_id)
    assert result.final_integrity_hash == records[0].integrity_hash


def test_chain_proof_detects_broken_previous_hash():
    service = ChainProofService()
    first = _record(1, previous_hash=GENESIS_HASH)
    second = _record(2, previous_hash="not-the-first-hash")
    records = [first, second]

    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    result = service.verify(proof=proof, records=records)

    assert result.chain_valid is False
    assert result.chain_breaks == (str(second.record_id),)
    assert result.tampered_records == ()


def test_chain_proof_detects_integrity_hash_mismatch():
    service = ChainProofService()
    records = _valid_chain(2)
    tampered = records[1].model_copy(update={"integrity_hash": "bad-hash"})

    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    result = service.verify(proof=proof, records=[records[0], tampered])

    assert result.chain_valid is False
    assert result.tampered_records == (str(tampered.record_id),)
    assert "final_integrity_hash_mismatch" in result.errors


def test_chain_proof_detects_missing_sequence_number():
    service = ChainProofService()
    first = _record(1, sequence_no=1, previous_hash=GENESIS_HASH)
    third = _record(3, sequence_no=3, previous_hash=first.integrity_hash)
    records = [first, third]

    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    result = service.verify(proof=proof, records=records)

    assert result.chain_valid is False
    assert result.missing_records == ("2",)


def test_chain_proof_generation_rejects_cross_tenant_records():
    service = ChainProofService()
    records = [_record(1), _record(2, tenant_id=OTHER_TENANT_ID)]

    try:
        service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    except ValueError as exc:
        assert "cross-tenant" in str(exc)
    else:
        raise AssertionError("expected cross-tenant proof generation to fail")


def test_chain_proof_verification_detects_tenant_mismatch():
    service = ChainProofService()
    records = _valid_chain(1)
    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())

    result = service.verify(
        proof=proof,
        records=records,
        expected_tenant_id=OTHER_TENANT_ID,
    )

    assert result.chain_valid is False
    assert "tenant_mismatch" in result.errors
    assert "cross_tenant_record" in result.errors


def test_chain_proof_detects_unsupported_schema_version():
    service = ChainProofService()
    records = _valid_chain(1)
    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    raw = proof.model_dump(mode="json", by_alias=True)
    raw["schema_version"] = 999

    result = service.verify(proof=raw, records=records)

    assert result.chain_valid is False
    assert result.errors == ("unsupported_schema_version",)


def test_chain_proof_detects_unsupported_hash_algorithm():
    service = ChainProofService()
    records = _valid_chain(1)
    proof = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    raw = proof.model_dump(mode="json", by_alias=True)
    raw["chain_proof"]["hash_algorithm"] = "SHA-512"

    result = service.verify(proof=raw, records=records)

    assert result.chain_valid is False
    assert result.errors == ("unsupported_hash_algorithm",)


def test_chain_proof_detects_manifest_digest_mismatch_placeholder():
    service = ChainProofService()
    records = _valid_chain(1)
    proof = service.generate(
        tenant_id=TENANT_ID,
        records=records,
        time_range=_time_range(),
        manifest_digest="manifest-placeholder-a",
    )

    result = service.verify(
        proof=proof,
        records=records,
        expected_manifest_digest="manifest-placeholder-b",
    )

    assert result.chain_valid is False
    assert result.errors == ("manifest_digest_mismatch",)


def test_chain_proof_output_is_deterministic_and_canonical():
    service = ChainProofService()
    records = list(reversed(_valid_chain(3)))

    proof_a = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())
    proof_b = service.generate(tenant_id=TENANT_ID, records=records, time_range=_time_range())

    assert service.canonical_document(proof_a) == service.canonical_document(proof_b)
    assert [record.sequence_no for record in proof_a.records] == [1, 2, 3]
    assert proof_a.chain_proof.hash_algorithm == HashAlgorithm.SHA_256
