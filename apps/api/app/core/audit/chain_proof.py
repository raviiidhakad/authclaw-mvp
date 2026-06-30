"""
E4.4 Phase 3 audit chain proof generation and verification.

This module reuses AuthClaw's existing audit hash computation. It does not sign
proofs, package ZIP files, expose APIs, persist database rows, or modify audit
write paths.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Mapping, Sequence
from uuid import UUID

from pydantic import Field, ValidationError

from app.core.audit.export_contracts import (
    AUDIT_EXPORT_SCHEMA,
    CanonicalizationIdentifier,
    ChainProofContract,
    ChainProofResultContract,
    ExportContractModel,
    HashAlgorithm,
    TimeRangeContract,
)
from app.core.audit.repository import AuditRecord
from app.core.audit.integrity import compute_canonical_record_hash
from app.services.trust_reporting import canonical_json


CHAIN_PROOF_SCHEMA = "authclaw.audit.chain-proof/v1"
CHAIN_PROOF_SCHEMA_VERSION = 1
MANIFEST_DIGEST_PLACEHOLDER = "PENDING_MANIFEST_DIGEST"


class ChainProofRecordContract(ExportContractModel):
    """Minimal per-record chain metadata safe for chain-proof export."""

    record_id: str
    tenant_id: UUID
    sequence_no: int = Field(ge=0)
    created_at: datetime
    previous_hash: str
    integrity_hash: str


class ChainProofDocument(ExportContractModel):
    """Canonical chain-proof.json document produced by Phase 3."""

    schema_id: str = Field(CHAIN_PROOF_SCHEMA, alias="schema")
    schema_version: int = CHAIN_PROOF_SCHEMA_VERSION
    package_schema: str = AUDIT_EXPORT_SCHEMA
    chain_proof: ChainProofContract
    records: tuple[ChainProofRecordContract, ...] = ()


class ChainProofService:
    """Generate and verify deterministic tenant-scoped audit chain proofs."""

    def generate(
        self,
        *,
        tenant_id: UUID,
        records: Sequence[AuditRecord],
        time_range: TimeRangeContract,
        manifest_digest: str = MANIFEST_DIGEST_PLACEHOLDER,
    ) -> ChainProofDocument:
        ordered_records = order_audit_records(records)
        self._assert_tenant_scoped(tenant_id, ordered_records)

        if ordered_records:
            first = ordered_records[0]
            last = ordered_records[-1]
            start_record_id = str(first.record_id)
            end_record_id = str(last.record_id)
            start_previous_hash = first.previous_hash
            expected_final_integrity_hash = last.integrity_hash
        else:
            start_record_id = ""
            end_record_id = ""
            start_previous_hash = ""
            expected_final_integrity_hash = ""

        return ChainProofDocument(
            chain_proof=ChainProofContract(
                tenant_id=tenant_id,
                record_range={
                    "tenant_id": tenant_id,
                    "start_record_id": start_record_id,
                    "end_record_id": end_record_id,
                    "record_count": len(ordered_records),
                    "time_range": time_range,
                },
                start_previous_hash=start_previous_hash,
                expected_final_integrity_hash=expected_final_integrity_hash,
                manifest_digest=manifest_digest,
            ),
            records=tuple(self._record_contract(record) for record in ordered_records),
        )

    def canonical_document(self, proof: ChainProofDocument) -> str:
        """Serialize a chain proof with AuthClaw's existing canonical JSON helper."""

        return canonical_json(proof.model_dump(mode="json", by_alias=True))

    def verify(
        self,
        *,
        proof: ChainProofDocument | Mapping[str, Any],
        records: Sequence[AuditRecord],
        expected_tenant_id: UUID | None = None,
        expected_manifest_digest: str | None = None,
    ) -> ChainProofResultContract:
        raw_proof = proof.model_dump(mode="json", by_alias=True) if isinstance(proof, ChainProofDocument) else dict(proof)
        preflight_errors = self._preflight_errors(raw_proof, expected_manifest_digest)
        if preflight_errors:
            return ChainProofResultContract(
                chain_valid=False,
                record_count=0,
                errors=tuple(preflight_errors),
            )

        try:
            parsed = ChainProofDocument.model_validate(raw_proof)
        except ValidationError as exc:
            return ChainProofResultContract(
                chain_valid=False,
                record_count=0,
                errors=(f"invalid_chain_proof_document:{exc.errors()[0]['type']}",),
            )

        tenant_id = expected_tenant_id or parsed.chain_proof.tenant_id
        ordered_records = order_audit_records(records)
        errors: list[str] = []
        tampered_records: list[str] = []
        missing_records: list[str] = []
        chain_breaks: list[str] = []

        if parsed.chain_proof.tenant_id != tenant_id:
            errors.append("tenant_mismatch")

        for record in ordered_records:
            if record.tenant_id != tenant_id:
                errors.append("cross_tenant_record")
                break

        if parsed.chain_proof.record_range.record_count != len(ordered_records):
            errors.append("record_count_mismatch")

        proof_record_ids = [record.record_id for record in parsed.records]
        actual_record_ids = [str(record.record_id) for record in ordered_records]
        if proof_record_ids != actual_record_ids:
            errors.append("proof_record_order_mismatch")

        expected_sequence = 1
        expected_previous_hash = parsed.chain_proof.start_previous_hash
        for record in ordered_records:
            if record.sequence_no > 0:
                if record.sequence_no > expected_sequence:
                    missing_records.extend(
                        str(sequence_no)
                        for sequence_no in range(expected_sequence, record.sequence_no)
                    )
                expected_sequence = record.sequence_no + 1

            if record.previous_hash != expected_previous_hash:
                chain_breaks.append(str(record.record_id))

            computed_hash = compute_record_hash(record)
            if record.integrity_hash != computed_hash:
                tampered_records.append(str(record.record_id))

            expected_previous_hash = record.integrity_hash

        final_integrity_hash = ordered_records[-1].integrity_hash if ordered_records else ""
        if parsed.chain_proof.expected_final_integrity_hash != final_integrity_hash:
            errors.append("final_integrity_hash_mismatch")

        if ordered_records:
            first = ordered_records[0]
            last = ordered_records[-1]
            if parsed.chain_proof.record_range.start_record_id != str(first.record_id):
                errors.append("start_record_id_mismatch")
            if parsed.chain_proof.record_range.end_record_id != str(last.record_id):
                errors.append("end_record_id_mismatch")

        return ChainProofResultContract(
            chain_valid=not errors and not tampered_records and not missing_records and not chain_breaks,
            record_count=len(ordered_records),
            start_record_id=parsed.chain_proof.record_range.start_record_id or None,
            end_record_id=parsed.chain_proof.record_range.end_record_id or None,
            start_previous_hash=parsed.chain_proof.start_previous_hash or None,
            final_integrity_hash=final_integrity_hash or None,
            tampered_records=tuple(tampered_records),
            missing_records=tuple(missing_records),
            chain_breaks=tuple(chain_breaks),
            errors=tuple(errors),
        )

    @staticmethod
    def _record_contract(record: AuditRecord) -> ChainProofRecordContract:
        return ChainProofRecordContract(
            record_id=str(record.record_id),
            tenant_id=record.tenant_id,
            sequence_no=record.sequence_no,
            created_at=normalize_timestamp(record.created_at),
            previous_hash=record.previous_hash,
            integrity_hash=record.integrity_hash,
        )

    @staticmethod
    def _assert_tenant_scoped(tenant_id: UUID, records: tuple[AuditRecord, ...]) -> None:
        for record in records:
            if record.tenant_id != tenant_id:
                raise ValueError("chain proof cannot include cross-tenant audit records")

    @staticmethod
    def _preflight_errors(
        raw_proof: Mapping[str, Any],
        expected_manifest_digest: str | None,
    ) -> list[str]:
        errors: list[str] = []
        if raw_proof.get("schema_version") != CHAIN_PROOF_SCHEMA_VERSION:
            errors.append("unsupported_schema_version")
        chain_proof = raw_proof.get("chain_proof")
        if not isinstance(chain_proof, Mapping):
            errors.append("missing_chain_proof")
            return errors
        if chain_proof.get("hash_algorithm") != HashAlgorithm.SHA_256.value:
            errors.append("unsupported_hash_algorithm")
        if chain_proof.get("canonicalization") != CanonicalizationIdentifier.AUTHCLAW_CANONICAL_JSON_V1.value:
            errors.append("unsupported_canonicalization")
        if (
            expected_manifest_digest is not None
            and chain_proof.get("manifest_digest") != expected_manifest_digest
        ):
            errors.append("manifest_digest_mismatch")
        return errors


def compute_record_hash(record: AuditRecord) -> str:
    """Recompute an audit record hash using the existing AuthClaw hash utility."""

    return compute_canonical_record_hash(record)


def order_audit_records(records: Sequence[AuditRecord]) -> tuple[AuditRecord, ...]:
    """Return deterministic chain order for exported audit records."""

    return tuple(
        sorted(
            records,
            key=lambda record: (
                record.sequence_no if record.sequence_no > 0 else 0,
                normalize_timestamp(record.created_at),
                str(record.record_id),
            ),
        )
    )


def normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
