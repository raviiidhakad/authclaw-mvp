"""
E4.4 canonical audit export assembler.

The builder assembles sanitized, canonical in-memory export artifacts only. It
does not create ZIP files, sign manifests, verify exports, persist database rows,
or modify runtime audit paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import UUID, uuid4

from app.core.audit.chain_proof import (
    ChainProofDocument,
    ChainProofService,
    MANIFEST_DIGEST_PLACEHOLDER,
    order_audit_records,
)
from app.core.audit.export_contracts import (
    AuditExportAlgorithmIdentifiers,
    AuditExportManifestContract,
    ChainInformationContract,
    ExportPackagePath,
    FileDigestContract,
    PackageMetadataContract,
    REQUIRED_EXPORT_PACKAGE_PATHS,
    SignatureInformationContract,
    TimeRangeContract,
)
from app.core.audit.repository import AuditRecord, AuditRepository
from app.services.trust_reporting import ExportSanitizer, canonical_json


PHASE_2_DIGEST_PLACEHOLDER = "PENDING_PHASE_3_DIGEST"
PHASE_2_SIGNATURE_KEY_PLACEHOLDER = "PENDING_PHASE_4_SIGNING_KEY"
PHASE_2_GENERATOR = "authclaw-audit-export-builder"


@dataclass(frozen=True)
class AuditExportAssembly:
    """In-memory canonical export artifacts assembled by Phase 2."""

    export_id: UUID
    tenant_id: UUID
    manifest: AuditExportManifestContract
    files: Mapping[str, str]
    audit_records: tuple[dict[str, Any], ...]
    metadata: dict[str, Any]
    config_snapshot: dict[str, Any]
    redaction_metrics: dict[str, Any]
    chain_proof: ChainProofDocument


class AuditExportBuilder:
    """Assemble canonical audit export artifacts from an existing repository."""

    def __init__(
        self,
        repository: AuditRepository,
        *,
        sanitizer: ExportSanitizer | None = None,
        chain_proof_service: ChainProofService | None = None,
        tool_version: str = "0.9.0",
        generator: str = PHASE_2_GENERATOR,
    ) -> None:
        self.repository = repository
        self.sanitizer = sanitizer or ExportSanitizer()
        self.chain_proof_service = chain_proof_service or ChainProofService()
        self.tool_version = tool_version
        self.generator = generator

    async def build(
        self,
        *,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
        export_id: UUID | None = None,
        requester_id: UUID | None = None,
        created_at: datetime | None = None,
        purpose: str | None = None,
        config_snapshot: Mapping[str, Any] | None = None,
    ) -> AuditExportAssembly:
        """Build sanitized canonical artifacts without signatures, verification, or ZIP output."""

        resolved_export_id = export_id or uuid4()
        resolved_created_at = _normalize_timestamp(created_at or datetime.now(UTC))
        time_range = TimeRangeContract(
            start_at=_normalize_timestamp(start_date),
            end_at=_normalize_timestamp(end_date),
        )
        records = await self.repository.export(tenant_id, start_date, end_date)
        ordered_records = self._order_records(records)
        self._assert_tenant_scoped(tenant_id, ordered_records)

        sanitized_records = tuple(self._sanitize_record(record) for record in ordered_records)
        chain_proof = self.chain_proof_service.generate(
            tenant_id=tenant_id,
            records=ordered_records,
            time_range=time_range,
            manifest_digest=MANIFEST_DIGEST_PLACEHOLDER,
        )
        metadata = self._build_metadata(
            tenant_id=tenant_id,
            export_id=resolved_export_id,
            created_at=resolved_created_at,
            requester_id=requester_id,
            purpose=purpose,
        )
        sanitized_config_snapshot = self._build_config_snapshot(config_snapshot)
        redaction_metrics = self._build_redaction_metrics(sanitized_records)

        files_without_manifest = {
            ExportPackagePath.AUDIT.value: _canonical_jsonl(sanitized_records),
            ExportPackagePath.CHAIN_PROOF.value: self.chain_proof_service.canonical_document(
                chain_proof
            ),
            ExportPackagePath.METADATA.value: canonical_json(metadata),
            ExportPackagePath.CONFIG_SNAPSHOT.value: canonical_json(sanitized_config_snapshot),
            ExportPackagePath.REDACTION_METRICS.value: canonical_json(redaction_metrics),
        }
        manifest = self._build_manifest(
            tenant_id=tenant_id,
            export_id=resolved_export_id,
            created_at=resolved_created_at,
            record_count=len(sanitized_records),
            time_range=time_range,
            files_without_manifest=files_without_manifest,
            ordered_records=ordered_records,
        )
        files = {
            ExportPackagePath.MANIFEST.value: canonical_json(
                manifest.model_dump(mode="json", by_alias=True)
            ),
            **files_without_manifest,
        }

        return AuditExportAssembly(
            export_id=resolved_export_id,
            tenant_id=tenant_id,
            manifest=manifest,
            files=files,
            audit_records=sanitized_records,
            metadata=metadata,
            config_snapshot=sanitized_config_snapshot,
            redaction_metrics=redaction_metrics,
            chain_proof=chain_proof,
        )

    def _build_manifest(
        self,
        *,
        tenant_id: UUID,
        export_id: UUID,
        created_at: datetime,
        record_count: int,
        time_range: TimeRangeContract,
        files_without_manifest: Mapping[str, str],
        ordered_records: tuple[AuditRecord, ...],
    ) -> AuditExportManifestContract:
        file_digest_map = self._build_file_digest_map(files_without_manifest)
        chain_information = self._build_chain_information(ordered_records)
        signature_information = SignatureInformationContract(
            key_id=PHASE_2_SIGNATURE_KEY_PLACEHOLDER,
            created_at=created_at,
            verification_hint="Signature generation is reserved for E4.4 Phase 4.",
        )
        return AuditExportManifestContract(
            created_at=created_at,
            tenant_id=tenant_id,
            export_id=export_id,
            record_count=record_count,
            time_range=time_range,
            file_digest_map=file_digest_map,
            chain_information=chain_information,
            signature_information=signature_information,
            algorithm_identifiers=AuditExportAlgorithmIdentifiers(),
            tool_version=self.tool_version,
            generator=self.generator,
        )

    def _build_file_digest_map(self, files_without_manifest: Mapping[str, str]) -> dict[str, FileDigestContract]:
        file_digest_map: dict[str, FileDigestContract] = {}
        for path in sorted(path.value for path in REQUIRED_EXPORT_PACKAGE_PATHS):
            content = files_without_manifest.get(path, "")
            file_digest_map[path] = FileDigestContract(
                path=path,
                digest=PHASE_2_DIGEST_PLACEHOLDER,
                size_bytes=len(content.encode("utf-8")),
                required=True,
            )
        return file_digest_map

    def _build_chain_information(self, ordered_records: tuple[AuditRecord, ...]) -> ChainInformationContract:
        if not ordered_records:
            return ChainInformationContract(
                start_record_id="",
                end_record_id="",
                start_previous_hash="",
                final_integrity_hash="",
                record_count=0,
            )
        first = ordered_records[0]
        last = ordered_records[-1]
        return ChainInformationContract(
            start_record_id=str(first.record_id),
            end_record_id=str(last.record_id),
            start_previous_hash=first.previous_hash,
            final_integrity_hash=last.integrity_hash,
            record_count=len(ordered_records),
        )

    def _build_metadata(
        self,
        *,
        tenant_id: UUID,
        export_id: UUID,
        created_at: datetime,
        requester_id: UUID | None,
        purpose: str | None,
    ) -> dict[str, Any]:
        metadata = PackageMetadataContract(
            tenant_id=tenant_id,
            export_id=export_id,
            created_at=created_at,
            requester_id=requester_id,
            purpose=purpose,
            tool_version=self.tool_version,
            generator=self.generator,
        )
        return self.sanitizer.sanitize(metadata.model_dump(mode="json", by_alias=True))

    def _build_config_snapshot(self, config_snapshot: Mapping[str, Any] | None) -> dict[str, Any]:
        safe_snapshot = {
            "snapshot_type": "audit_export_config",
            "phase": "E4.4 Phase 2",
            "runtime_behavior_changed": False,
            "hash_generation_enabled": False,
            "chain_proof_generation_enabled": True,
            "signature_generation_enabled": False,
            "zip_generation_enabled": False,
            "provided_config": dict(config_snapshot or {}),
        }
        return self.sanitizer.sanitize(safe_snapshot)

    def _build_redaction_metrics(self, records: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        redacted_marker = "[REDACTED]"
        serialized = canonical_json({"records": list(records)})
        return {
            "sanitization_version": self.sanitizer.sanitization_version,
            "records_processed": len(records),
            "redaction_marker": redacted_marker,
            "redaction_marker_occurrences": serialized.count(redacted_marker),
            "raw_provider_payload_exported": False,
            "vault_references_exported": False,
            "secret_values_exported": False,
        }

    def _sanitize_record(self, record: AuditRecord) -> dict[str, Any]:
        payload = {
            "record_id": str(record.record_id),
            "tenant_id": str(record.tenant_id),
            "sequence_no": record.sequence_no,
            "created_at": _normalize_timestamp(record.created_at).isoformat(),
            "actor_id": str(record.actor_id) if record.actor_id else None,
            "actor_type": record.actor_type,
            "action": record.action,
            "frameworks_affected": list(record.frameworks_affected),
            "resource": record.resource,
            "resource_id": record.resource_id,
            "metadata": record.metadata,
            "ip_address": record.ip_address,
            "user_agent": record.user_agent,
            "previous_hash": record.previous_hash,
            "integrity_hash": record.integrity_hash,
        }
        return self.sanitizer.sanitize(payload)

    @staticmethod
    def _order_records(records: list[AuditRecord]) -> tuple[AuditRecord, ...]:
        return order_audit_records(records)

    @staticmethod
    def _assert_tenant_scoped(tenant_id: UUID, records: tuple[AuditRecord, ...]) -> None:
        for record in records:
            if record.tenant_id != tenant_id:
                raise ValueError("audit export repository returned a cross-tenant record")


def _canonical_jsonl(records: tuple[dict[str, Any], ...]) -> str:
    if not records:
        return ""
    return "".join(f"{canonical_json(record)}\n" for record in records)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
