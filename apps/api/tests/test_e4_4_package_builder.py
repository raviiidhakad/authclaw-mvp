from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import UUID

import pytest

from app.core.audit.export_builder import AuditExportBuilder
from app.core.audit.export_contracts import ExportPackagePath, SignatureAlgorithm
from app.core.audit.package_builder import (
    MANIFEST_SELF_DIGEST_PLACEHOLDER,
    SIGNATURE_FILE_DIGEST_PLACEHOLDER,
    AuditExportPackageBuilder,
    MissingPackageArtifactError,
)
from app.core.audit.repository import AuditRecord, AuditRepository
from app.core.audit.signing import AuditExportSigningService


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
EXPORT_ID = UUID("22222222-2222-4222-8222-222222222222")
REQUESTER_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=1)
END = NOW + timedelta(hours=1)


class DeterministicSigningProvider:
    key_id = "deterministic-test-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def sign_digest(
        self,
        *,
        manifest_digest: str,
        algorithm: SignatureAlgorithm,
    ) -> str:
        return f"detached-signature:{algorithm.value}:{manifest_digest}"


class FakeAuditRepository(AuditRepository):
    def __init__(self, records: list[AuditRecord]) -> None:
        self.records = records

    async def append(self, record: AuditRecord) -> None:
        self.records.append(record)

    async def bulk_append(self, records: list[AuditRecord]) -> None:
        self.records.extend(records)

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
            if record.tenant_id == tenant_id
            and start_date <= record.created_at <= end_date
        ]

    async def get_latest_hash(self, tenant_id: UUID) -> str | None:
        return None

    async def get_latest_sequence_no(self, tenant_id: UUID) -> int:
        return 0


class UnsafeFakeAuditRepository(FakeAuditRepository):
    async def export(
        self,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> list[AuditRecord]:
        return list(self.records)


def _record(
    suffix: int,
    *,
    tenant_id: UUID = TENANT_ID,
    metadata: dict | None = None,
) -> AuditRecord:
    return AuditRecord(
        record_id=UUID(f"aaaaaaaa-aaaa-4aaa-8aaa-{suffix:012d}"),
        tenant_id=tenant_id,
        sequence_no=suffix,
        created_at=NOW + timedelta(seconds=suffix),
        actor_id=REQUESTER_ID,
        actor_type="user",
        action="execute",
        frameworks_affected=["SOC2"],
        resource="gateway",
        resource_id=f"route-{suffix}",
        execution_trace=None,
        metadata=metadata or {"event_type": "gateway.request", "safe": f"value-{suffix}"},
        ip_address=None,
        user_agent=None,
        previous_hash=f"prev-{suffix}",
        integrity_hash=f"hash-{suffix}",
    )


def _package_builder(records: list[AuditRecord]) -> AuditExportPackageBuilder:
    export_builder = AuditExportBuilder(
        FakeAuditRepository(records),
        tool_version="0.9.0-test",
    )
    signing_service = AuditExportSigningService(
        DeterministicSigningProvider(),
        tool_version="0.9.0-test",
    )
    return AuditExportPackageBuilder(
        export_builder=export_builder,
        signing_service=signing_service,
    )


async def _build_package(records: list[AuditRecord]):
    return await _package_builder(records).build(
        tenant_id=TENANT_ID,
        start_date=START,
        end_date=END,
        export_id=EXPORT_ID,
        requester_id=REQUESTER_ID,
        created_at=NOW,
        purpose="compliance evidence",
        signing_timestamp=NOW,
    )


def _zip_contents(package_bytes: bytes) -> dict[str, str]:
    with zipfile.ZipFile(BytesIO(package_bytes), "r") as archive:
        return {
            name: archive.read(name).decode("utf-8")
            for name in archive.namelist()
        }


def _zip_order(package_bytes: bytes) -> list[str]:
    with zipfile.ZipFile(BytesIO(package_bytes), "r") as archive:
        return archive.namelist()


@pytest.mark.asyncio
async def test_package_generation_includes_required_files():
    package = await _build_package([_record(1)])
    contents = _zip_contents(package.package_bytes)

    assert set(contents) == {
        "manifest.json",
        "audit.jsonl",
        "chain-proof.json",
        "metadata.json",
        "redaction-metrics.json",
        "config-snapshot.json",
        "signature.sig",
    }
    assert contents["signature.sig"] == package.signature.signature
    assert contents["manifest.json"] == package.files["manifest.json"]


@pytest.mark.asyncio
async def test_package_contents_are_deterministic_with_deterministic_signer():
    first = await _build_package([_record(1), _record(2)])
    second = await _build_package([_record(1), _record(2)])

    assert first.package_bytes == second.package_bytes
    assert first.files == second.files
    assert first.manifest_digest == second.manifest_digest


@pytest.mark.asyncio
async def test_manifest_consistency_matches_package_metadata():
    package = await _build_package([_record(1)])
    manifest = json.loads(package.files["manifest.json"])

    assert manifest["tenant_id"] == str(TENANT_ID)
    assert manifest["export_id"] == str(EXPORT_ID)
    assert manifest["signature_information"]["key_id"] == "deterministic-test-key"
    assert manifest["signature_information"]["created_at"] == "2026-06-30T12:00:00Z"
    assert manifest["signature_information"]["signature_algorithm"] == "ES256"
    assert package.signature.manifest_digest == package.manifest_digest
    assert package.signature.key_id == "deterministic-test-key"


@pytest.mark.asyncio
async def test_manifest_file_digest_map_contains_actual_content_digests():
    package = await _build_package([_record(1)])
    manifest = json.loads(package.files["manifest.json"])
    digest_map = manifest["file_digest_map"]

    assert digest_map["manifest.json"]["digest"] == MANIFEST_SELF_DIGEST_PLACEHOLDER
    assert digest_map["signature.sig"]["digest"] == SIGNATURE_FILE_DIGEST_PLACEHOLDER
    for path in (
        "audit.jsonl",
        "chain-proof.json",
        "metadata.json",
        "redaction-metrics.json",
        "config-snapshot.json",
    ):
        assert digest_map[path]["digest"] != MANIFEST_SELF_DIGEST_PLACEHOLDER
        assert digest_map[path]["digest"] != SIGNATURE_FILE_DIGEST_PLACEHOLDER
        assert digest_map[path]["size_bytes"] == len(package.files[path].encode("utf-8"))


@pytest.mark.asyncio
async def test_chain_proof_and_signature_are_included():
    package = await _build_package([_record(1)])
    contents = _zip_contents(package.package_bytes)
    chain_proof = json.loads(contents["chain-proof.json"])

    assert chain_proof["schema"] == "authclaw.audit.chain-proof/v1"
    assert chain_proof["chain_proof"]["tenant_id"] == str(TENANT_ID)
    assert contents["signature.sig"].startswith("detached-signature:ES256:")


@pytest.mark.asyncio
async def test_missing_artifact_failure():
    package_builder = _package_builder([_record(1)])
    assembly = await package_builder.export_builder.build(
        tenant_id=TENANT_ID,
        start_date=START,
        end_date=END,
        export_id=EXPORT_ID,
        created_at=NOW,
    )
    broken_files = dict(assembly.files)
    broken_files.pop("metadata.json")
    broken_assembly = assembly.__class__(
        export_id=assembly.export_id,
        tenant_id=assembly.tenant_id,
        manifest=assembly.manifest,
        files=broken_files,
        audit_records=assembly.audit_records,
        metadata=assembly.metadata,
        config_snapshot=assembly.config_snapshot,
        redaction_metrics=assembly.redaction_metrics,
        chain_proof=assembly.chain_proof,
    )

    with pytest.raises(MissingPackageArtifactError, match="metadata.json"):
        package_builder.assemble(broken_assembly, signing_timestamp=NOW)


@pytest.mark.asyncio
async def test_package_ordering_is_canonical():
    package = await _build_package([_record(1)])

    assert _zip_order(package.package_bytes) == [
        "manifest.json",
        "audit.jsonl",
        "chain-proof.json",
        "metadata.json",
        "redaction-metrics.json",
        "config-snapshot.json",
        "signature.sig",
    ]


@pytest.mark.asyncio
async def test_tenant_isolation_is_preserved_from_export_builder():
    export_builder = AuditExportBuilder(
        UnsafeFakeAuditRepository([_record(1), _record(2, tenant_id=OTHER_TENANT_ID)]),
        tool_version="0.9.0-test",
    )
    signing_service = AuditExportSigningService(DeterministicSigningProvider())
    package_builder = AuditExportPackageBuilder(
        export_builder=export_builder,
        signing_service=signing_service,
    )

    with pytest.raises(ValueError, match="cross-tenant"):
        await package_builder.build(
            tenant_id=TENANT_ID,
            start_date=START,
            end_date=END,
            export_id=EXPORT_ID,
            created_at=NOW,
            signing_timestamp=NOW,
        )


@pytest.mark.asyncio
async def test_package_does_not_include_sanitized_secrets_or_vault_refs():
    package = await _build_package(
        [
            _record(
                1,
                metadata={
                    "event_type": "gateway.request",
                    "api_key": "sk-should-not-export",
                    "vault_ref": "vault://secret/path",
                    "raw_provider_payload": {"secret": "bad"},
                    "safe": "kept",
                },
            )
        ]
    )

    contents = _zip_contents(package.package_bytes)
    audit_payload = contents["audit.jsonl"]
    serialized = package.package_bytes.decode("latin1")

    assert "sk-should-not-export" not in serialized
    assert "vault://secret/path" not in serialized
    assert '"raw_provider_payload":' not in audit_payload
    assert "safe" in serialized
