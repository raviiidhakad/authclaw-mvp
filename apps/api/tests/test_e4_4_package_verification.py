from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import UUID

import pytest

from app.core.audit.chain_proof import compute_record_hash
from app.core.audit.export_builder import AuditExportBuilder
from app.core.audit.export_contracts import ExportPackagePath, SignatureAlgorithm, VerificationState
from app.core.audit.package_builder import AuditExportPackageBuilder
from app.core.audit.package_verification import (
    AuditExportVerificationService,
    StaticSignatureVerifierResolver,
    verification_state_catalog,
)
from app.core.audit.repository import AuditRecord, AuditRepository
from app.core.audit.signing import AuditExportSigningService
from app.core.events.audit_hash import GENESIS_HASH
from app.schemas.audit_export import AuditExportVerificationResponse


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
EXPORT_ID = UUID("22222222-2222-4222-8222-222222222222")
REQUESTER_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
START = NOW - timedelta(minutes=5)
END = NOW + timedelta(minutes=5)


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


class DeterministicSignatureVerifier:
    key_id = "deterministic-test-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def verify_digest_signature(
        self,
        *,
        manifest_digest: str,
        signature: str,
        algorithm: SignatureAlgorithm,
    ) -> bool:
        return signature == f"detached-signature:{algorithm.value}:{manifest_digest}"


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
            if record.tenant_id == tenant_id and start_date <= record.created_at <= end_date
        ]

    async def get_latest_hash(self, tenant_id: UUID) -> str | None:
        return None

    async def get_latest_sequence_no(self, tenant_id: UUID) -> int:
        return 0


def _record(suffix: int, *, previous_hash: str) -> AuditRecord:
    record = AuditRecord(
        record_id=UUID(f"aaaaaaaa-aaaa-4aaa-8aaa-{suffix:012d}"),
        tenant_id=TENANT_ID,
        sequence_no=suffix,
        created_at=NOW + timedelta(seconds=suffix),
        actor_id=REQUESTER_ID,
        actor_type="user",
        action="execute",
        frameworks_affected=["SOC2"],
        resource="gateway",
        resource_id=f"route-{suffix}",
        execution_trace=None,
        metadata={"event_type": "gateway.request", "safe": f"value-{suffix}"},
        ip_address=None,
        user_agent=None,
        previous_hash=previous_hash,
        integrity_hash="",
    )
    return record.model_copy(update={"integrity_hash": compute_record_hash(record)})


def _valid_chain(count: int = 2) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    previous_hash = GENESIS_HASH
    for suffix in range(1, count + 1):
        record = _record(suffix, previous_hash=previous_hash)
        records.append(record)
        previous_hash = record.integrity_hash
    return records


def _verification_service() -> AuditExportVerificationService:
    return AuditExportVerificationService(
        signature_resolver=StaticSignatureVerifierResolver(
            {"deterministic-test-key": DeterministicSignatureVerifier()}
        )
    )


async def _build_package(records: list[AuditRecord]) -> bytes:
    export_builder = AuditExportBuilder(FakeAuditRepository(records), tool_version="0.9.0-test")
    signing_service = AuditExportSigningService(
        DeterministicSigningProvider(),
        tool_version="0.9.0-test",
    )
    package = await AuditExportPackageBuilder(
        export_builder=export_builder,
        signing_service=signing_service,
    ).build(
        tenant_id=TENANT_ID,
        start_date=START,
        end_date=END,
        export_id=EXPORT_ID,
        requester_id=REQUESTER_ID,
        created_at=NOW,
        purpose="compliance evidence",
        signing_timestamp=NOW,
    )
    return package.package_bytes


def _mutate_package(package_bytes: bytes, path: str, mutate) -> bytes:
    source = BytesIO(package_bytes)
    destination = BytesIO()
    with zipfile.ZipFile(source, "r") as in_zip, zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as out_zip:
        for name in in_zip.namelist():
            content = in_zip.read(name).decode("utf-8")
            if name == path:
                content = mutate(content)
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            out_zip.writestr(info, content.encode("utf-8"))
    return destination.getvalue()


def _mutate_manifest(package_bytes: bytes, mutate) -> bytes:
    def apply(content: str) -> str:
        payload = json.loads(content)
        mutate(payload)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    return _mutate_package(package_bytes, ExportPackagePath.MANIFEST.value, apply)


@pytest.mark.asyncio
async def test_verifier_accepts_valid_package():
    records = _valid_chain()
    package_bytes = await _build_package(records)

    result = _verification_service().verify_package(
        package_bytes,
        expected_tenant_id=TENANT_ID,
        original_records=records,
    )

    assert result.state == VerificationState.VERIFIED
    assert result.export_id == EXPORT_ID
    assert result.tenant_id == TENANT_ID
    assert result.record_count == 2
    assert result.signature_valid is True
    assert result.errors == ()


@pytest.mark.asyncio
async def test_verifier_detects_tampered_manifest():
    records = _valid_chain()
    package_bytes = await _build_package(records)
    tampered = _mutate_manifest(package_bytes, lambda payload: payload.update({"record_count": 99}))

    result = _verification_service().verify_package(tampered, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.TAMPERED
    assert "record_count_mismatch" in result.errors


@pytest.mark.asyncio
async def test_verifier_detects_tampered_audit_jsonl():
    package_bytes = await _build_package(_valid_chain())
    tampered = _mutate_package(
        package_bytes,
        ExportPackagePath.AUDIT.value,
        lambda content: content.replace("value-1", "changed"),
    )

    result = _verification_service().verify_package(tampered, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.TAMPERED
    assert "file_digest_mismatch:audit.jsonl" in result.errors


@pytest.mark.asyncio
async def test_verifier_detects_tampered_chain_proof():
    package_bytes = await _build_package(_valid_chain())
    tampered = _mutate_package(
        package_bytes,
        ExportPackagePath.CHAIN_PROOF.value,
        lambda content: content.replace("authclaw.audit.chain-proof/v1", "authclaw.audit.chain-proof/v999"),
    )

    result = _verification_service().verify_package(tampered, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.TAMPERED
    assert "file_digest_mismatch:chain-proof.json" in result.errors


@pytest.mark.asyncio
async def test_verifier_detects_invalid_signature():
    package_bytes = await _build_package(_valid_chain())
    tampered = _mutate_package(
        package_bytes,
        ExportPackagePath.SIGNATURE.value,
        lambda _content: "invalid-signature",
    )

    result = _verification_service().verify_package(tampered, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.TAMPERED
    assert result.errors == ("invalid_signature",)


@pytest.mark.asyncio
async def test_verifier_rejects_unsupported_schema():
    package_bytes = await _build_package(_valid_chain())
    unsupported = _mutate_manifest(package_bytes, lambda payload: payload.update({"schema": "authclaw.audit.export/v999"}))

    result = _verification_service().verify_package(unsupported, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.UNSUPPORTED_VERSION
    assert result.errors == ("unsupported_schema",)


@pytest.mark.asyncio
async def test_verifier_rejects_unsupported_package_version():
    package_bytes = await _build_package(_valid_chain())
    unsupported = _mutate_manifest(package_bytes, lambda payload: payload.update({"package_version": 999}))

    result = _verification_service().verify_package(unsupported, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.UNSUPPORTED_VERSION
    assert result.errors == ("unsupported_package_version",)


@pytest.mark.asyncio
async def test_verifier_rejects_cross_tenant_verification():
    package_bytes = await _build_package(_valid_chain())

    result = _verification_service().verify_package(package_bytes, expected_tenant_id=OTHER_TENANT_ID)

    assert result.state == VerificationState.TAMPERED
    assert result.errors == ("tenant_mismatch",)


@pytest.mark.asyncio
async def test_verifier_rejects_unsupported_algorithm():
    package_bytes = await _build_package(_valid_chain())
    unsupported = _mutate_manifest(
        package_bytes,
        lambda payload: payload["algorithm_identifiers"].update({"hash_algorithm": "SHA-512"}),
    )

    result = _verification_service().verify_package(unsupported, expected_tenant_id=TENANT_ID)

    assert result.state == VerificationState.UNSUPPORTED_VERSION
    assert result.errors == ("unsupported_hash_algorithm",)


def test_trust_center_state_catalog_covers_design_freeze_states():
    states = {item["state"] for item in verification_state_catalog()}

    assert states == {
        "Verified",
        "Tampered",
        "Verification Failed",
        "Unsupported Version",
        "Expired",
        "Unknown",
        "Error",
    }


@pytest.mark.asyncio
async def test_api_response_mapping_is_sanitized_metadata_only():
    package_bytes = await _build_package(_valid_chain())
    result = _verification_service().verify_package(package_bytes, expected_tenant_id=TENANT_ID)

    response = AuditExportVerificationResponse.from_contract(result)
    payload = response.model_dump(mode="json", by_alias=True)

    assert payload["state"] == "Verified"
    assert payload["schema"] == "authclaw.audit.export/v1"
    assert "audit.jsonl" not in json.dumps(payload)
    assert "chain-proof.json" not in json.dumps(payload)
    assert "signature_key_id" in payload["metadata"]
