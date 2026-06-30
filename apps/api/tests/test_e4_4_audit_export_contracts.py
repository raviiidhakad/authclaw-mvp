from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.core.audit import export_contracts as contracts


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
EXPORT_ID = UUID("22222222-2222-4222-8222-222222222222")
REQUESTER_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 29, 12, 0, tzinfo=UTC)


def _time_range() -> contracts.TimeRangeContract:
    return contracts.TimeRangeContract(start_at=NOW, end_at=NOW)


def _chain_information() -> contracts.ChainInformationContract:
    return contracts.ChainInformationContract(
        start_record_id="record-001",
        end_record_id="record-002",
        start_previous_hash="0" * 64,
        final_integrity_hash="a" * 64,
        record_count=2,
    )


def _signature_information() -> contracts.SignatureInformationContract:
    return contracts.SignatureInformationContract(
        key_id="audit-export-signing-key-v1",
        created_at=NOW,
    )


def _file_digest(path: str, *, required: bool = True) -> contracts.FileDigestContract:
    return contracts.FileDigestContract(
        path=path,
        digest="b" * 64,
        size_bytes=128,
        required=required,
    )


def test_e4_4_contracts_are_non_executing_scaffolding():
    source = inspect.getsource(contracts)

    assert "from app.core.engine.gateway" not in source
    assert "from app.core.engine.streaming" not in source
    assert "from app.core.engine.token_vault" not in source
    assert "from app.core.policy" not in source
    assert "from app.workers.audit_worker" not in source
    assert "from app.core.audit.repository" not in source
    assert "hashlib" not in source
    assert "zipfile" not in source


def test_schema_algorithm_and_version_constants_match_design_freeze():
    versions = contracts.AuditExportVersionIdentifiers()
    algorithms = contracts.AuditExportAlgorithmIdentifiers()

    assert versions.schema_id == "authclaw.audit.export/v1"
    assert versions.schema_version == 1
    assert versions.package_version == 1
    assert versions.manifest_version == 1
    assert versions.canonicalization == "authclaw.canonical-json/v1"
    assert versions.model_dump(mode="json", by_alias=True)["schema"] == (
        "authclaw.audit.export/v1"
    )
    assert algorithms.hash_algorithm == "SHA-256"
    assert algorithms.signature_algorithm == "ES256"
    assert algorithms.canonicalization == "authclaw.canonical-json/v1"


def test_package_contract_contains_required_files_and_optional_attachment_prefix():
    package = contracts.ExportPackageContract()

    assert package.allow_unlisted_files is False
    assert tuple(package.required_files) == (
        "manifest.json",
        "audit.jsonl",
        "chain-proof.json",
        "metadata.json",
        "redaction-metrics.json",
        "config-snapshot.json",
        "signature.sig",
    )
    assert tuple(package.optional_prefixes) == ("attachments/",)


def test_verification_state_enum_covers_trust_center_states():
    assert {state.value for state in contracts.VerificationState} == {
        "Verified",
        "Tampered",
        "Verification Failed",
        "Unsupported Version",
        "Expired",
        "Unknown",
        "Error",
    }


def test_manifest_contract_serializes_with_required_fields_and_defaults():
    manifest = contracts.AuditExportManifestContract(
        created_at=NOW,
        tenant_id=TENANT_ID,
        export_id=EXPORT_ID,
        record_count=2,
        time_range=_time_range(),
        file_digest_map={
            "manifest.json": _file_digest("manifest.json"),
            "audit.jsonl": _file_digest("audit.jsonl"),
            "chain-proof.json": _file_digest("chain-proof.json"),
            "metadata.json": _file_digest("metadata.json"),
            "redaction-metrics.json": _file_digest("redaction-metrics.json"),
            "config-snapshot.json": _file_digest("config-snapshot.json"),
            "signature.sig": _file_digest("signature.sig"),
        },
        chain_information=_chain_information(),
        signature_information=_signature_information(),
        tool_version="0.9.0",
        generator="authclaw-api",
    )

    dumped = manifest.model_dump(mode="json", by_alias=True)
    json.dumps(dumped)

    assert dumped["schema"] == contracts.AUDIT_EXPORT_SCHEMA
    assert dumped["schema_version"] == 1
    assert dumped["package_version"] == 1
    assert dumped["manifest_version"] == 1
    assert dumped["algorithm_identifiers"] == {
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "ES256",
        "canonicalization": "authclaw.canonical-json/v1",
    }
    assert dumped["chain_information"]["proof_file"] == "chain-proof.json"
    assert dumped["signature_information"]["signature_file"] == "signature.sig"
    assert dumped["signature_information"]["signed_object"] == "manifest_digest"


def test_manifest_contract_rejects_unknown_fields_and_invalid_record_count():
    with pytest.raises(ValidationError):
        contracts.AuditExportManifestContract(
            created_at=NOW,
            tenant_id=TENANT_ID,
            export_id=EXPORT_ID,
            record_count=-1,
            time_range=_time_range(),
            file_digest_map={},
            chain_information=_chain_information(),
            signature_information=_signature_information(),
            tool_version="0.9.0",
            generator="authclaw-api",
            unexpected="blocked",
        )


def test_chain_proof_contract_binds_tenant_range_hash_and_manifest_digest():
    record_range = contracts.AuditRecordRangeContract(
        tenant_id=TENANT_ID,
        start_record_id="record-001",
        end_record_id="record-002",
        record_count=2,
        time_range=_time_range(),
    )
    proof = contracts.ChainProofContract(
        tenant_id=TENANT_ID,
        record_range=record_range,
        start_previous_hash="0" * 64,
        expected_final_integrity_hash="a" * 64,
        manifest_digest="c" * 64,
    )

    dumped = proof.model_dump(mode="json", by_alias=True)

    assert dumped["tenant_id"] == str(TENANT_ID)
    assert dumped["record_range"]["tenant_id"] == str(TENANT_ID)
    assert dumped["hash_algorithm"] == "SHA-256"
    assert dumped["canonicalization"] == "authclaw.canonical-json/v1"
    assert dumped["manifest_digest"] == "c" * 64


def test_verification_result_contract_defaults_are_safe_for_unverified_state():
    result = contracts.VerificationResultContract(
        state=contracts.VerificationState.UNKNOWN,
    )

    dumped = result.model_dump(mode="json", by_alias=True)

    assert dumped["state"] == "Unknown"
    assert dumped["record_count"] == 0
    assert dumped["signature_valid"] is None
    assert dumped["manifest_valid"] is None
    assert dumped["files_valid"] is None
    assert dumped["chain_valid"] is None
    assert dumped["errors"] == []
    assert dumped["warnings"] == []
    assert dumped["security_summary"] == {
        "tenant_isolation": "not_evaluated",
        "manifest_integrity": "not_evaluated",
        "export_integrity": "not_evaluated",
        "chain_integrity": "not_evaluated",
        "signature_integrity": "not_evaluated",
        "safe_export": "not_evaluated",
        "safe_verification": "not_evaluated",
    }


def test_package_metadata_contract_is_tenant_scoped_and_serializable():
    metadata = contracts.PackageMetadataContract(
        tenant_id=TENANT_ID,
        export_id=EXPORT_ID,
        created_at=NOW,
        requester_id=REQUESTER_ID,
        purpose="compliance evidence export",
        tool_version="0.9.0",
        generator="authclaw-api",
    )

    dumped = metadata.model_dump(mode="json", by_alias=True)
    json.dumps(dumped)

    assert dumped["tenant_id"] == str(TENANT_ID)
    assert dumped["export_id"] == str(EXPORT_ID)
    assert dumped["requester_id"] == str(REQUESTER_ID)


def test_contract_models_are_frozen():
    versions = contracts.AuditExportVersionIdentifiers()

    with pytest.raises(ValidationError):
        versions.schema_version = 2
