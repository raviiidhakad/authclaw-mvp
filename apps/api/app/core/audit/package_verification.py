"""
E4.4 Phase 6 signed audit export package verification.

This module verifies packages produced by the E4.4 export builders. It does not
manage certificates, rotate keys, write audit records, or modify runtime audit
paths.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Mapping, Protocol, Sequence
from uuid import UUID

from pydantic import ValidationError

from app.core.audit.chain_proof import (
    CHAIN_PROOF_SCHEMA,
    CHAIN_PROOF_SCHEMA_VERSION,
    MANIFEST_DIGEST_PLACEHOLDER,
    ChainProofDocument,
    ChainProofService,
)
from app.core.audit.export_contracts import (
    AUDIT_EXPORT_SCHEMA,
    AUDIT_EXPORT_SCHEMA_VERSION,
    AUDIT_EXPORT_PACKAGE_VERSION,
    AUDIT_EXPORT_MANIFEST_VERSION,
    AuditExportManifestContract,
    CanonicalizationIdentifier,
    ExportPackagePath,
    HashAlgorithm,
    REQUIRED_EXPORT_PACKAGE_PATHS,
    SecurityCheckState,
    SignatureAlgorithm,
    VerificationResultContract,
    VerificationSecuritySummaryContract,
    VerificationState,
)
from app.core.audit.package_builder import (
    MANIFEST_SELF_DIGEST_PLACEHOLDER,
    SIGNATURE_FILE_DIGEST_PLACEHOLDER,
)
from app.core.audit.repository import AuditRecord
from app.services.trust_reporting import build_manifest_hash


MAX_AUDIT_EXPORT_PACKAGE_BYTES = 50 * 1024 * 1024


class AuditExportVerificationError(ValueError):
    """Base class for sanitized package verification failures."""


class AuditExportSignatureVerifier(Protocol):
    """Verifier boundary for future KMS/HSM/local public-key verification."""

    key_id: str
    supported_algorithms: tuple[SignatureAlgorithm, ...]

    def verify_digest_signature(
        self,
        *,
        manifest_digest: str,
        signature: str,
        algorithm: SignatureAlgorithm,
    ) -> bool:
        ...


class SignatureVerifierResolver(Protocol):
    """Resolve a signature verifier without exposing key material."""

    def resolve(
        self,
        *,
        key_id: str,
        algorithm: SignatureAlgorithm,
    ) -> AuditExportSignatureVerifier | None:
        ...


@dataclass(frozen=True)
class StaticSignatureVerifierResolver:
    """Small resolver for tests/local composition; no key lifecycle behavior."""

    verifiers: Mapping[str, AuditExportSignatureVerifier]

    def resolve(
        self,
        *,
        key_id: str,
        algorithm: SignatureAlgorithm,
    ) -> AuditExportSignatureVerifier | None:
        verifier = self.verifiers.get(key_id)
        if verifier is None:
            return None
        if algorithm not in verifier.supported_algorithms:
            return None
        return verifier


def verification_state_catalog() -> tuple[dict[str, str], ...]:
    """Trust Center-safe state metadata for audit export verification."""

    return (
        {
            "state": VerificationState.VERIFIED.value,
            "severity": "success",
            "meaning": "Package integrity, manifest, chain proof, and signature were verified.",
        },
        {
            "state": VerificationState.TAMPERED.value,
            "severity": "critical",
            "meaning": "Package contents, proof, digest, tenant binding, or signature did not match.",
        },
        {
            "state": VerificationState.VERIFICATION_FAILED.value,
            "severity": "high",
            "meaning": "The package could not be verified because required artifacts were invalid or missing.",
        },
        {
            "state": VerificationState.UNSUPPORTED_VERSION.value,
            "severity": "medium",
            "meaning": "The package uses an unsupported schema, package, manifest, or algorithm version.",
        },
        {
            "state": VerificationState.EXPIRED.value,
            "severity": "medium",
            "meaning": "The package verification policy marks the export as expired.",
        },
        {
            "state": VerificationState.UNKNOWN.value,
            "severity": "medium",
            "meaning": "Integrity checks completed, but no trusted verifier was available for the signing key.",
        },
        {
            "state": VerificationState.ERROR.value,
            "severity": "high",
            "meaning": "A controlled verification error occurred without exposing package contents.",
        },
    )


class AuditExportVerificationService:
    """Verify deterministic signed audit export packages."""

    def __init__(
        self,
        *,
        signature_resolver: SignatureVerifierResolver | None = None,
        chain_proof_service: ChainProofService | None = None,
        max_package_bytes: int = MAX_AUDIT_EXPORT_PACKAGE_BYTES,
    ) -> None:
        self.signature_resolver = signature_resolver
        self.chain_proof_service = chain_proof_service or ChainProofService()
        self.max_package_bytes = max_package_bytes

    def verify_package(
        self,
        package_bytes: bytes,
        *,
        expected_tenant_id: UUID | None = None,
        original_records: Sequence[AuditRecord] | None = None,
    ) -> VerificationResultContract:
        """Verify package integrity and return a sanitized deterministic result."""

        if len(package_bytes) > self.max_package_bytes:
            return self._result(
                VerificationState.VERIFICATION_FAILED,
                errors=("package_too_large",),
            )

        try:
            files = _read_zip_text_files(package_bytes)
            missing = _missing_required_files(files)
            if missing:
                return self._result(
                    VerificationState.VERIFICATION_FAILED,
                    errors=(f"missing_required_file:{missing[0]}",),
                )
            extra = _extra_package_files(files)
            if extra:
                return self._result(
                    VerificationState.VERIFICATION_FAILED,
                    errors=("unexpected_package_file",),
                )

            manifest_payload = _json_load(files[ExportPackagePath.MANIFEST.value], "manifest")
            version_errors = _manifest_version_errors(manifest_payload)
            if version_errors:
                return self._result(
                    VerificationState.UNSUPPORTED_VERSION,
                    manifest_payload=manifest_payload,
                    errors=tuple(version_errors),
                )

            manifest = AuditExportManifestContract.model_validate(manifest_payload)
            algorithm_errors = _algorithm_errors(manifest)
            if algorithm_errors:
                return self._result(
                    VerificationState.UNSUPPORTED_VERSION,
                    manifest=manifest,
                    errors=tuple(algorithm_errors),
                )

            if expected_tenant_id is not None and manifest.tenant_id != expected_tenant_id:
                return self._result(
                    VerificationState.TAMPERED,
                    manifest=manifest,
                    errors=("tenant_mismatch",),
                )

            digest_errors = _file_digest_errors(manifest, files)
            if digest_errors:
                return self._result(
                    VerificationState.TAMPERED,
                    manifest=manifest,
                    errors=tuple(digest_errors),
                )

            manifest_errors = _manifest_consistency_errors(manifest, files)
            if manifest_errors:
                return self._result(
                    VerificationState.TAMPERED,
                    manifest=manifest,
                    errors=tuple(manifest_errors),
                )

            proof_result = self._verify_chain_proof(
                manifest=manifest,
                files=files,
                original_records=original_records,
            )
            if proof_result.state != VerificationState.VERIFIED:
                return proof_result

            signature_result = self._verify_signature(
                manifest=manifest,
                signature=files[ExportPackagePath.SIGNATURE.value],
            )
            if signature_result.state != VerificationState.VERIFIED:
                return signature_result

            return self._result(VerificationState.VERIFIED, manifest=manifest)
        except (AuditExportVerificationError, ValidationError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
            return self._result(
                VerificationState.VERIFICATION_FAILED,
                errors=(_safe_error_code(exc),),
            )
        except Exception:
            return self._result(VerificationState.ERROR, errors=("verification_error",))

    def _verify_chain_proof(
        self,
        *,
        manifest: AuditExportManifestContract,
        files: Mapping[str, str],
        original_records: Sequence[AuditRecord] | None,
    ) -> VerificationResultContract:
        proof_payload = _json_load(files[ExportPackagePath.CHAIN_PROOF.value], "chain_proof")
        if proof_payload.get("schema") != CHAIN_PROOF_SCHEMA:
            return self._result(
                VerificationState.UNSUPPORTED_VERSION,
                manifest=manifest,
                errors=("unsupported_chain_proof_schema",),
            )
        if proof_payload.get("schema_version") != CHAIN_PROOF_SCHEMA_VERSION:
            return self._result(
                VerificationState.UNSUPPORTED_VERSION,
                manifest=manifest,
                errors=("unsupported_chain_proof_version",),
            )
        proof = ChainProofDocument.model_validate(proof_payload)
        proof_errors = _chain_proof_consistency_errors(manifest, proof, files)
        if proof_errors:
            return self._result(
                VerificationState.TAMPERED,
                manifest=manifest,
                errors=tuple(proof_errors),
            )
        if original_records is None:
            return self._result(VerificationState.VERIFIED, manifest=manifest)

        expected_manifest_digest: str | None = None
        if proof.chain_proof.manifest_digest != MANIFEST_DIGEST_PLACEHOLDER:
            expected_manifest_digest = build_manifest_hash(
                manifest.model_dump(mode="json", by_alias=True)
            )
        chain_result = self.chain_proof_service.verify(
            proof=proof,
            records=original_records,
            expected_tenant_id=manifest.tenant_id,
            expected_manifest_digest=expected_manifest_digest,
        )
        if not chain_result.chain_valid:
            return self._result(
                VerificationState.TAMPERED,
                manifest=manifest,
                errors=chain_result.errors or ("chain_proof_invalid",),
            )
        return self._result(VerificationState.VERIFIED, manifest=manifest)

    def _verify_signature(
        self,
        *,
        manifest: AuditExportManifestContract,
        signature: str,
    ) -> VerificationResultContract:
        signature_info = manifest.signature_information
        algorithm = SignatureAlgorithm(signature_info.signature_algorithm)
        if algorithm != SignatureAlgorithm.ES256:
            return self._result(
                VerificationState.UNSUPPORTED_VERSION,
                manifest=manifest,
                errors=("unsupported_signature_algorithm",),
            )
        if self.signature_resolver is None:
            return self._result(
                VerificationState.UNKNOWN,
                manifest=manifest,
                warnings=("signature_verifier_unavailable",),
            )
        verifier = self.signature_resolver.resolve(
            key_id=signature_info.key_id,
            algorithm=algorithm,
        )
        if verifier is None:
            return self._result(
                VerificationState.UNKNOWN,
                manifest=manifest,
                warnings=("signature_verifier_unavailable",),
            )
        manifest_digest = build_manifest_hash(manifest.model_dump(mode="json", by_alias=True))
        if not verifier.verify_digest_signature(
            manifest_digest=manifest_digest,
            signature=signature,
            algorithm=algorithm,
        ):
            return self._result(
                VerificationState.TAMPERED,
                manifest=manifest,
                errors=("invalid_signature",),
            )
        return self._result(VerificationState.VERIFIED, manifest=manifest)

    @staticmethod
    def _result(
        state: VerificationState,
        *,
        manifest: AuditExportManifestContract | None = None,
        manifest_payload: Mapping[str, Any] | None = None,
        errors: tuple[str, ...] = (),
        warnings: tuple[str, ...] = (),
    ) -> VerificationResultContract:
        tenant_id = manifest.tenant_id if manifest is not None else _payload_uuid(manifest_payload, "tenant_id")
        export_id = manifest.export_id if manifest is not None else _payload_uuid(manifest_payload, "export_id")
        record_count = manifest.record_count if manifest is not None else _payload_int(manifest_payload, "record_count")
        signature_key_id = manifest.signature_information.key_id if manifest is not None else None
        signature_algorithm = (
            str(manifest.signature_information.signature_algorithm) if manifest is not None else None
        )
        manifests_clean = state in {VerificationState.VERIFIED, VerificationState.UNKNOWN} and not errors
        signature_clean = state == VerificationState.VERIFIED and not errors
        tenant_clean = "tenant_mismatch" not in errors
        return VerificationResultContract(
            state=state,
            export_id=export_id,
            tenant_id=tenant_id,
            schema=AUDIT_EXPORT_SCHEMA if manifest is not None else None,
            record_count=record_count,
            manifest_digest=build_manifest_hash(manifest.model_dump(mode="json", by_alias=True))
            if manifest is not None
            else None,
            manifest_valid=manifests_clean,
            files_valid=manifests_clean,
            chain_valid=manifests_clean,
            signature_valid=signature_clean,
            security_summary=VerificationSecuritySummaryContract(
                tenant_isolation=SecurityCheckState.PASSED
                if tenant_clean
                else SecurityCheckState.FAILED,
                manifest_integrity=SecurityCheckState.PASSED
                if manifests_clean
                else SecurityCheckState.FAILED,
                export_integrity=SecurityCheckState.PASSED
                if manifests_clean
                else SecurityCheckState.FAILED,
                chain_integrity=SecurityCheckState.PASSED
                if manifests_clean
                else SecurityCheckState.FAILED,
                signature_integrity=SecurityCheckState.PASSED
                if signature_clean
                else (
                    SecurityCheckState.WARNING
                    if state == VerificationState.UNKNOWN
                    else SecurityCheckState.FAILED
                ),
                safe_export=SecurityCheckState.PASSED if manifests_clean else SecurityCheckState.WARNING,
                safe_verification=SecurityCheckState.PASSED,
            ),
            errors=tuple(errors),
            warnings=tuple(warnings),
            metadata={
                "signature_key_id": signature_key_id,
                "signature_algorithm": signature_algorithm,
            },
        )


def _read_zip_text_files(package_bytes: bytes) -> dict[str, str]:
    with zipfile.ZipFile(BytesIO(package_bytes), "r") as archive:
        return {
            name: archive.read(name).decode("utf-8")
            for name in archive.namelist()
        }


def _missing_required_files(files: Mapping[str, str]) -> list[str]:
    required = {path.value for path in REQUIRED_EXPORT_PACKAGE_PATHS}
    return sorted(required.difference(files))


def _extra_package_files(files: Mapping[str, str]) -> list[str]:
    required = {path.value for path in REQUIRED_EXPORT_PACKAGE_PATHS}
    return sorted(set(files).difference(required))


def _json_load(value: str, artifact: str) -> Mapping[str, Any]:
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AuditExportVerificationError(f"invalid_json:{artifact}") from exc
    if not isinstance(loaded, Mapping):
        raise AuditExportVerificationError(f"invalid_json_object:{artifact}")
    return loaded


def _jsonl_load(value: str) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    for index, line in enumerate(value.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditExportVerificationError(f"invalid_audit_jsonl:{index}") from exc
        if not isinstance(loaded, Mapping):
            raise AuditExportVerificationError(f"invalid_audit_record:{index}")
        records.append(loaded)
    return records


def _manifest_version_errors(manifest_payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest_payload.get("schema") != AUDIT_EXPORT_SCHEMA:
        errors.append("unsupported_schema")
    if manifest_payload.get("schema_version") != AUDIT_EXPORT_SCHEMA_VERSION:
        errors.append("unsupported_schema_version")
    if manifest_payload.get("package_version") != AUDIT_EXPORT_PACKAGE_VERSION:
        errors.append("unsupported_package_version")
    if manifest_payload.get("manifest_version") != AUDIT_EXPORT_MANIFEST_VERSION:
        errors.append("unsupported_manifest_version")
    algorithms = manifest_payload.get("algorithm_identifiers")
    if isinstance(algorithms, Mapping):
        if algorithms.get("hash_algorithm") != HashAlgorithm.SHA_256.value:
            errors.append("unsupported_hash_algorithm")
        if algorithms.get("signature_algorithm") != SignatureAlgorithm.ES256.value:
            errors.append("unsupported_signature_algorithm")
        if algorithms.get("canonicalization") != CanonicalizationIdentifier.AUTHCLAW_CANONICAL_JSON_V1.value:
            errors.append("unsupported_canonicalization")
    return errors


def _algorithm_errors(manifest: AuditExportManifestContract) -> list[str]:
    errors: list[str] = []
    algorithms = manifest.algorithm_identifiers
    if algorithms.hash_algorithm != HashAlgorithm.SHA_256:
        errors.append("unsupported_hash_algorithm")
    if algorithms.signature_algorithm != SignatureAlgorithm.ES256:
        errors.append("unsupported_signature_algorithm")
    if algorithms.canonicalization != CanonicalizationIdentifier.AUTHCLAW_CANONICAL_JSON_V1:
        errors.append("unsupported_canonicalization")
    return errors


def _file_digest_errors(
    manifest: AuditExportManifestContract,
    files: Mapping[str, str],
) -> list[str]:
    errors: list[str] = []
    for path in sorted(path.value for path in REQUIRED_EXPORT_PACKAGE_PATHS):
        digest_entry = manifest.file_digest_map.get(path)
        if digest_entry is None:
            errors.append(f"missing_manifest_digest:{path}")
            continue
        if path == ExportPackagePath.MANIFEST.value:
            if digest_entry.digest != MANIFEST_SELF_DIGEST_PLACEHOLDER:
                errors.append("manifest_self_digest_mismatch")
            continue
        if path == ExportPackagePath.SIGNATURE.value:
            if digest_entry.digest != SIGNATURE_FILE_DIGEST_PLACEHOLDER:
                errors.append("signature_digest_mismatch")
            continue
        content = files.get(path)
        if content is None:
            errors.append(f"missing_package_file:{path}")
            continue
        encoded = content.encode("utf-8")
        if digest_entry.size_bytes != len(encoded):
            errors.append(f"file_size_mismatch:{path}")
        if digest_entry.digest != hashlib.sha256(encoded).hexdigest():
            errors.append(f"file_digest_mismatch:{path}")
    return errors


def _manifest_consistency_errors(
    manifest: AuditExportManifestContract,
    files: Mapping[str, str],
) -> list[str]:
    errors: list[str] = []
    audit_records = _jsonl_load(files[ExportPackagePath.AUDIT.value])
    if manifest.record_count != len(audit_records):
        errors.append("record_count_mismatch")
    chain_info = manifest.chain_information
    if chain_info.record_count != len(audit_records):
        errors.append("chain_record_count_mismatch")
    if audit_records:
        first_id = str(audit_records[0].get("record_id") or audit_records[0].get("id") or "")
        last_id = str(audit_records[-1].get("record_id") or audit_records[-1].get("id") or "")
        if chain_info.start_record_id and first_id and chain_info.start_record_id != first_id:
            errors.append("manifest_start_record_mismatch")
        if chain_info.end_record_id and last_id and chain_info.end_record_id != last_id:
            errors.append("manifest_end_record_mismatch")
    return errors


def _chain_proof_consistency_errors(
    manifest: AuditExportManifestContract,
    proof: ChainProofDocument,
    files: Mapping[str, str],
) -> list[str]:
    errors: list[str] = []
    audit_records = _jsonl_load(files[ExportPackagePath.AUDIT.value])
    proof_records = list(proof.records)
    if proof.chain_proof.tenant_id != manifest.tenant_id:
        errors.append("chain_tenant_mismatch")
    if proof.chain_proof.record_range.tenant_id != manifest.tenant_id:
        errors.append("chain_range_tenant_mismatch")
    if proof.chain_proof.record_range.record_count != manifest.record_count:
        errors.append("chain_record_count_mismatch")
    if len(proof_records) != len(audit_records):
        errors.append("chain_proof_record_count_mismatch")
    if proof.chain_proof.start_previous_hash != manifest.chain_information.start_previous_hash:
        errors.append("chain_start_previous_hash_mismatch")
    if proof.chain_proof.expected_final_integrity_hash != manifest.chain_information.final_integrity_hash:
        errors.append("chain_final_integrity_hash_mismatch")
    if proof.chain_proof.record_range.start_record_id != manifest.chain_information.start_record_id:
        errors.append("chain_start_record_mismatch")
    if proof.chain_proof.record_range.end_record_id != manifest.chain_information.end_record_id:
        errors.append("chain_end_record_mismatch")
    audit_ids = [str(record.get("record_id") or record.get("id") or "") for record in audit_records]
    proof_ids = [record.record_id for record in proof_records]
    if audit_ids != proof_ids:
        errors.append("chain_audit_record_order_mismatch")
    expected_previous = proof.chain_proof.start_previous_hash
    for record in proof_records:
        if record.previous_hash != expected_previous:
            errors.append("chain_previous_hash_mismatch")
            break
        expected_previous = record.integrity_hash
    if (
        proof.chain_proof.manifest_digest not in {MANIFEST_DIGEST_PLACEHOLDER, ""}
        and proof.chain_proof.manifest_digest
        != build_manifest_hash(manifest.model_dump(mode="json", by_alias=True))
    ):
        errors.append("chain_manifest_digest_mismatch")
    return errors


def _payload_uuid(payload: Mapping[str, Any] | None, key: str) -> UUID | None:
    if payload is None:
        return None
    value = payload.get(key)
    try:
        return UUID(str(value)) if value else None
    except ValueError:
        return None


def _payload_int(payload: Mapping[str, Any] | None, key: str) -> int:
    if payload is None:
        return 0
    value = payload.get(key)
    return int(value) if isinstance(value, int) else 0


def _safe_error_code(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        first_error = exc.errors()[0]
        return f"validation_error:{first_error['type']}"
    message = str(exc).split(":", 1)[0].strip()
    return message or exc.__class__.__name__
