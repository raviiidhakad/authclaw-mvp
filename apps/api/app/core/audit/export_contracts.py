"""
E4.4 Cryptographic Audit Export contracts.

This module defines immutable specification shapes only. It must remain inert:
no audit export generation, hashing, signing, ZIP creation, verification engine,
database persistence, or runtime integration belongs here.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


AUDIT_EXPORT_SCHEMA = "authclaw.audit.export/v1"
AUDIT_EXPORT_SCHEMA_VERSION = 1
AUDIT_EXPORT_PACKAGE_VERSION = 1
AUDIT_EXPORT_MANIFEST_VERSION = 1
AUDIT_EXPORT_CANONICALIZATION = "authclaw.canonical-json/v1"


class ExportPackagePath(str, Enum):
    """Canonical file paths inside an E4.4 audit export package."""

    MANIFEST = "manifest.json"
    AUDIT = "audit.jsonl"
    CHAIN_PROOF = "chain-proof.json"
    METADATA = "metadata.json"
    REDACTION_METRICS = "redaction-metrics.json"
    CONFIG_SNAPSHOT = "config-snapshot.json"
    SIGNATURE = "signature.sig"
    ATTACHMENTS = "attachments/"


REQUIRED_EXPORT_PACKAGE_PATHS: tuple[ExportPackagePath, ...] = (
    ExportPackagePath.MANIFEST,
    ExportPackagePath.AUDIT,
    ExportPackagePath.CHAIN_PROOF,
    ExportPackagePath.METADATA,
    ExportPackagePath.REDACTION_METRICS,
    ExportPackagePath.CONFIG_SNAPSHOT,
    ExportPackagePath.SIGNATURE,
)


class HashAlgorithm(str, Enum):
    """Versioned hash algorithm identifiers for audit export contracts."""

    SHA_256 = "SHA-256"


class SignatureAlgorithm(str, Enum):
    """Versioned signature algorithm identifiers for audit export contracts."""

    ES256 = "ES256"


class CanonicalizationIdentifier(str, Enum):
    """Canonical serialization identifiers for deterministic export hashing."""

    AUTHCLAW_CANONICAL_JSON_V1 = AUDIT_EXPORT_CANONICALIZATION


class VerificationState(str, Enum):
    """Trust Center/API/offline verifier states defined by the design freeze."""

    VERIFIED = "Verified"
    TAMPERED = "Tampered"
    VERIFICATION_FAILED = "Verification Failed"
    UNSUPPORTED_VERSION = "Unsupported Version"
    EXPIRED = "Expired"
    UNKNOWN = "Unknown"
    ERROR = "Error"


class SecurityCheckState(str, Enum):
    """Normalized security checks that future verifiers must report without raw data."""

    NOT_EVALUATED = "not_evaluated"
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"


class ExportContractModel(BaseModel):
    """Frozen base model for E4.4 contract-only structures."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        populate_by_name=True,
        use_enum_values=True,
    )


class AuditExportVersionIdentifiers(ExportContractModel):
    """Schema, package, manifest, and canonicalization version identifiers."""

    schema_id: str = Field(AUDIT_EXPORT_SCHEMA, alias="schema")
    schema_version: int = AUDIT_EXPORT_SCHEMA_VERSION
    package_version: int = AUDIT_EXPORT_PACKAGE_VERSION
    manifest_version: int = AUDIT_EXPORT_MANIFEST_VERSION
    canonicalization: CanonicalizationIdentifier = (
        CanonicalizationIdentifier.AUTHCLAW_CANONICAL_JSON_V1
    )


class AuditExportAlgorithmIdentifiers(ExportContractModel):
    """Hash and signature algorithm identifiers carried by export manifests."""

    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA_256
    signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.ES256
    canonicalization: CanonicalizationIdentifier = (
        CanonicalizationIdentifier.AUTHCLAW_CANONICAL_JSON_V1
    )


class ExportPackageContract(ExportContractModel):
    """Canonical audit-export package layout contract."""

    required_files: tuple[ExportPackagePath, ...] = REQUIRED_EXPORT_PACKAGE_PATHS
    optional_prefixes: tuple[ExportPackagePath, ...] = (ExportPackagePath.ATTACHMENTS,)
    allow_unlisted_files: bool = False


class TimeRangeContract(ExportContractModel):
    """Inclusive export time range."""

    start_at: datetime
    end_at: datetime


class FileDigestContract(ExportContractModel):
    """Digest metadata for one file inside the canonical package."""

    path: str
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA_256
    digest: str
    size_bytes: int = Field(ge=0)
    required: bool = True


class ChainInformationContract(ExportContractModel):
    """Chain summary embedded in the signed manifest."""

    chain_algorithm: HashAlgorithm = HashAlgorithm.SHA_256
    start_record_id: str
    end_record_id: str
    start_previous_hash: str
    final_integrity_hash: str
    record_count: int = Field(ge=0)
    proof_file: str = ExportPackagePath.CHAIN_PROOF.value


class SignatureInformationContract(ExportContractModel):
    """Detached signature metadata for the canonical manifest digest."""

    signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.ES256
    key_id: str
    signature_file: str = ExportPackagePath.SIGNATURE.value
    signed_object: str = "manifest_digest"
    certificate_reference: str | None = None
    created_at: datetime
    verification_hint: str | None = None


class PackageMetadataContract(ExportContractModel):
    """Tenant-scoped package metadata safe for export manifests."""

    tenant_id: UUID
    export_id: UUID
    created_at: datetime
    requester_id: UUID | None = None
    purpose: str | None = None
    tool_version: str
    generator: str


class AuditExportManifestContract(ExportContractModel):
    """Canonical manifest contract for signed E4.4 audit exports."""

    schema_id: str = Field(AUDIT_EXPORT_SCHEMA, alias="schema")
    schema_version: int = AUDIT_EXPORT_SCHEMA_VERSION
    package_version: int = AUDIT_EXPORT_PACKAGE_VERSION
    manifest_version: int = AUDIT_EXPORT_MANIFEST_VERSION
    created_at: datetime
    tenant_id: UUID
    export_id: UUID
    record_count: int = Field(ge=0)
    time_range: TimeRangeContract
    file_digest_map: dict[str, FileDigestContract]
    chain_information: ChainInformationContract
    signature_information: SignatureInformationContract
    algorithm_identifiers: AuditExportAlgorithmIdentifiers = Field(
        default_factory=AuditExportAlgorithmIdentifiers
    )
    tool_version: str
    generator: str


class AuditRecordRangeContract(ExportContractModel):
    """Ordered audit-record range covered by a chain proof."""

    tenant_id: UUID
    start_record_id: str
    end_record_id: str
    record_count: int = Field(ge=0)
    time_range: TimeRangeContract


class ChainProofContract(ExportContractModel):
    """Hash-chain proof contract for a canonical audit export."""

    tenant_id: UUID
    record_range: AuditRecordRangeContract
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA_256
    canonicalization: CanonicalizationIdentifier = (
        CanonicalizationIdentifier.AUTHCLAW_CANONICAL_JSON_V1
    )
    start_previous_hash: str
    expected_final_integrity_hash: str
    manifest_digest: str


class ChainProofResultContract(ExportContractModel):
    """Future verifier output for audit-chain validation."""

    chain_valid: bool
    record_count: int = Field(ge=0)
    start_record_id: str | None = None
    end_record_id: str | None = None
    start_previous_hash: str | None = None
    final_integrity_hash: str | None = None
    tampered_records: tuple[str, ...] = ()
    missing_records: tuple[str, ...] = ()
    chain_breaks: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


class VerificationSecuritySummaryContract(ExportContractModel):
    """Sanitized security summary for API, CLI, and Trust Center verification."""

    tenant_isolation: SecurityCheckState = SecurityCheckState.NOT_EVALUATED
    manifest_integrity: SecurityCheckState = SecurityCheckState.NOT_EVALUATED
    export_integrity: SecurityCheckState = SecurityCheckState.NOT_EVALUATED
    chain_integrity: SecurityCheckState = SecurityCheckState.NOT_EVALUATED
    signature_integrity: SecurityCheckState = SecurityCheckState.NOT_EVALUATED
    safe_export: SecurityCheckState = SecurityCheckState.NOT_EVALUATED
    safe_verification: SecurityCheckState = SecurityCheckState.NOT_EVALUATED


class VerificationResultContract(ExportContractModel):
    """Canonical verification result shared by offline, API, and Trust Center verifiers."""

    state: VerificationState
    export_id: UUID | None = None
    tenant_id: UUID | None = None
    schema_id: str | None = Field(None, alias="schema")
    record_count: int = Field(default=0, ge=0)
    manifest_digest: str | None = None
    signature_valid: bool | None = None
    manifest_valid: bool | None = None
    files_valid: bool | None = None
    chain_valid: bool | None = None
    security_summary: VerificationSecuritySummaryContract = Field(
        default_factory=VerificationSecuritySummaryContract
    )
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    verified_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
