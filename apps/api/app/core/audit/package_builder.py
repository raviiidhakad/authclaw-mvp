"""
E4.4 Phase 5 signed audit export package generation.

This module assembles deterministic ZIP package bytes from the Phase 2 export
builder, Phase 3 chain proof, and Phase 4 signing abstraction. It does not
publish APIs, integrate with Trust Center, manage certificates, or modify audit
runtime paths.
"""
from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from typing import Mapping
from uuid import UUID

from app.core.audit.export_builder import AuditExportAssembly, AuditExportBuilder
from app.core.audit.export_contracts import (
    AuditExportManifestContract,
    ExportPackagePath,
    FileDigestContract,
    REQUIRED_EXPORT_PACKAGE_PATHS,
    SignatureAlgorithm,
    SignatureInformationContract,
)
from app.core.audit.signing import AuditExportSigningService, SignatureResult
from app.services.trust_reporting import build_manifest_hash, canonical_json


MANIFEST_SELF_DIGEST_PLACEHOLDER = "MANIFEST_SELF_DIGEST_RESERVED"
SIGNATURE_FILE_DIGEST_PLACEHOLDER = "DETACHED_SIGNATURE_DIGEST_RESERVED"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class AuditExportPackageError(ValueError):
    """Base class for sanitized package assembly errors."""


class MissingPackageArtifactError(AuditExportPackageError):
    """Raised when required package content is unavailable before assembly."""


@dataclass(frozen=True)
class SignedAuditExportPackage:
    """Final in-memory signed audit export package."""

    export_id: UUID
    tenant_id: UUID
    manifest: AuditExportManifestContract
    manifest_digest: str
    signature: SignatureResult
    files: Mapping[str, str]
    package_bytes: bytes


class AuditExportPackageBuilder:
    """Build deterministic signed audit export ZIP packages."""

    def __init__(
        self,
        *,
        export_builder: AuditExportBuilder,
        signing_service: AuditExportSigningService,
    ) -> None:
        self.export_builder = export_builder
        self.signing_service = signing_service

    async def build(
        self,
        *,
        signing_timestamp: datetime | None = None,
        signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.ES256,
        **export_builder_kwargs,
    ) -> SignedAuditExportPackage:
        assembly = await self.export_builder.build(**export_builder_kwargs)
        return self.assemble(
            assembly,
            signing_timestamp=signing_timestamp,
            signature_algorithm=signature_algorithm,
        )

    def assemble(
        self,
        assembly: AuditExportAssembly,
        *,
        signing_timestamp: datetime | None = None,
        signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.ES256,
    ) -> SignedAuditExportPackage:
        timestamp = _normalize_timestamp(signing_timestamp or datetime.now(UTC))
        signature_information = SignatureInformationContract(
            signature_algorithm=signature_algorithm,
            key_id=self.signing_service.provider.key_id,
            created_at=timestamp,
            verification_hint="Detached signature over canonical manifest digest.",
        )
        content_files = dict(assembly.files)
        self._assert_required_content_available(content_files)

        manifest = self._build_final_manifest(
            assembly=assembly,
            content_files=content_files,
            signature_information=signature_information,
        )
        manifest_json = canonical_json(manifest.model_dump(mode="json", by_alias=True))
        manifest_digest = build_manifest_hash(manifest.model_dump(mode="json", by_alias=True))
        signature = self.signing_service.sign_digest(
            manifest_digest,
            algorithm=signature_algorithm,
            signing_timestamp=timestamp,
        )
        if signature.signature_information != signature_information:
            raise AuditExportPackageError("signing service returned inconsistent signature metadata")

        final_files = {
            ExportPackagePath.MANIFEST.value: manifest_json,
            ExportPackagePath.AUDIT.value: content_files[ExportPackagePath.AUDIT.value],
            ExportPackagePath.CHAIN_PROOF.value: content_files[ExportPackagePath.CHAIN_PROOF.value],
            ExportPackagePath.METADATA.value: content_files[ExportPackagePath.METADATA.value],
            ExportPackagePath.REDACTION_METRICS.value: content_files[
                ExportPackagePath.REDACTION_METRICS.value
            ],
            ExportPackagePath.CONFIG_SNAPSHOT.value: content_files[
                ExportPackagePath.CONFIG_SNAPSHOT.value
            ],
            ExportPackagePath.SIGNATURE.value: signature.signature,
        }
        package_bytes = _build_deterministic_zip(final_files)

        return SignedAuditExportPackage(
            export_id=assembly.export_id,
            tenant_id=assembly.tenant_id,
            manifest=manifest,
            manifest_digest=manifest_digest,
            signature=signature,
            files=final_files,
            package_bytes=package_bytes,
        )

    def _build_final_manifest(
        self,
        *,
        assembly: AuditExportAssembly,
        content_files: Mapping[str, str],
        signature_information: SignatureInformationContract,
    ) -> AuditExportManifestContract:
        file_digest_map = _build_package_file_digest_map(content_files)
        return assembly.manifest.model_copy(
            update={
                "file_digest_map": file_digest_map,
                "signature_information": signature_information,
            }
        )

    @staticmethod
    def _assert_required_content_available(files: Mapping[str, str]) -> None:
        required_content = (
            ExportPackagePath.AUDIT,
            ExportPackagePath.CHAIN_PROOF,
            ExportPackagePath.METADATA,
            ExportPackagePath.REDACTION_METRICS,
            ExportPackagePath.CONFIG_SNAPSHOT,
        )
        missing = [path.value for path in required_content if path.value not in files]
        if missing:
            raise MissingPackageArtifactError(f"missing package artifact: {missing[0]}")


def _build_package_file_digest_map(files: Mapping[str, str]) -> dict[str, FileDigestContract]:
    digest_map: dict[str, FileDigestContract] = {}
    for path in sorted(path.value for path in REQUIRED_EXPORT_PACKAGE_PATHS):
        if path == ExportPackagePath.MANIFEST.value:
            digest = MANIFEST_SELF_DIGEST_PLACEHOLDER
            size_bytes = 0
        elif path == ExportPackagePath.SIGNATURE.value:
            digest = SIGNATURE_FILE_DIGEST_PLACEHOLDER
            size_bytes = 0
        else:
            content = files.get(path, "")
            digest = _sha256_text(content)
            size_bytes = len(content.encode("utf-8"))
        digest_map[path] = FileDigestContract(
            path=path,
            digest=digest,
            size_bytes=size_bytes,
            required=True,
        )
    return digest_map


def _build_deterministic_zip(files: Mapping[str, str]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for path in _package_file_order():
            if path not in files:
                raise MissingPackageArtifactError(f"missing package artifact: {path}")
            info = zipfile.ZipInfo(filename=path, date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            archive.writestr(info, files[path].encode("utf-8"))
    return buffer.getvalue()


def _package_file_order() -> tuple[str, ...]:
    return tuple(path.value for path in REQUIRED_EXPORT_PACKAGE_PATHS)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
