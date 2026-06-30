from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.core.audit.export_contracts import (
    AuditExportManifestContract,
    ChainInformationContract,
    FileDigestContract,
    SignatureAlgorithm,
    SignatureInformationContract,
    TimeRangeContract,
)
from app.core.audit.signing import (
    AuditExportSigningService,
    LocalEs256SigningProvider,
    MissingManifestDigestError,
    SignatureResult,
    UnsupportedSignatureAlgorithmError,
)


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
EXPORT_ID = UUID("22222222-2222-4222-8222-222222222222")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


class FutureCompatibleProvider:
    key_id = "future-provider-key"
    supported_algorithms = (SignatureAlgorithm.ES256,)

    def __init__(self) -> None:
        self.calls: list[tuple[str, SignatureAlgorithm]] = []

    def sign_digest(
        self,
        *,
        manifest_digest: str,
        algorithm: SignatureAlgorithm,
    ) -> str:
        self.calls.append((manifest_digest, algorithm))
        return f"future-signature-for-{manifest_digest[:8]}"


class UnsupportedProvider:
    key_id = "unsupported-key"
    supported_algorithms = ()

    def sign_digest(
        self,
        *,
        manifest_digest: str,
        algorithm: SignatureAlgorithm,
    ) -> str:
        raise AssertionError("unsupported provider must not be called")


def _manifest() -> AuditExportManifestContract:
    return AuditExportManifestContract(
        created_at=NOW,
        tenant_id=TENANT_ID,
        export_id=EXPORT_ID,
        record_count=1,
        time_range=TimeRangeContract(start_at=NOW, end_at=NOW),
        file_digest_map={
            "manifest.json": FileDigestContract(
                path="manifest.json",
                digest="a" * 64,
                size_bytes=128,
            ),
            "audit.jsonl": FileDigestContract(
                path="audit.jsonl",
                digest="b" * 64,
                size_bytes=256,
            ),
        },
        chain_information=ChainInformationContract(
            start_record_id="record-1",
            end_record_id="record-1",
            start_previous_hash="0" * 64,
            final_integrity_hash="c" * 64,
            record_count=1,
        ),
        signature_information=SignatureInformationContract(
            key_id="pending",
            created_at=NOW,
        ),
        tool_version="0.9.0-test",
        generator="test",
    )


def test_local_es256_signing_success():
    provider = LocalEs256SigningProvider(key_id="local-es256-test-key")
    service = AuditExportSigningService(provider, tool_version="0.9.0-test")

    result = service.sign_manifest(_manifest(), signing_timestamp=NOW)

    assert isinstance(result, SignatureResult)
    assert result.signature_algorithm == SignatureAlgorithm.ES256
    assert result.key_id == "local-es256-test-key"
    assert result.signature
    assert result.signing_timestamp == NOW
    assert result.tool_version == "0.9.0-test"
    assert provider.verify_local_signature(
        manifest_digest=result.manifest_digest,
        signature=result.signature,
    )


def test_manifest_digest_preparation_is_deterministic():
    provider = LocalEs256SigningProvider(key_id="local-es256-test-key")
    service = AuditExportSigningService(provider)
    manifest = _manifest()

    first = service.prepare_manifest_digest(manifest)
    second = service.prepare_manifest_digest(manifest.model_dump(mode="json", by_alias=True))

    assert first == second
    assert first.hash_algorithm == "SHA-256"
    assert first.canonicalization == "authclaw.canonical-json/v1"
    assert first.signed_object == "manifest_digest"
    assert len(first.manifest_digest) == 64


def test_algorithm_identifier_and_key_identifier_propagate_to_metadata():
    provider = LocalEs256SigningProvider(key_id="audit-export-key-v1")
    service = AuditExportSigningService(provider, tool_version="0.9.0-test")

    result = service.sign_manifest(
        _manifest(),
        algorithm=SignatureAlgorithm.ES256,
        signing_timestamp=NOW,
    )
    info = result.signature_information.model_dump(mode="json", by_alias=True)

    assert result.signature_algorithm == SignatureAlgorithm.ES256
    assert result.key_id == "audit-export-key-v1"
    assert info["signature_algorithm"] == "ES256"
    assert info["key_id"] == "audit-export-key-v1"
    assert info["signature_file"] == "signature.sig"
    assert info["signed_object"] == "manifest_digest"
    assert info["created_at"] == "2026-06-30T12:00:00Z"


def test_invalid_algorithm_is_rejected_before_provider_call():
    provider = LocalEs256SigningProvider(key_id="local-es256-test-key")
    service = AuditExportSigningService(provider)

    with pytest.raises(UnsupportedSignatureAlgorithmError):
        service.sign_manifest(_manifest(), algorithm="RS256")  # type: ignore[arg-type]


def test_missing_manifest_digest_is_rejected():
    provider = LocalEs256SigningProvider(key_id="local-es256-test-key")
    service = AuditExportSigningService(provider)

    with pytest.raises(MissingManifestDigestError):
        service.sign_digest("")


def test_unsupported_signer_is_rejected_without_calling_provider():
    service = AuditExportSigningService(UnsupportedProvider())

    with pytest.raises(UnsupportedSignatureAlgorithmError):
        service.sign_manifest(_manifest())


def test_signature_metadata_construction_for_direct_digest_signing():
    provider = LocalEs256SigningProvider(key_id="direct-digest-key")
    service = AuditExportSigningService(provider, tool_version="0.9.0-test")
    digest = "d" * 64

    result = service.sign_digest(digest, signing_timestamp=NOW)

    assert result.manifest_digest == digest
    assert result.signature_information.key_id == "direct-digest-key"
    assert result.signature_information.signature_algorithm == SignatureAlgorithm.ES256
    assert result.signature_information.certificate_reference is None
    assert result.signature_information.verification_hint == (
        "Detached signature over canonical manifest digest."
    )


def test_future_provider_compatibility_boundary():
    provider = FutureCompatibleProvider()
    service = AuditExportSigningService(provider, tool_version="future-test")
    digest = "e" * 64

    result = service.sign_digest(digest, algorithm="ES256", signing_timestamp=NOW)

    assert provider.calls == [(digest, SignatureAlgorithm.ES256)]
    assert result.signature == "future-signature-for-eeeeeeee"
    assert result.key_id == "future-provider-key"
    assert result.tool_version == "future-test"
