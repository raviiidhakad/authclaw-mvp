"""
E4.4 Phase 4 signing abstraction.

This module signs canonical manifest digests only. It does not create ZIP files,
publish APIs, validate certificate chains, modify Trust Center behavior, or
change audit/runtime paths.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from app.core.audit.export_contracts import (
    AuditExportManifestContract,
    HashAlgorithm,
    SignatureAlgorithm,
    SignatureInformationContract,
)
from app.services.trust_reporting import build_manifest_hash


SIGNING_SERVICE_TOOL_VERSION = "0.9.0"


class AuditExportSigningError(ValueError):
    """Base class for sanitized audit export signing failures."""


class MissingManifestDigestError(AuditExportSigningError):
    """Raised when signing input does not include a manifest digest."""


class UnsupportedSignatureAlgorithmError(AuditExportSigningError):
    """Raised when a provider cannot sign with the requested algorithm."""


@dataclass(frozen=True)
class ManifestDigestInput:
    """Deterministic manifest digest prepared for signing."""

    manifest_digest: str
    hash_algorithm: HashAlgorithm
    canonicalization: str
    signed_object: str = "manifest_digest"


@dataclass(frozen=True)
class SignatureResult:
    """Detached signature payload and Phase 1-compatible metadata."""

    signature_algorithm: SignatureAlgorithm
    key_id: str
    signature: str
    signing_timestamp: datetime
    tool_version: str
    manifest_digest: str
    signature_information: SignatureInformationContract


class SigningProvider(Protocol):
    """Pluggable provider boundary for future KMS/HSM/local signers."""

    key_id: str
    supported_algorithms: tuple[SignatureAlgorithm, ...]

    def sign_digest(
        self,
        *,
        manifest_digest: str,
        algorithm: SignatureAlgorithm,
    ) -> str:
        ...


class LocalEs256SigningProvider:
    """
    In-memory ES256 signer for tests and local development.

    The private key is never exported by this provider. Production KMS/HSM
    providers can implement the same SigningProvider protocol in later phases.
    """

    supported_algorithms = (SignatureAlgorithm.ES256,)

    def __init__(
        self,
        *,
        key_id: str,
        private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        self.key_id = key_id
        self._private_key = private_key or ec.generate_private_key(ec.SECP256R1())

    def sign_digest(
        self,
        *,
        manifest_digest: str,
        algorithm: SignatureAlgorithm,
    ) -> str:
        algorithm = normalize_signature_algorithm(algorithm)
        if algorithm not in self.supported_algorithms:
            raise UnsupportedSignatureAlgorithmError(f"unsupported signature algorithm: {algorithm}")
        digest_bytes = _manifest_digest_bytes(manifest_digest)
        der_signature = self._private_key.sign(
            digest_bytes,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        r_value, s_value = utils.decode_dss_signature(der_signature)
        raw_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        return _base64url_encode(raw_signature)

    def verify_local_signature(self, *, manifest_digest: str, signature: str) -> bool:
        """Local test helper; not an export verification engine."""

        digest_bytes = _manifest_digest_bytes(manifest_digest)
        raw_signature = _base64url_decode(signature)
        if len(raw_signature) != 64:
            return False
        r_value = int.from_bytes(raw_signature[:32], "big")
        s_value = int.from_bytes(raw_signature[32:], "big")
        der_signature = utils.encode_dss_signature(r_value, s_value)
        try:
            self._private_key.public_key().verify(
                der_signature,
                digest_bytes,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            return False
        return True


class AuditExportSigningService:
    """Prepare manifest digests and delegate signing to a configured provider."""

    def __init__(
        self,
        provider: SigningProvider,
        *,
        tool_version: str = SIGNING_SERVICE_TOOL_VERSION,
    ) -> None:
        self.provider = provider
        self.tool_version = tool_version

    def prepare_manifest_digest(
        self,
        manifest: AuditExportManifestContract | Mapping[str, object],
    ) -> ManifestDigestInput:
        manifest_json = (
            manifest.model_dump(mode="json", by_alias=True)
            if isinstance(manifest, AuditExportManifestContract)
            else dict(manifest)
        )
        algorithm_identifiers = manifest_json.get("algorithm_identifiers", {})
        if isinstance(algorithm_identifiers, Mapping):
            hash_algorithm = HashAlgorithm(algorithm_identifiers.get("hash_algorithm", HashAlgorithm.SHA_256.value))
            canonicalization = str(algorithm_identifiers.get("canonicalization", "authclaw.canonical-json/v1"))
        else:
            hash_algorithm = HashAlgorithm.SHA_256
            canonicalization = "authclaw.canonical-json/v1"
        if hash_algorithm != HashAlgorithm.SHA_256:
            raise AuditExportSigningError(f"unsupported manifest hash algorithm: {hash_algorithm}")
        return ManifestDigestInput(
            manifest_digest=build_manifest_hash(manifest_json),
            hash_algorithm=hash_algorithm,
            canonicalization=canonicalization,
        )

    def sign_manifest(
        self,
        manifest: AuditExportManifestContract | Mapping[str, object],
        *,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ES256,
        signing_timestamp: datetime | None = None,
    ) -> SignatureResult:
        digest_input = self.prepare_manifest_digest(manifest)
        return self.sign_digest(
            digest_input.manifest_digest,
            algorithm=algorithm,
            signing_timestamp=signing_timestamp,
        )

    def sign_digest(
        self,
        manifest_digest: str,
        *,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ES256,
        signing_timestamp: datetime | None = None,
    ) -> SignatureResult:
        algorithm = normalize_signature_algorithm(algorithm)
        if not manifest_digest:
            raise MissingManifestDigestError("manifest digest is required")
        if algorithm not in self.provider.supported_algorithms:
            raise UnsupportedSignatureAlgorithmError(f"unsupported signature algorithm: {algorithm}")
        timestamp = _normalize_timestamp(signing_timestamp or datetime.now(UTC))
        signature = self.provider.sign_digest(
            manifest_digest=manifest_digest,
            algorithm=algorithm,
        )
        signature_information = SignatureInformationContract(
            signature_algorithm=algorithm,
            key_id=self.provider.key_id,
            created_at=timestamp,
            verification_hint="Detached signature over canonical manifest digest.",
        )
        return SignatureResult(
            signature_algorithm=algorithm,
            key_id=self.provider.key_id,
            signature=signature,
            signing_timestamp=timestamp,
            tool_version=self.tool_version,
            manifest_digest=manifest_digest,
            signature_information=signature_information,
        )


def normalize_signature_algorithm(value: SignatureAlgorithm | str) -> SignatureAlgorithm:
    try:
        return value if isinstance(value, SignatureAlgorithm) else SignatureAlgorithm(value)
    except ValueError as exc:
        raise UnsupportedSignatureAlgorithmError(f"unsupported signature algorithm: {value}") from exc


def _manifest_digest_bytes(manifest_digest: str) -> bytes:
    try:
        digest_bytes = bytes.fromhex(manifest_digest)
    except ValueError as exc:
        raise MissingManifestDigestError("manifest digest must be hex encoded") from exc
    if len(digest_bytes) != 32:
        raise MissingManifestDigestError("manifest digest must be a SHA-256 hex digest")
    return digest_bytes


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
