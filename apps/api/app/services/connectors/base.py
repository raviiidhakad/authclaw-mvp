"""
AuthClaw Sprint 2 — Connector Base Classes & DTOs
--------------------------------------------------
Defines the abstract interface every cloud connector must implement,
plus the `RawFindingData` data-transfer object that connectors populate
instead of writing directly to the database.

Connector → Worker flow:
  1. ConnectorFactory creates a concrete connector (AWS / GitHub / GCP).
  2. ConnectorWorker calls validate_credentials() — raises on invalid auth.
  3. ConnectorWorker calls fetch_findings() — returns List[RawFindingData].
  4. FindingInventoryService upserts the DTOs into PostgreSQL (dedup).
  5. FindingRawStore batch-writes raw_payload dicts to ClickHouse.

No database session is passed to connectors.  That responsibility belongs
to the ConnectorWorker and service layer, keeping connectors pure I/O.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar, List, Optional

from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider

logger = logging.getLogger(__name__)


# ── Data transfer object ────────────────────────────────────────────────────────

@dataclass
class RawFindingData:
    """
    Provider-agnostic finding DTO produced by every connector.

    Connectors populate this from native API responses and return a list.
    The ConnectorWorker hands this to:
      - FindingInventoryService  → upsert into security_findings (Postgres)
      - FindingRawStore          → batch-insert raw_payload into ClickHouse

    Fields:
        external_id:              Provider-native finding ID
                                  (e.g. Security Hub ARN, GitHub alert number).
        resource_id:              Affected resource identifier
                                  (e.g. S3 ARN, GitHub repo full_name).
        title:                    Short human-readable description.
        severity:                 Normalized FindingSeverity enum value.
        description:              Optional detailed description.
        remediation_instructions: Optional guidance from the provider.
        raw_payload:              Full original API response as dict.
                                  Goes to ClickHouse — NOT PostgreSQL.
    """
    external_id: str
    resource_id: str
    title: str
    severity: FindingSeverity
    description: Optional[str] = None
    remediation_instructions: Optional[str] = None
    raw_payload: dict = field(default_factory=dict)


# ── Abstract base connector ────────────────────────────────────────────────────

class BaseConnector(ABC):
    """
    Abstract base for all cloud security connectors.

    Subclasses MUST:
      1. Set the class variable PROVIDER to their CloudProvider enum value.
      2. Implement validate_credentials() — raises ValueError on failure.
      3. Implement fetch_findings() — returns List[RawFindingData].

    Subclasses MUST NOT:
      - Access the database directly. Use RawFindingData DTOs.
      - Store raw credentials beyond __init__. Keep them in self._creds only.
      - Swallow exceptions from provider APIs — let them propagate so the
        ConnectorWorker's circuit breaker can count failures correctly.

    Tenant isolation:
      - self.integration carries the tenant_id from CloudIntegration.
      - All provider API calls are scoped to self.integration.target_identifier.
      - Connectors NEVER accept target_identifier from user input at call time;
        they use only what was stored at integration-creation time.
    """

    PROVIDER: ClassVar[CloudProvider]

    def __init__(
        self,
        integration: CloudIntegration,
        credentials: dict,
    ) -> None:
        """
        Args:
            integration:   CloudIntegration ORM record (read-only — no session needed).
            credentials:   Decrypted credential dict retrieved from Vault.
                           Never logged. Stored in self._creds only.
        """
        self.integration = integration
        self.tenant_id: uuid.UUID = integration.tenant_id
        self.integration_id: uuid.UUID = integration.id
        self.target: str = integration.target_identifier
        # Store under private name to discourage accidental logging
        self._creds: dict = credentials

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    async def validate_credentials(self) -> None:
        """
        Perform a lightweight dry-run call to verify the credentials are valid
        and the connector has the required permissions.

        Raises:
            ValueError:  Human-readable message explaining the failure.
                         e.g. "AWS credential missing securityhub:GetFindings permission"
        """
        ...

    @abstractmethod
    async def fetch_findings(self) -> List[RawFindingData]:
        """
        Retrieve active security findings from the provider.

        Implementations MUST:
          - Respect settings.MAX_FINDINGS_PER_SYNC (truncate if exceeded).
          - Respect settings.MAX_SCAN_DURATION (checked by outer timeout guard).
          - Prefer the primary API path; fall back to native API scanning only
            when the primary path raises a PermissionError / is unavailable.
          - Convert all provider-specific severity scales to FindingSeverity.

        Returns:
            List of RawFindingData DTOs — never raw dicts.

        Raises:
            Any exception from the provider API. The ConnectorWorker's
            circuit breaker records this as a failure.
        """
        ...

    # ── Shared utilities ──────────────────────────────────────────────────────

    def make_dedup_hash(self, external_id: str, resource_id: str) -> str:
        """
        Compute the SHA-256 deduplication hash used for upsert.

        Format:  SHA256("{integration_id}:{external_id}:{resource_id}")
        Length:  64 hex characters — matches the dedup_hash column (String(64)).

        This is stable across scans for the same finding on the same resource,
        so repeated fetches hit the UPDATE path rather than creating duplicates.
        """
        key = f"{self.integration_id}:{external_id}:{resource_id}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _normalize_severity(self, provider_value: str) -> FindingSeverity:
        """
        Map provider-specific severity strings to normalized FindingSeverity.

        Mapping strategy:
          - Unknown / unmapped values default to CRITICAL (fail-safe).
          - AWS uses CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL.
          - GitHub uses critical / high / medium / low / warning / note.
          - GCP uses CRITICAL / HIGH / MEDIUM / LOW.

        The fail-safe default of CRITICAL ensures unmapped severities are
        prioritized for human review, not silently deprioritized.
        """
        mapping: dict[str, FindingSeverity] = {
            # Critical
            "critical": FindingSeverity.critical,
            "CRITICAL": FindingSeverity.critical,
            # High
            "high": FindingSeverity.high,
            "HIGH": FindingSeverity.high,
            # Medium
            "medium": FindingSeverity.medium,
            "MEDIUM": FindingSeverity.medium,
            "warning": FindingSeverity.medium,
            "WARNING": FindingSeverity.medium,
            # Low
            "low": FindingSeverity.low,
            "LOW": FindingSeverity.low,
            "informational": FindingSeverity.low,
            "INFORMATIONAL": FindingSeverity.low,
            "note": FindingSeverity.low,
            "NOTE": FindingSeverity.low,
        }
        normalized = mapping.get(provider_value)
        if normalized is None:
            logger.warning(
                "Unknown provider severity value '%s' for integration %s. "
                "Defaulting to CRITICAL (fail-safe).",
                provider_value,
                self.integration_id,
            )
            return FindingSeverity.critical
        return normalized
