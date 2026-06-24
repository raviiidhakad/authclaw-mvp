"""
AuthClaw Sprint 1 — Security Classification Layer
--------------------------------------------------
Maps Presidio entity types to a four-tier risk severity model.

  LOW      — Generic identifiers with low harm potential (first name, location)
  MEDIUM   — Sensitive but not directly exploitable without context
  HIGH     — Financially sensitive; regulated under PCI-DSS / GDPR
  CRITICAL — Protected Health Information (PHI) under HIPAA

Design rules:
  1. Unknown entity types always classify as CRITICAL (fail-safe by default).
  2. Tenants may override individual entity classifications via their Redis-cached
     policy configuration. Overrides can only lower a classification, never raise
     one above the system default (anti-privilege-escalation).
  3. Classification is evaluated per-entity at scan time, before policy decisions.
"""
from enum import Enum
from typing import Dict, Optional


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Default system entity-to-risk map ──────────────────────────────────────────
# Ordered from most to least permissive.
# Source of truth for base classifications — tenants may only override downward.

DEFAULT_ENTITY_RISK_MAP: Dict[str, RiskLevel] = {
    # LOW — Generic PII with minimal standalone harm
    "PERSON":              RiskLevel.LOW,
    "LOCATION":            RiskLevel.LOW,
    "DATE_TIME":           RiskLevel.LOW,
    "URL":                 RiskLevel.LOW,
    "NRP":                 RiskLevel.LOW,   # Nationality/religion/political group

    # MEDIUM — Sensitive contact and demographic data
    "EMAIL_ADDRESS":       RiskLevel.MEDIUM,
    "PHONE_NUMBER":        RiskLevel.MEDIUM,
    "ADDRESS":             RiskLevel.MEDIUM,
    "DATE":                RiskLevel.MEDIUM,
    "AGE":                 RiskLevel.MEDIUM,
    "IP_ADDRESS":          RiskLevel.MEDIUM,

    # HIGH — Financially regulated data (PCI-DSS / GDPR)
    "CREDIT_CARD":         RiskLevel.HIGH,
    "IBAN_CODE":           RiskLevel.HIGH,
    "BANK_ACCOUNT":        RiskLevel.HIGH,
    "US_SSN":              RiskLevel.HIGH,
    "US_PASSPORT":         RiskLevel.HIGH,
    "US_DRIVER_LICENSE":   RiskLevel.HIGH,
    "US_ITIN":             RiskLevel.HIGH,
    "UK_NHS":              RiskLevel.HIGH,
    "CREDENTIAL":          RiskLevel.HIGH,

    # CRITICAL — Protected Health Information (PHI) under HIPAA
    "MEDICAL_RECORD":      RiskLevel.CRITICAL,
    "PHI_MRN":             RiskLevel.CRITICAL,
    "PHI_NPI":             RiskLevel.CRITICAL,
    "PHI_INSURANCE_ID":    RiskLevel.CRITICAL,
}


class SecurityClassifier:
    """
    Classifies Presidio entity types into risk levels.

    Tenant overrides are loaded from the compiled Redis policy cache and merged
    at classification time. The merge enforces that overrides can only lower the
    risk (i.e., downgrade from CRITICAL to HIGH), never elevate it.
    """

    _RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

    def classify(
        self,
        entity_type: str,
        tenant_overrides: Optional[Dict[str, str]] = None,
    ) -> RiskLevel:
        """
        Return the effective risk level for an entity type.

        Args:
            entity_type:       Presidio entity type string (e.g. "EMAIL_ADDRESS").
            tenant_overrides:  Optional dict from Redis-cached tenant policy.
                               Keys are entity types; values are RiskLevel strings.

        Returns:
            RiskLevel — defaults to CRITICAL for any unknown entity type.
        """
        # System default (unknown = CRITICAL: fail-safe)
        system_risk = DEFAULT_ENTITY_RISK_MAP.get(entity_type, RiskLevel.CRITICAL)

        if not tenant_overrides:
            return system_risk

        # Tenant override: only accepted if it lowers the risk, never raises it
        override_str = tenant_overrides.get(entity_type)
        if override_str:
            try:
                override_risk = RiskLevel(override_str)
                # Enforce: override may only move risk downward
                if self._risk_index(override_risk) <= self._risk_index(system_risk):
                    return override_risk
            except ValueError:
                pass  # Invalid override string — ignore, use system default

        return system_risk

    def classify_many(
        self,
        entity_types: list[str],
        tenant_overrides: Optional[Dict[str, str]] = None,
    ) -> Dict[str, RiskLevel]:
        """Batch-classify a list of entity types."""
        return {et: self.classify(et, tenant_overrides) for et in entity_types}

    def max_risk(
        self,
        entity_types: list[str],
        tenant_overrides: Optional[Dict[str, str]] = None,
    ) -> Optional[RiskLevel]:
        """Return the highest risk level across a set of entity types."""
        if not entity_types:
            return None
        classified = self.classify_many(entity_types, tenant_overrides)
        return max(classified.values(), key=self._risk_index)

    def _risk_index(self, level: RiskLevel) -> int:
        return self._RISK_ORDER.index(level)


# Module-level singleton — import this directly in the pipeline
classifier = SecurityClassifier()
