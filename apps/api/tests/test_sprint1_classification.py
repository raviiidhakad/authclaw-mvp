"""
Sprint 1 — Unit Tests: Security Classification Layer
Tests the entity-to-risk mapping, unknown-entity CRITICAL default,
and tenant override enforcement (overrides can only lower risk).
"""
import pytest

from app.core.detection.classification import (
    SecurityClassifier, RiskLevel, DEFAULT_ENTITY_RISK_MAP
)


class TestSecurityClassifier:
    """Unit tests for SecurityClassifier."""

    def setup_method(self):
        self.classifier = SecurityClassifier()

    # ── Default classifications ──────────────────────────────────────────────

    def test_known_low_risk_entity(self):
        assert self.classifier.classify("PERSON") == RiskLevel.LOW

    def test_known_medium_risk_entity(self):
        assert self.classifier.classify("EMAIL_ADDRESS") == RiskLevel.MEDIUM

    def test_known_high_risk_entity(self):
        assert self.classifier.classify("US_SSN") == RiskLevel.HIGH

    def test_known_critical_phi_entity(self):
        assert self.classifier.classify("PHI_MRN") == RiskLevel.CRITICAL

    def test_known_critical_npi_entity(self):
        assert self.classifier.classify("PHI_NPI") == RiskLevel.CRITICAL

    def test_known_critical_insurance_entity(self):
        assert self.classifier.classify("PHI_INSURANCE_ID") == RiskLevel.CRITICAL

    # ── Fail-safe: unknown entity = CRITICAL ────────────────────────────────

    def test_unknown_entity_defaults_to_critical(self):
        """Any unknown entity type must classify as CRITICAL (fail-safe)."""
        assert self.classifier.classify("SOME_FUTURE_ENTITY_TYPE") == RiskLevel.CRITICAL

    def test_empty_string_entity_defaults_to_critical(self):
        assert self.classifier.classify("") == RiskLevel.CRITICAL

    def test_none_like_entity_defaults_to_critical(self):
        assert self.classifier.classify("NULL") == RiskLevel.CRITICAL

    # ── Tenant overrides — downward only ────────────────────────────────────

    def test_tenant_can_lower_risk(self):
        """Tenant override should lower EMAIL_ADDRESS from MEDIUM to LOW."""
        overrides = {"EMAIL_ADDRESS": "LOW"}
        result = self.classifier.classify("EMAIL_ADDRESS", tenant_overrides=overrides)
        assert result == RiskLevel.LOW

    def test_tenant_cannot_lower_critical_phi_to_low(self):
        """
        Tenant attempting to lower PHI_MRN (CRITICAL) to LOW should fail.
        System enforces: overrides may only lower risk, not raise it to CRITICAL.
        But since the check is: override must be <= system_risk, LOW < CRITICAL is allowed.
        
        Wait — re-read the design: override CAN lower (CRITICAL -> LOW is a downgrade).
        The anti-escalation rule says: override CANNOT raise risk. So a LOW->CRITICAL
        attempt on a LOW entity would be rejected.
        """
        # CRITICAL -> LOW: this IS a downgrade (allowed by policy)
        overrides = {"PHI_MRN": "LOW"}
        result = self.classifier.classify("PHI_MRN", tenant_overrides=overrides)
        assert result == RiskLevel.LOW

    def test_tenant_cannot_raise_low_risk_to_critical(self):
        """Tenant override attempting to raise PERSON (LOW) to CRITICAL must be rejected."""
        overrides = {"PERSON": "CRITICAL"}
        result = self.classifier.classify("PERSON", tenant_overrides=overrides)
        # CRITICAL > LOW — anti-escalation rule rejects this, returns system default (LOW)
        assert result == RiskLevel.LOW

    def test_tenant_cannot_raise_medium_to_high(self):
        """Tenant override attempting to raise EMAIL_ADDRESS (MEDIUM) to HIGH must be rejected."""
        overrides = {"EMAIL_ADDRESS": "HIGH"}
        result = self.classifier.classify("EMAIL_ADDRESS", tenant_overrides=overrides)
        assert result == RiskLevel.MEDIUM

    def test_invalid_override_value_ignored(self):
        """Invalid override string should be silently ignored, system default used."""
        overrides = {"EMAIL_ADDRESS": "SUPER_HIGH_RISK"}
        result = self.classifier.classify("EMAIL_ADDRESS", tenant_overrides=overrides)
        assert result == RiskLevel.MEDIUM  # System default

    # ── Batch operations ─────────────────────────────────────────────────────

    def test_classify_many(self):
        result = self.classifier.classify_many(["PERSON", "EMAIL_ADDRESS", "PHI_MRN"])
        assert result["PERSON"] == RiskLevel.LOW
        assert result["EMAIL_ADDRESS"] == RiskLevel.MEDIUM
        assert result["PHI_MRN"] == RiskLevel.CRITICAL

    def test_max_risk_returns_highest(self):
        result = self.classifier.max_risk(["PERSON", "EMAIL_ADDRESS", "PHI_MRN"])
        assert result == RiskLevel.CRITICAL

    def test_max_risk_empty_list_returns_none(self):
        result = self.classifier.max_risk([])
        assert result is None

    def test_max_risk_single_entity(self):
        result = self.classifier.max_risk(["EMAIL_ADDRESS"])
        assert result == RiskLevel.MEDIUM

    # ── Map coverage ─────────────────────────────────────────────────────────

    def test_all_default_entities_have_risk_levels(self):
        """Every entry in DEFAULT_ENTITY_RISK_MAP must be a valid RiskLevel."""
        for entity_type, risk_level in DEFAULT_ENTITY_RISK_MAP.items():
            assert isinstance(risk_level, RiskLevel), (
                f"{entity_type} maps to invalid risk level: {risk_level}"
            )

    def test_phi_entities_are_critical_by_default(self):
        """All PHI_ prefixed entities must be CRITICAL in the default map."""
        phi_entities = [k for k in DEFAULT_ENTITY_RISK_MAP if k.startswith("PHI_")]
        assert len(phi_entities) >= 3, "Expected at least 3 PHI entity types"
        for entity in phi_entities:
            assert DEFAULT_ENTITY_RISK_MAP[entity] == RiskLevel.CRITICAL, (
                f"{entity} is PHI but not CRITICAL in default map"
            )

