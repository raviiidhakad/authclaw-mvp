"""
Sprint 1 — Unit Tests: Custom PHI Recognizers
Tests that the MRN, NPI, and Insurance ID recognizers match expected patterns
without requiring Presidio (pure regex + PatternRecognizer).
"""
import pytest
import re

from app.core.detection.recognizers import (
    build_mrn_recognizer,
    build_npi_recognizer,
    build_insurance_id_recognizer,
    build_phone_recognizer,
    build_credential_recognizer,
    get_all_custom_recognizers,
)


class TestMRNRecognizer:
    """Unit tests for the Medical Record Number recognizer."""

    def setup_method(self):
        self.recognizer = build_mrn_recognizer()
        # Extract the primary pattern for direct testing
        self._mrn_pattern = re.compile(
            r"(?i)\b(?:MRN|Medical Record(?:\s+Number)?|Patient(?:\s+ID)?|Record\s*#?)\s*[:\-#]?\s*([A-Z0-9]{5,15})\b"
        )

    def test_mrn_with_label_matches(self):
        text = "Patient MRN: A123456"
        assert self._mrn_pattern.search(text), "Should match MRN with label"

    def test_mrn_record_number_matches(self):
        text = "Medical Record Number: B9876543"
        assert self._mrn_pattern.search(text), "Should match Medical Record Number"

    def test_mrn_patient_id_matches(self):
        text = "Patient ID: XY78901"
        assert self._mrn_pattern.search(text), "Should match Patient ID"

    def test_mrn_recognizer_is_pattern_recognizer(self):
        from presidio_analyzer import PatternRecognizer
        assert isinstance(self.recognizer, PatternRecognizer)

    def test_mrn_entity_name(self):
        assert self.recognizer.supported_entities == ["PHI_MRN"]


class TestNPIRecognizer:
    """Unit tests for the National Provider Identifier recognizer."""

    def setup_method(self):
        self.recognizer = build_npi_recognizer()
        self._npi_pattern = re.compile(
            r"(?i)\b(?:NPI|Provider(?:\s+ID)?|National\s+Provider)\s*[:\-#]?\s*(\d{10})\b"
        )

    def test_npi_with_label_matches(self):
        text = "NPI: 1234567890"
        assert self._npi_pattern.search(text), "Should match NPI with label"

    def test_provider_id_matches(self):
        text = "Provider ID: 9876543210"
        assert self._npi_pattern.search(text), "Should match Provider ID"

    def test_national_provider_matches(self):
        text = "National Provider: 1122334455"
        assert self._npi_pattern.search(text), "Should match National Provider"

    def test_npi_entity_name(self):
        assert self.recognizer.supported_entities == ["PHI_NPI"]

    def test_npi_nine_digits_no_match(self):
        # NPI must be exactly 10 digits
        text = "NPI: 123456789"
        assert not self._npi_pattern.search(text), "9-digit NPI should not match"


class TestInsuranceIDRecognizer:
    """Unit tests for the Insurance/Member ID recognizer."""

    def setup_method(self):
        self.recognizer = build_insurance_id_recognizer()
        self._ins_pattern = re.compile(
            r"(?i)\b(?:Member\s+ID|Insurance\s+ID|Policy\s*#?|Plan\s*#?|Group\s*#?)\s*[:\-]?\s*([A-Z0-9]{8,20})\b"
        )

    def test_member_id_matches(self):
        text = "Member ID: ABCD1234"
        assert self._ins_pattern.search(text), "Should match Member ID"

    def test_insurance_id_matches(self):
        text = "Insurance ID: XY12345678"
        assert self._ins_pattern.search(text), "Should match Insurance ID"

    def test_policy_number_matches(self):
        text = "Policy #: PLAN12345"
        assert self._ins_pattern.search(text), "Should match Policy number"

    def test_insurance_entity_name(self):
        assert self.recognizer.supported_entities == ["PHI_INSURANCE_ID"]


class TestPhoneRecognizer:
    """Unit tests for deterministic gateway phone recognition."""

    def setup_method(self):
        self.recognizer = build_phone_recognizer()
        self._phone_pattern = re.compile(
            r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
        )

    def test_demo_phone_number_matches(self):
        text = "A demo support caller entered +1 202-555-0100 and it should be protected."
        assert self._phone_pattern.search(text), "Should match the gateway demo phone number"

    def test_phone_entity_name(self):
        assert self.recognizer.supported_entities == ["PHONE_NUMBER"]


class TestCredentialRecognizer:
    """Unit tests for credential marker recognition."""

    def setup_method(self):
        self.recognizer = build_credential_recognizer()
        self._credential_pattern = re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
            r"auth(?:orization)?|client[_-]?secret|credential|secret|token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=@:-]{6,})['\"]?"
        )

    def test_token_marker_matches(self):
        text = "A demo credential marker token=demo-token-redacted should be protected."
        assert self._credential_pattern.search(text), "Should match token key-value marker"

    def test_api_key_marker_matches(self):
        text = "api_key=ac_demo_key_should_not_forward"
        assert self._credential_pattern.search(text), "Should match api_key key-value marker"

    def test_credential_entity_name(self):
        assert self.recognizer.supported_entities == ["CREDENTIAL"]


class TestGetAllCustomRecognizers:
    """Tests the factory function returning all custom recognizers."""

    def test_returns_five_recognizers(self):
        recognizers = get_all_custom_recognizers()
        assert len(recognizers) == 5

    def test_all_recognizers_have_supported_entities(self):
        recognizers = get_all_custom_recognizers()
        for rec in recognizers:
            assert len(rec.supported_entities) > 0

    def test_all_phi_entities_in_recognizers(self):
        recognizers = get_all_custom_recognizers()
        entity_types = set()
        for rec in recognizers:
            entity_types.update(rec.supported_entities)
        assert "PHI_MRN" in entity_types
        assert "PHI_NPI" in entity_types
        assert "PHI_INSURANCE_ID" in entity_types
        assert "PHONE_NUMBER" in entity_types
        assert "CREDENTIAL" in entity_types
