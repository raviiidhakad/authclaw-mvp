"""
AuthClaw Sprint 1 — Custom PHI Recognizers for Microsoft Presidio
-----------------------------------------------------------------
Extends Presidio's default PII recognizers with healthcare-specific
patterns required for HIPAA compliance:

  • MEDICAL_RECORD_NUMBER (MRN)   — labelled as PHI_MRN
  • NATIONAL_PROVIDER_ID  (NPI)   — labelled as PHI_NPI
  • INSURANCE_ID                  — labelled as PHI_INSURANCE_ID

Each recognizer uses Pattern + context-word scoring strategy.
Scores below 0.75 are treated as low-confidence and mapped to MEDIUM risk.
"""
from presidio_analyzer import PatternRecognizer, Pattern


def build_mrn_recognizer() -> PatternRecognizer:
    """
    Medical Record Number (MRN) recognizer.

    Patterns:
      - Preceded by keywords: MRN, Medical Record, Patient ID, Record #
      - Format: 5–15 alphanumeric characters

    False-positive mitigation:
      Context words are required to boost score above the 0.75 threshold.
    """
    patterns = [
        Pattern(
            name="mrn_with_label",
            regex=r"(?i)\b(?:MRN|Medical Record(?:\s+Number)?|Patient(?:\s+ID)?|Record\s*#?)\s*[:\-#]?\s*([A-Z0-9]{5,15})\b",
            score=0.85,
        ),
        Pattern(
            name="mrn_bare",
            regex=r"\b[A-Z]{1,3}\d{6,12}\b",
            score=0.5,  # Low score — requires context boost to act on
        ),
    ]
    return PatternRecognizer(
        supported_entity="PHI_MRN",
        patterns=patterns,
        context=["mrn", "medical record", "patient id", "record number", "chart"],
        name="MRNRecognizer",
    )


def build_npi_recognizer() -> PatternRecognizer:
    """
    National Provider Identifier (NPI) recognizer.

    Format: Exactly 10 digits.
    NPIs are issued by CMS and do not use Luhn checksum; the 10-digit
    fixed-length is the primary signal. Context words are required to
    avoid false-positives with phone numbers and zip codes.
    """
    patterns = [
        Pattern(
            name="npi_with_label",
            regex=r"(?i)\b(?:NPI|Provider(?:\s+ID)?|National\s+Provider)\s*[:\-#]?\s*(\d{10})\b",
            score=0.90,
        ),
        Pattern(
            name="npi_bare",
            regex=r"\b\d{10}\b",
            score=0.4,  # Very low — needs full context-word boost
        ),
    ]
    return PatternRecognizer(
        supported_entity="PHI_NPI",
        patterns=patterns,
        context=["npi", "national provider", "provider id", "cms", "medicare provider"],
        name="NPIRecognizer",
    )


def build_insurance_id_recognizer() -> PatternRecognizer:
    """
    Insurance / Payer Member ID recognizer.

    Common formats:
      - Alphanumeric, 8–20 characters
      - Often preceded by: Member ID, Insurance ID, Policy #, Plan #
    """
    patterns = [
        Pattern(
            name="insurance_id_with_label",
            regex=r"(?i)\b(?:Member\s+ID|Insurance\s+ID|Policy\s*#?|Plan\s*#?|Group\s*#?)\s*[:\-]?\s*([A-Z0-9]{8,20})\b",
            score=0.85,
        ),
    ]
    return PatternRecognizer(
        supported_entity="PHI_INSURANCE_ID",
        patterns=patterns,
        context=["member", "insurance", "policy", "plan", "coverage", "payer", "beneficiary"],
        name="InsuranceIDRecognizer",
    )


def build_phone_recognizer() -> PatternRecognizer:
    """
    Phone number recognizer.

    Presidio's built-in phone recognizer can miss local/demo formats depending
    on runtime context. This deterministic recognizer covers AuthClaw gateway
    policy tests and common North American phone formats.
    """
    patterns = [
        Pattern(
            name="north_american_phone",
            regex=r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
            score=0.90,
        ),
    ]
    return PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=patterns,
        context=["phone", "caller", "mobile", "contact", "support"],
        name="AuthClawPhoneRecognizer",
    )


def build_credential_recognizer() -> PatternRecognizer:
    """
    Credential marker recognizer.

    Catches key-value credential leaks before they are forwarded to a provider,
    including demo/test marker strings such as token=demo-token-redacted.
    """
    patterns = [
        Pattern(
            name="credential_key_value",
            regex=(
                r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
                r"auth(?:orization)?|client[_-]?secret|credential|secret|token)"
                r"\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=@:-]{6,})['\"]?"
            ),
            score=0.92,
        ),
    ]
    return PatternRecognizer(
        supported_entity="CREDENTIAL",
        patterns=patterns,
        context=[
            "api key",
            "token",
            "secret",
            "credential",
            "authorization",
            "client secret",
            "bearer",
        ],
        name="CredentialRecognizer",
    )


def get_all_custom_recognizers() -> list:
    """Return all custom recognizers for registration with Presidio."""
    return [
        build_mrn_recognizer(),
        build_npi_recognizer(),
        build_insurance_id_recognizer(),
        build_phone_recognizer(),
        build_credential_recognizer(),
    ]
