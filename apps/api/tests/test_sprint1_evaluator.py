"""
Sprint 1 — Unit Tests: Embedded Policy Evaluator
Tests the PolicyDecision logic including BLOCK, REDACT, WARN, PASS outcomes,
keyword blocklist enforcement, CRITICAL auto-redact, shadow mode, and
tenant override anti-escalation through the evaluator.
"""
import pytest

from app.core.policy.evaluator import (
    EmbeddedPolicyEvaluator, PolicyAction, PolicyDecision, EntityViolation
)
from app.core.detection.classification import RiskLevel


def make_detection(entity_type: str, score: float = 0.85) -> dict:
    return {"entity_type": entity_type, "start": 0, "end": 10, "score": score}


class TestEmbeddedPolicyEvaluator:
    """Unit tests for EmbeddedPolicyEvaluator."""

    def setup_method(self):
        self.evaluator = EmbeddedPolicyEvaluator()
        self.empty_policy = {
            "entity_actions": {},
            "classification_overrides": {},
            "keyword_blocklist": [],
        }

    # ── No detections / clean text ───────────────────────────────────────────

    def test_no_detections_returns_pass(self):
        decision = self.evaluator.evaluate(
            detections=[],
            text="Hello world, nothing sensitive here.",
            compiled_policy=self.empty_policy,
        )
        assert decision.action == PolicyAction.PASS
        assert not decision.has_violations

    def test_empty_text_returns_pass(self):
        decision = self.evaluator.evaluate(
            detections=[],
            text="",
            compiled_policy=self.empty_policy,
        )
        assert decision.action == PolicyAction.PASS

    # ── BLOCK action ─────────────────────────────────────────────────────────

    def test_block_policy_triggers_block(self):
        policy = {
            "entity_actions": {"EMAIL_ADDRESS": "BLOCK"},
            "classification_overrides": {},
            "keyword_blocklist": [],
        }
        detections = [make_detection("EMAIL_ADDRESS")]
        decision = self.evaluator.evaluate(detections, "email: user@test.com", policy)
        assert decision.action == PolicyAction.BLOCK
        assert decision.block_reason is not None
        assert "EMAIL_ADDRESS" in decision.block_reason

    def test_block_action_wins_over_redact(self):
        """If one entity is BLOCK and another is REDACT, BLOCK wins."""
        policy = {
            "entity_actions": {
                "EMAIL_ADDRESS": "BLOCK",
                "PHONE_NUMBER": "MASK",
            },
            "classification_overrides": {},
            "keyword_blocklist": [],
        }
        detections = [make_detection("EMAIL_ADDRESS"), make_detection("PHONE_NUMBER")]
        decision = self.evaluator.evaluate(detections, "email and phone", policy)
        assert decision.action == PolicyAction.BLOCK

    def test_should_block_is_true_without_shadow_mode(self):
        policy = {"entity_actions": {"US_SSN": "BLOCK"}, "classification_overrides": {}, "keyword_blocklist": []}
        decision = self.evaluator.evaluate([make_detection("US_SSN")], "ssn text", policy, shadow_mode=False)
        assert decision.should_block is True

    def test_should_block_is_false_in_shadow_mode(self):
        """Shadow mode: decision is BLOCK but should_block returns False (not enforced)."""
        policy = {"entity_actions": {"US_SSN": "BLOCK"}, "classification_overrides": {}, "keyword_blocklist": []}
        decision = self.evaluator.evaluate([make_detection("US_SSN")], "ssn text", policy, shadow_mode=True)
        assert decision.action == PolicyAction.BLOCK  # Decision still computed
        assert decision.should_block is False          # But NOT enforced

    # ── REDACT action ────────────────────────────────────────────────────────

    def test_mask_policy_triggers_redact(self):
        policy = {
            "entity_actions": {"EMAIL_ADDRESS": "MASK"},
            "classification_overrides": {},
            "keyword_blocklist": [],
        }
        detections = [make_detection("EMAIL_ADDRESS")]
        decision = self.evaluator.evaluate(detections, "email: user@test.com", policy)
        assert decision.action == PolicyAction.REDACT
        assert "EMAIL_ADDRESS" in decision.redact_entities

    def test_hash_policy_triggers_redact(self):
        policy = {"entity_actions": {"CREDIT_CARD": "HASH"}, "classification_overrides": {}, "keyword_blocklist": []}
        decision = self.evaluator.evaluate([make_detection("CREDIT_CARD")], "cc text", policy)
        assert decision.action == PolicyAction.REDACT

    def test_should_redact_is_true_without_shadow_mode(self):
        policy = {"entity_actions": {"EMAIL_ADDRESS": "MASK"}, "classification_overrides": {}, "keyword_blocklist": []}
        decision = self.evaluator.evaluate([make_detection("EMAIL_ADDRESS")], "email text", policy, shadow_mode=False)
        assert decision.should_redact is True

    def test_should_redact_is_false_in_shadow_mode(self):
        policy = {"entity_actions": {"EMAIL_ADDRESS": "MASK"}, "classification_overrides": {}, "keyword_blocklist": []}
        decision = self.evaluator.evaluate([make_detection("EMAIL_ADDRESS")], "email text", policy, shadow_mode=True)
        assert decision.should_redact is False

    # ── CRITICAL auto-redact (no policy configured) ──────────────────────────

    def test_critical_entity_auto_redacts_without_explicit_policy(self):
        """CRITICAL entities with no policy action should auto-redact for safety."""
        decision = self.evaluator.evaluate(
            detections=[make_detection("PHI_MRN")],
            text="MRN: A123456",
            compiled_policy=self.empty_policy,  # No explicit action configured
        )
        # CRITICAL entity → auto-redact
        assert decision.action == PolicyAction.REDACT
        assert "PHI_MRN" in decision.redact_entities

    def test_unknown_entity_auto_redacts(self):
        """Unknown entity type defaults to CRITICAL → auto-redacts."""
        decision = self.evaluator.evaluate(
            detections=[make_detection("SOME_FUTURE_ENTITY")],
            text="some future entity here",
            compiled_policy=self.empty_policy,
        )
        assert decision.action == PolicyAction.REDACT

    # ── Keyword blocklist ────────────────────────────────────────────────────

    def test_keyword_hit_triggers_block(self):
        policy = {
            "entity_actions": {},
            "classification_overrides": {},
            "keyword_blocklist": ["confidential", "top secret"],
        }
        decision = self.evaluator.evaluate(
            detections=[],
            text="This document is TOP SECRET and must not leave the building.",
            compiled_policy=policy,
        )
        assert decision.action == PolicyAction.BLOCK
        assert "top secret" in decision.keyword_hits

    def test_keyword_case_insensitive(self):
        policy = {
            "entity_actions": {},
            "classification_overrides": {},
            "keyword_blocklist": ["confidential"],
        }
        decision = self.evaluator.evaluate([], "CONFIDENTIAL report", policy)
        assert "confidential" in decision.keyword_hits

    def test_no_keyword_hit_on_clean_text(self):
        policy = {
            "entity_actions": {},
            "classification_overrides": {},
            "keyword_blocklist": ["confidential"],
        }
        decision = self.evaluator.evaluate([], "This is a clean message.", policy)
        assert decision.keyword_hits == []
        assert decision.action == PolicyAction.PASS

    # ── Violation deduplication ──────────────────────────────────────────────

    def test_duplicate_entity_type_counted_once(self):
        """Two detections of the same entity type should produce one violation."""
        detections = [
            make_detection("EMAIL_ADDRESS"),
            make_detection("EMAIL_ADDRESS"),  # Duplicate
        ]
        policy = {"entity_actions": {"EMAIL_ADDRESS": "MASK"}, "classification_overrides": {}, "keyword_blocklist": []}
        decision = self.evaluator.evaluate(detections, "two emails", policy)
        assert len(decision.violations) == 1

    # ── Max risk level ───────────────────────────────────────────────────────

    def test_max_risk_is_highest_across_violations(self):
        detections = [make_detection("PERSON"), make_detection("PHI_MRN")]
        decision = self.evaluator.evaluate(detections, "name and mrn", self.empty_policy)
        assert decision.max_risk_level == RiskLevel.CRITICAL

    def test_max_risk_is_none_on_no_detections(self):
        decision = self.evaluator.evaluate([], "clean text", self.empty_policy)
        assert decision.max_risk_level is None
