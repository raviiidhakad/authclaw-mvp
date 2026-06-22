"""
AuthClaw Sprint 1 — Embedded Policy Evaluator
-----------------------------------------------
Evaluates the compiled tenant policy (from Redis cache) against a
set of detected entities. This is the enforcement layer that sits
between Presidio detection and the gateway action (BLOCK / REDACT / PASS).

Key design:
  • NO DB calls on the hot path — uses the compiled policy dict from PolicyCache.
  • Produces a typed PolicyDecision result that the gateway acts on immediately.
  • Keyword blocklist evaluation runs as a fast substring pass (O(n*k) where
    k = number of keywords, typically < 20).
  • The evaluator is a pure function — it holds no state, is fully testable,
    and adds zero latency to the gateway when the pipeline is healthy.

Decision priority (highest to lowest):
  1. BLOCK  — any entity with entity_actions["ENTITY_TYPE"] == "BLOCK"
  2. REDACT — any entity with entity_actions["ENTITY_TYPE"] in ("MASK", "HASH", "REPLACE", "SYNTHETIC")
  3. WARN   — detection without a configured action (logged only)
  4. PASS   — no detections; no keyword hits
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from app.core.detection.classification import RiskLevel, classifier


class PolicyAction(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass
class EntityViolation:
    """A single entity that triggered a policy decision."""
    entity_type: str
    action: PolicyAction
    risk_level: RiskLevel
    score: float = 1.0


@dataclass
class PolicyDecision:
    """
    The result of evaluating detected entities against the compiled tenant policy.

    Attributes:
        action:           The highest-priority action across all violations.
        violations:       List of individual entity violations.
        keyword_hits:     Keywords from the blocklist found in the text.
        max_risk_level:   Highest risk level across all detected entities.
        redact_entities:  Entity types that should be redacted (action=REDACT).
        block_reason:     Human-readable reason for BLOCK action.
        shadow_mode:      If True, decision was computed but not enforced.
    """
    action: PolicyAction = PolicyAction.PASS
    violations: List[EntityViolation] = field(default_factory=list)
    keyword_hits: List[str] = field(default_factory=list)
    max_risk_level: Optional[RiskLevel] = None
    redact_entities: List[str] = field(default_factory=list)
    block_reason: Optional[str] = None
    shadow_mode: bool = False

    @property
    def should_block(self) -> bool:
        return self.action == PolicyAction.BLOCK and not self.shadow_mode

    @property
    def should_redact(self) -> bool:
        return self.action in (PolicyAction.REDACT, PolicyAction.WARN) and not self.shadow_mode

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0 or len(self.keyword_hits) > 0


class EmbeddedPolicyEvaluator:
    """
    Stateless evaluator that applies the compiled tenant policy against
    detected PII/PHI entities.

    Usage:
        evaluator = EmbeddedPolicyEvaluator()
        decision = evaluator.evaluate(
            detections=scan_result.detections,
            text=full_prompt,
            compiled_policy=policy_cache.get(tenant_id, db),
            shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
        )
        if decision.should_block:
            return 403
        if decision.should_redact:
            text = scan_result.sanitized_text
    """

    # Redaction action keywords — any of these means REDACT, not BLOCK
    _REDACT_ACTIONS = {"MASK", "HASH", "REPLACE", "SYNTHETIC", "REDACT"}

    def evaluate(
        self,
        detections: List[Dict[str, Any]],
        text: str,
        compiled_policy: Dict[str, Any],
        shadow_mode: bool = False,
    ) -> PolicyDecision:
        """
        Evaluate detected entities against the compiled policy.

        Args:
            detections:      List of dicts from PresidioEngine.scan() (entity_type, start, end, score).
            text:            The original (pre-redaction) text for keyword scanning.
            compiled_policy: The compiled policy dict from PolicyCache.get().
            shadow_mode:     If True, compute decision but mark as shadow — gateway does not enforce.

        Returns:
            PolicyDecision with the final action and all violation details.
        """
        entity_actions: Dict[str, str] = compiled_policy.get("entity_actions", {})
        classification_overrides: Dict[str, str] = compiled_policy.get("classification_overrides", {})
        keyword_blocklist: List[str] = compiled_policy.get("keyword_blocklist", [])

        violations: List[EntityViolation] = []
        redact_entities: List[str] = []
        highest_action = PolicyAction.PASS
        block_reason: Optional[str] = None

        # ── 1. Evaluate each detected entity ────────────────────────────────
        seen_entity_types = set()
        for detection in detections:
            entity_type = detection.get("entity_type", "UNKNOWN")
            score = detection.get("score", 1.0)

            if entity_type in seen_entity_types:
                continue  # Deduplicate — one violation per entity type per request
            seen_entity_types.add(entity_type)

            # Get configured action for this entity type
            configured_action_str = entity_actions.get(entity_type, "").upper()
            risk_level = classifier.classify(entity_type, classification_overrides)

            if configured_action_str == "BLOCK":
                action = PolicyAction.BLOCK
                block_reason = (
                    f"Entity type '{entity_type}' (risk={risk_level.value}) "
                    f"is blocked by tenant policy."
                )
                highest_action = PolicyAction.BLOCK

            elif configured_action_str in self._REDACT_ACTIONS:
                action = PolicyAction.REDACT
                redact_entities.append(entity_type)
                if highest_action == PolicyAction.PASS:
                    highest_action = PolicyAction.REDACT

            else:
                # No explicit policy action — classify by risk level and WARN
                action = PolicyAction.WARN
                if risk_level == RiskLevel.CRITICAL:
                    # Critical entities with no policy action → auto-redact for safety
                    action = PolicyAction.REDACT
                    redact_entities.append(entity_type)
                    if highest_action == PolicyAction.PASS:
                        highest_action = PolicyAction.REDACT
                elif highest_action == PolicyAction.PASS:
                    highest_action = PolicyAction.WARN

            violations.append(EntityViolation(
                entity_type=entity_type,
                action=action,
                risk_level=risk_level,
                score=score,
            ))

        # ── 2. Keyword blocklist evaluation ─────────────────────────────────
        keyword_hits: List[str] = []
        if keyword_blocklist and text:
            lower_text = text.lower()
            for keyword in keyword_blocklist:
                if keyword.lower() in lower_text:
                    keyword_hits.append(keyword)

        # Keywords always trigger BLOCK (highest priority override)
        if keyword_hits:
            highest_action = PolicyAction.BLOCK
            block_reason = (
                f"Keyword blocklist hit: {keyword_hits}. Request blocked by tenant policy."
            )

        # ── 3. Compute max risk level ─────────────────────────────────────
        max_risk = None
        if violations:
            max_risk = max(
                (v.risk_level for v in violations),
                key=lambda r: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(r.value),
            )

        return PolicyDecision(
            action=highest_action,
            violations=violations,
            keyword_hits=keyword_hits,
            max_risk_level=max_risk,
            redact_entities=list(set(redact_entities)),
            block_reason=block_reason,
            shadow_mode=shadow_mode,
        )


# Module-level singleton
evaluator = EmbeddedPolicyEvaluator()
