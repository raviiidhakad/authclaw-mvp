from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.models.policy import Policy, PolicyRule, RuleType, PolicyAction
from app.core.engine.pii import PIIDetector, PIIRedactor, PIIFinding

@dataclass
class RuleViolation:
    policy_id: str
    rule_id: str
    rule_type: str
    action: str
    message: str
    context: Dict[str, Any]

@dataclass
class EvaluationResult:
    allowed: bool
    modified_prompt: str
    violations: List[RuleViolation] = field(default_factory=list)
    action_taken: str = "allow" # allow, warn, block

class PolicyEngine:
    """Evaluates prompts against a tenant's active policies."""

    def __init__(self):
        self.pii_detector = PIIDetector()
        self.pii_redactor = PIIRedactor()

    def evaluate(self, prompt: str, policies: List[Policy], target_model: str = "") -> EvaluationResult:
        result = EvaluationResult(
            allowed=True,
            modified_prompt=prompt,
            violations=[],
            action_taken="allow"
        )

        current_prompt = prompt
        
        # Sort policies by priority descending
        sorted_policies = sorted(policies, key=lambda p: p.priority, reverse=True)

        for policy in sorted_policies:
            if not policy.is_active:
                continue

            for rule in policy.rules:
                if not rule.is_active:
                    continue

                if rule.rule_type == RuleType.pii_block:
                    self._evaluate_pii_block(policy, rule, current_prompt, result)
                elif rule.rule_type == RuleType.pii_redact:
                    current_prompt = self._evaluate_pii_redact(policy, rule, current_prompt, result)
                elif rule.rule_type == RuleType.content_filter:
                    self._evaluate_content_filter(policy, rule, current_prompt, result)
                elif rule.rule_type == RuleType.model_restrict:
                    self._evaluate_model_restrict(policy, rule, target_model, result)

                # If a block action was triggered, we can halt evaluation
                if result.action_taken == "block":
                    result.allowed = False
                    return result

        result.modified_prompt = current_prompt
        if result.violations and result.action_taken != "block":
            result.action_taken = "warn" # If there are violations but not blocked, it's a warn

        return result

    def _evaluate_pii_block(self, policy: Policy, rule: PolicyRule, prompt: str, result: EvaluationResult):
        pii_types = rule.conditions.get("pii_types", [])
        findings = self.pii_detector.detect(prompt, pii_types)
        
        if findings:
            result.violations.append(RuleViolation(
                policy_id=str(policy.id),
                rule_id=str(rule.id),
                rule_type=rule.rule_type,
                action=rule.action,
                message=rule.message or "PII blocked by policy.",
                context={"findings": [f.pii_type for f in findings]}
            ))
            if rule.action == PolicyAction.block:
                result.action_taken = "block"

    def _evaluate_pii_redact(self, policy: Policy, rule: PolicyRule, prompt: str, result: EvaluationResult) -> str:
        pii_types = rule.conditions.get("pii_types", [])
        findings = self.pii_detector.detect(prompt, pii_types)
        
        if findings:
            result.violations.append(RuleViolation(
                policy_id=str(policy.id),
                rule_id=str(rule.id),
                rule_type=rule.rule_type,
                action=rule.action,
                message=rule.message or "PII redacted by policy.",
                context={"findings": [f.pii_type for f in findings], "redacted_count": len(findings)}
            ))
            return self.pii_redactor.redact(prompt, findings)
            
        return prompt

    def _evaluate_content_filter(self, policy: Policy, rule: PolicyRule, prompt: str, result: EvaluationResult):
        # MVP: simple exact keyword match
        blocked_keywords = rule.conditions.get("keywords", rule.conditions.get("blocked_terms", []))
        lower_prompt = prompt.lower()
        
        found_keywords = [kw for kw in blocked_keywords if kw.lower() in lower_prompt]
        
        if found_keywords:
            result.violations.append(RuleViolation(
                policy_id=str(policy.id),
                rule_id=str(rule.id),
                rule_type=rule.rule_type,
                action=rule.action,
                message=rule.message or "Content blocked by keyword filter.",
                context={"keywords": found_keywords}
            ))
            if rule.action == PolicyAction.block:
                result.action_taken = "block"

    def _evaluate_model_restrict(self, policy: Policy, rule: PolicyRule, target_model: str, result: EvaluationResult):
        allowed_models = rule.conditions.get("allowed_models", [])
        blocked_models = rule.conditions.get("blocked_models", [])

        if not target_model:
            return

        is_blocked = False
        if allowed_models and target_model not in allowed_models:
            is_blocked = True
        if blocked_models and target_model in blocked_models:
            is_blocked = True

        if is_blocked:
            result.violations.append(RuleViolation(
                policy_id=str(policy.id),
                rule_id=str(rule.id),
                rule_type=rule.rule_type,
                action=rule.action,
                message=rule.message or f"Model '{target_model}' is restricted.",
                context={"attempted_model": target_model}
            ))
            if rule.action == PolicyAction.block:
                result.action_taken = "block"

