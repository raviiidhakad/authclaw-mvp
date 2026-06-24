import pytest
from app.models.policy import Policy, PolicyRule, RuleType, PolicyAction
from app.core.engine.pii import PIIDetector, PIIRedactor, PIIFinding
from app.core.engine.evaluator import PolicyEngine, EvaluationResult

def test_pii_detector():
    detector = PIIDetector()
    text = "Contact me at user@example.com or 555-987-6543 or visit 1600 Amphitheatre Parkway."
    findings = detector.detect(text)
    
    assert len(findings) == 3
    assert findings[0].pii_type == "EMAIL"
    assert findings[0].value == "user@example.com"
    assert findings[1].pii_type == "PHONE"
    assert findings[1].value == "555-987-6543"
    assert findings[2].pii_type == "ADDRESS"
    assert findings[2].value == "1600 Amphitheatre Parkway"


def test_pii_redactor():
    text = "My SSN is 123-45-6789!"
    findings = [PIIFinding("SSN", "123-45-6789", 10, 21)]
    redacted = PIIRedactor.redact(text, findings)
    assert redacted == "My SSN is [SSN]!"

def test_pii_synthetic_replacement():
    text = "Email me at bob@test.com"
    findings = [PIIFinding("EMAIL", "bob@test.com", 12, 24)]
    synthetic = PIIRedactor.synthesize(text, findings)
    assert synthetic == "Email me at synthetic-email-1@example.test"
    assert "bob@test.com" not in synthetic

def test_policy_engine_allow():
    engine = PolicyEngine()
    policy = Policy(is_active=True, priority=1, rules=[])
    result = engine.evaluate("Hello world", [policy])
    
    assert result.allowed is True
    assert result.action_taken == "allow"
    assert result.modified_prompt == "Hello world"

def test_policy_engine_pii_redact():
    engine = PolicyEngine()
    rule = PolicyRule(
        is_active=True, 
        rule_type=RuleType.pii_redact, 
        action=PolicyAction.allow, # redact doesn't block
        conditions={"pii_types": ["EMAIL"]}
    )
    policy = Policy(id="test-id", is_active=True, priority=1, rules=[rule])
    
    result = engine.evaluate("Email me at bob@test.com", [policy])
    
    assert result.allowed is True
    assert result.action_taken == "warn" # warning because there was a violation
    assert result.modified_prompt == "Email me at [EMAIL]"
    assert len(result.violations) == 1
    assert result.violations[0].rule_type == RuleType.pii_redact

def test_policy_engine_pii_synthetic():
    engine = PolicyEngine()
    rule = PolicyRule(
        is_active=True,
        rule_type=RuleType.pii_synthetic,
        action=PolicyAction.allow,
        conditions={"pii_types": ["EMAIL"]}
    )
    policy = Policy(id="test-id", is_active=True, priority=1, rules=[rule])

    result = engine.evaluate("Email me at bob@test.com", [policy])

    assert result.allowed is True
    assert result.action_taken == "warn"
    assert result.modified_prompt == "Email me at synthetic-email-1@example.test"
    assert "bob@test.com" not in result.modified_prompt
    assert len(result.violations) == 1
    assert result.violations[0].rule_type == RuleType.pii_synthetic

def test_policy_engine_content_filter_block():
    engine = PolicyEngine()
    rule = PolicyRule(
        is_active=True, 
        rule_type=RuleType.content_filter, 
        action=PolicyAction.block,
        conditions={"keywords": ["secret", "confidential"]}
    )
    policy = Policy(id="test-id", is_active=True, priority=1, rules=[rule])
    
    result = engine.evaluate("This is a highly CONFIDENTIAL document.", [policy])
    
    assert result.allowed is False
    assert result.action_taken == "block"
    assert len(result.violations) == 1
    assert "confidential" in result.violations[0].context["keywords"]

def test_policy_engine_model_restrict():
    engine = PolicyEngine()
    rule = PolicyRule(
        is_active=True, 
        rule_type=RuleType.model_restrict, 
        action=PolicyAction.block,
        conditions={"allowed_models": ["gpt-4", "gpt-3.5-turbo"]}
    )
    policy = Policy(id="test-id", is_active=True, priority=1, rules=[rule])
    
    result = engine.evaluate("Hello", [policy], target_model="claude-3-opus")
    
    assert result.allowed is False
    assert result.action_taken == "block"
    assert len(result.violations) == 1
