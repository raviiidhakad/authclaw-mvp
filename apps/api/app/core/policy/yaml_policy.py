from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import yaml

from app.core.engine.evaluator import PolicyEngine
from app.models.policy import Policy, PolicyAction, PolicyRule, RuleType
from app.services.api_safety import sanitize_text

SUPPORTED_SCHEMA_VERSIONS = {"authclaw.policy/v1", "v1"}
SUPPORTED_RULE_TYPES = {item.value for item in RuleType}
SUPPORTED_ACTIONS = {item.value for item in PolicyAction}
SUPPORTED_REDACTION_MODES = {"MASK", "HASH", "SYNTHETIC"}
SUPPORTED_POLICY_KEYS = {"version", "schema_version", "name", "description", "enabled", "is_active", "priority", "rules"}
SUPPORTED_RULE_KEYS = {"type", "rule_type", "action", "message", "enabled", "is_active", "conditions"}
UNSAFE_DISABLE_KEYS = {
    "disable_security",
    "disable_security_pipeline",
    "disable_redaction",
    "disable_pii_scan",
    "passthrough",
}


@dataclass
class PolicyValidationIssue:
    code: str
    message: str
    path: str = "$"

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": sanitize_text(self.message),
            "path": self.path,
        }


@dataclass
class PolicyValidationResult:
    valid: bool
    schema_version: str | None
    normalized: dict[str, Any] | None
    errors: list[PolicyValidationIssue]
    warnings: list[PolicyValidationIssue]
    opa_adapter: str = "python_policy_adapter"

    def as_response(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "schema_version": self.schema_version,
            "normalized": self.normalized if self.valid else None,
            "errors": [issue.as_dict() for issue in self.errors],
            "warnings": [issue.as_dict() for issue in self.warnings],
            "opa": {
                "runtime": "adapter_seam",
                "adapter": self.opa_adapter,
                "full_opa_runtime": False,
            },
        }


class OpaRuntimeMode(str, Enum):
    """Future runtime failure policy. Selection is intentionally not implemented in T1."""

    STRICT = "STRICT"
    COMPATIBILITY = "COMPATIBILITY"


class OpaRuntimeKind(str, Enum):
    """Supported adapter families behind the OPA policy contract."""

    PYTHON = "python"
    NATIVE_OPA = "native_opa"
    EMBEDDED_OPA = "embedded_opa"
    WASM = "wasm"


@dataclass(frozen=True)
class OpaEvaluationContext:
    """Optional runtime context for future OPA engines.

    YAML remains the source of truth; this context carries request metadata only.
    Existing callers may omit it and retain the legacy behavior.
    """

    tenant_id: uuid.UUID | None = None
    route_id: uuid.UUID | None = None
    policy_id: uuid.UUID | None = None
    target_model: str = ""
    direction: str = "INBOUND"
    runtime_mode: OpaRuntimeMode = OpaRuntimeMode.STRICT
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpaEvaluationDecision:
    """Stable decision shape returned by adapter implementations.

    Existing public policy-test responses still receive the dict form produced by
    ``as_dict`` so API payloads remain unchanged.
    """

    allowed: bool
    action: str
    matched_rules: list[dict[str, Any]] = field(default_factory=list)
    redaction_required: bool = False
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "matched_rules": self.matched_rules,
            "redaction_required": self.redaction_required,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OpaAdapterCapabilities:
    """Static adapter capabilities for future strict/compatibility runtime wiring."""

    runtime_kind: OpaRuntimeKind
    supports_strict_mode: bool
    supports_compatibility_mode: bool
    full_opa_runtime: bool = False


class OpaPolicyAdapter(ABC):
    """Single policy-runtime integration contract.

    Implementations may be the current Python compatibility adapter, native OPA,
    embedded OPA, or WASM. YAML remains the source of truth and is passed as a
    normalized configuration document; adapters evaluate that configuration and
    request metadata without requiring gateway/API changes.
    """

    name = "base"
    capabilities = OpaAdapterCapabilities(
        runtime_kind=OpaRuntimeKind.PYTHON,
        supports_strict_mode=False,
        supports_compatibility_mode=False,
        full_opa_runtime=False,
    )

    @abstractmethod
    def validate(self, normalized_policy: dict[str, Any]) -> list[PolicyValidationIssue]:
        raise NotImplementedError

    @abstractmethod
    def evaluate(
        self,
        text: str,
        normalized_policy: dict[str, Any],
        context: OpaEvaluationContext | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError


class PythonPolicyAdapter(OpaPolicyAdapter):
    """Default Python-backed adapter that mirrors the existing runtime evaluator."""

    name = "python_policy_adapter"
    capabilities = OpaAdapterCapabilities(
        runtime_kind=OpaRuntimeKind.PYTHON,
        supports_strict_mode=True,
        supports_compatibility_mode=True,
        full_opa_runtime=False,
    )

    def validate(self, normalized_policy: dict[str, Any]) -> list[PolicyValidationIssue]:
        issues: list[PolicyValidationIssue] = []
        if normalized_policy.get("enabled") and not normalized_policy.get("rules"):
            issues.append(
                PolicyValidationIssue(
                    code="unsafe_allow_all",
                    message="Enabled policies must include at least one enforceable rule.",
                    path="$.rules",
                )
            )
        if normalized_policy.get("enabled") and normalized_policy.get("rules"):
            actions = {str(rule.get("action", "")).lower() for rule in normalized_policy.get("rules", [])}
            if actions == {"allow"}:
                issues.append(
                    PolicyValidationIssue(
                        code="unsafe_allow_all",
                        message="Enabled policies cannot consist only of allow rules.",
                        path="$.rules",
                    )
                )
        return issues

    def evaluate(
        self,
        text: str,
        normalized_policy: dict[str, Any],
        context: OpaEvaluationContext | None = None,
    ) -> dict[str, Any]:
        policy = policy_from_normalized(normalized_policy, tenant_id=uuid.uuid4())
        result = PolicyEngine().evaluate(text, [policy], target_model=context.target_model if context else "")
        decision = OpaEvaluationDecision(
            allowed=result.allowed,
            action=result.action_taken,
            matched_rules=[
                {
                    "rule_type": violation.rule_type,
                    "action": violation.action.value if hasattr(violation.action, "value") else str(violation.action),
                    "message": sanitize_text(violation.message),
                }
                for violation in result.violations
            ],
            redaction_required=result.modified_prompt != text,
            reason="Policy matched sample text." if result.violations else "No policy rule matched sample text.",
        )
        return decision.as_dict()


def _safe_load_yaml(source: str) -> tuple[dict[str, Any] | None, list[PolicyValidationIssue]]:
    try:
        loaded = yaml.safe_load(source)
    except yaml.YAMLError:
        return None, [
            PolicyValidationIssue(
                code="malformed_yaml",
                message="YAML could not be parsed.",
            )
        ]
    if not isinstance(loaded, dict):
        return None, [
            PolicyValidationIssue(
                code="invalid_document",
                message="Policy YAML must be a mapping object.",
            )
        ]
    return loaded, []


def _contains_unsafe_disable_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in UNSAFE_DISABLE_KEYS:
                return True
            if _contains_unsafe_disable_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_unsafe_disable_key(item) for item in value)
    return False


def _validate_regex_patterns(rule: dict[str, Any], index: int) -> list[PolicyValidationIssue]:
    issues: list[PolicyValidationIssue] = []
    conditions = rule.get("conditions") or {}
    for key in ("regex", "regexes", "regex_patterns", "patterns"):
        patterns = conditions.get(key)
        if patterns is None:
            continue
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list):
            issues.append(
                PolicyValidationIssue(
                    code="invalid_regex_list",
                    message="Regex patterns must be a string or list of strings.",
                    path=f"$.rules[{index}].conditions.{key}",
                )
            )
            continue
        for pattern_index, pattern in enumerate(patterns):
            if not isinstance(pattern, str):
                issues.append(
                    PolicyValidationIssue(
                        code="invalid_regex",
                        message="Regex pattern must be a string.",
                        path=f"$.rules[{index}].conditions.{key}[{pattern_index}]",
                    )
                )
                continue
            try:
                re.compile(pattern)
            except re.error:
                issues.append(
                    PolicyValidationIssue(
                        code="invalid_regex",
                        message="Regex pattern is invalid.",
                        path=f"$.rules[{index}].conditions.{key}[{pattern_index}]",
                    )
                )
    return issues


def validate_policy_yaml(source: str, adapter: OpaPolicyAdapter | None = None) -> PolicyValidationResult:
    adapter = adapter or PythonPolicyAdapter()
    loaded, parse_errors = _safe_load_yaml(source)
    if parse_errors:
        return PolicyValidationResult(False, None, None, parse_errors, [], adapter.name)

    assert loaded is not None
    errors: list[PolicyValidationIssue] = []
    warnings: list[PolicyValidationIssue] = []

    for key in sorted(set(loaded) - SUPPORTED_POLICY_KEYS):
        errors.append(PolicyValidationIssue("unsupported_field", "Unsupported policy field.", f"$.{key}"))

    schema_version = str(loaded.get("version") or loaded.get("schema_version") or "")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(
            PolicyValidationIssue(
                code="unsupported_schema_version",
                message="Unsupported policy schema version.",
                path="$.version",
            )
        )

    name = loaded.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append(PolicyValidationIssue("missing_name", "Policy name is required.", "$.name"))

    enabled = loaded.get("enabled", loaded.get("is_active", True))
    if not isinstance(enabled, bool):
        errors.append(PolicyValidationIssue("invalid_enabled", "Policy enabled must be boolean.", "$.enabled"))

    priority = loaded.get("priority", 0)
    if not isinstance(priority, int) or priority < 0:
        errors.append(PolicyValidationIssue("invalid_priority", "Policy priority must be a non-negative integer.", "$.priority"))

    if _contains_unsafe_disable_key(loaded):
        errors.append(
            PolicyValidationIssue(
                code="security_disable_forbidden",
                message="Policies cannot disable redaction, scanning, or the security pipeline.",
            )
        )

    raw_rules = loaded.get("rules")
    if not isinstance(raw_rules, list):
        errors.append(PolicyValidationIssue("missing_rules", "Policy rules must be a list.", "$.rules"))
        raw_rules = []

    normalized_rules: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            errors.append(PolicyValidationIssue("invalid_rule", "Policy rule must be an object.", f"$.rules[{index}]"))
            continue
        for key in sorted(set(raw_rule) - SUPPORTED_RULE_KEYS):
            errors.append(PolicyValidationIssue("unsupported_field", "Unsupported policy rule field.", f"$.rules[{index}].{key}"))
        rule_type = str(raw_rule.get("type") or raw_rule.get("rule_type") or "")
        action = str(raw_rule.get("action") or "")
        conditions = raw_rule.get("conditions") or {}
        if rule_type not in SUPPORTED_RULE_TYPES:
            errors.append(PolicyValidationIssue("unsupported_rule_type", "Unsupported policy rule type.", f"$.rules[{index}].type"))
        if action not in SUPPORTED_ACTIONS:
            errors.append(PolicyValidationIssue("unsupported_action", "Unsupported policy action.", f"$.rules[{index}].action"))
        if not isinstance(conditions, dict):
            errors.append(PolicyValidationIssue("invalid_conditions", "Rule conditions must be an object.", f"$.rules[{index}].conditions"))
            conditions = {}
        if rule_type in {"pii_redact", "pii_synthetic"}:
            mode = str(conditions.get("redaction_mode", "SYNTHETIC" if rule_type == "pii_synthetic" else "MASK")).upper()
            if mode not in SUPPORTED_REDACTION_MODES:
                errors.append(PolicyValidationIssue("unsupported_redaction_mode", "Unsupported redaction mode.", f"$.rules[{index}].conditions.redaction_mode"))
            conditions["redaction_mode"] = mode
        errors.extend(_validate_regex_patterns(raw_rule, index))
        normalized_rules.append(
            {
                "type": rule_type,
                "action": action,
                "message": sanitize_text(raw_rule.get("message")) if raw_rule.get("message") else None,
                "enabled": bool(raw_rule.get("enabled", raw_rule.get("is_active", True))),
                "conditions": conditions,
            }
        )

    normalized = {
        "version": "authclaw.policy/v1",
        "name": sanitize_text(str(name or "")),
        "description": sanitize_text(loaded.get("description")) if loaded.get("description") else None,
        "enabled": bool(enabled) if isinstance(enabled, bool) else True,
        "priority": priority if isinstance(priority, int) and priority >= 0 else 0,
        "rules": normalized_rules,
    }

    errors.extend(adapter.validate(normalized))
    return PolicyValidationResult(not errors, normalized["version"], normalized, errors, warnings, adapter.name)


def policy_from_normalized(normalized: dict[str, Any], tenant_id: uuid.UUID) -> Policy:
    policy = Policy(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name=normalized["name"],
        description=normalized.get("description"),
        is_active=bool(normalized.get("enabled", True)),
        priority=int(normalized.get("priority", 0)),
    )
    policy.rules = [
        PolicyRule(
            id=uuid.uuid4(),
            policy_id=policy.id,
            rule_type=RuleType(rule["type"]),
            conditions=rule.get("conditions") or {},
            action=PolicyAction(rule["action"]),
            message=rule.get("message"),
            is_active=bool(rule.get("enabled", True)),
        )
        for rule in normalized.get("rules", [])
    ]
    return policy


def normalized_from_policy(policy: Policy) -> dict[str, Any]:
    return {
        "version": "authclaw.policy/v1",
        "name": sanitize_text(getattr(policy, "name", "")),
        "description": sanitize_text(getattr(policy, "description", None)) if getattr(policy, "description", None) else None,
        "enabled": bool(getattr(policy, "is_active", True)),
        "priority": int(getattr(policy, "priority", 0) or 0),
        "rules": [
            {
                "type": rule.rule_type.value if hasattr(rule.rule_type, "value") else str(rule.rule_type),
                "action": rule.action.value if hasattr(rule.action, "value") else str(rule.action),
                "message": sanitize_text(rule.message) if rule.message else None,
                "enabled": bool(rule.is_active),
                "conditions": rule.conditions or {},
            }
            for rule in getattr(policy, "rules", [])
        ],
    }


def export_policy_yaml(policy: Policy) -> str:
    return yaml.safe_dump(normalized_from_policy(policy), sort_keys=False)
