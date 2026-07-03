from __future__ import annotations

import re
import uuid
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from app.models.policy import Policy
from app.services.api_safety import SECRET_FIELD_NAMES, collect_secret_values, sanitize_text


SANITIZATION_VERSION = "opa-input/v1"
REDACTION_MARKER = "[redacted]"

_VAULT_REF_PATTERN = re.compile(r"\b(?:vault|secret)://[^\s,;'\"]+", re.I)
_OPA_SECRET_KEYS = {
    *SECRET_FIELD_NAMES,
    "authorization",
    "proxy_authorization",
    "x_api_key",
    "x-api-key",
    "provider_api_key",
    "provider_key",
    "kms_key",
    "vault_ref",
    "vault_reference",
    "vault_path",
    "redis_value",
    "decrypted_pii",
    "plaintext_token",
}
_OPA_RAW_PAYLOAD_KEYS = {
    "raw_prompt",
    "prompt",
    "messages",
    "content",
    "raw_content",
    "raw_request",
    "raw_response",
    "raw_payload",
    "raw_provider_payload",
    "provider_response",
    "completion",
    "plaintext",
}
_RESERVED_METADATA_KEYS = {
    "tenant_id",
    "route_id",
    "provider_id",
    "policy_id",
}


@dataclass(frozen=True)
class OpaPolicyVersion:
    policy_version: str
    policy_hash: str
    policy_ids: list[str]


class OpaPolicyVersionTracker:
    """Derive deterministic policy hashes from existing ORM metadata only."""

    @classmethod
    def from_policies(cls, policies: list[Policy]) -> OpaPolicyVersion:
        policy_payloads: list[dict[str, Any]] = []
        for policy in sorted(policies, key=lambda item: str(item.id)):
            rules = []
            for rule in sorted(getattr(policy, "rules", []), key=lambda item: str(item.id)):
                rules.append(
                    {
                        "id": str(rule.id),
                        "type": getattr(rule.rule_type, "value", str(rule.rule_type)),
                        "action": getattr(rule.action, "value", str(rule.action)),
                        "conditions": rule.conditions or {},
                        "is_active": bool(rule.is_active),
                    }
                )
            policy_payloads.append(
                {
                    "id": str(policy.id),
                    "name": sanitize_text(policy.name),
                    "is_active": bool(policy.is_active),
                    "priority": int(policy.priority or 0),
                    "rules": rules,
                }
            )
        encoded = json.dumps(policy_payloads, sort_keys=True, separators=(",", ":"), default=str)
        policy_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return OpaPolicyVersion(
            policy_version=f"sha256:{policy_hash[:16]}",
            policy_hash=policy_hash,
            policy_ids=[item["id"] for item in policy_payloads],
        )


class _OmitValue:
    pass


_OMIT = _OmitValue()


@dataclass(frozen=True)
class OpaInputContext:
    """Gateway context accepted by the OPA input builder.

    The builder only normalizes and sanitizes already-available metadata. It
    does not evaluate policy, call OPA/Rego, or alter gateway enforcement.
    """

    tenant_id: uuid.UUID | str | None = None
    route_id: uuid.UUID | str | None = None
    provider_id: uuid.UUID | str | None = None
    provider: str | None = None
    provider_type: str | None = None
    model: str | None = None
    direction: str | None = "INBOUND"
    request_type: str | None = "chat.completions"
    request_metadata: dict[str, Any] | None = None
    detected_entities: list[dict[str, Any]] | None = None
    entity_types: list[str] | None = None
    policy_id: uuid.UUID | str | None = None
    policy_version: str | None = None
    normalized_policy: dict[str, Any] | None = None
    keyword_matches: list[str] | None = None
    regex_matches: list[str] | None = None
    risk_metadata: dict[str, Any] | None = None
    compliance_metadata: dict[str, Any] | None = None
    gateway_metadata: dict[str, Any] | None = None


class OpaInputBuilder:
    """Build deterministic, sanitized OPA input documents from gateway context."""

    sanitization_version = SANITIZATION_VERSION

    def build(self, context: OpaInputContext) -> dict[str, Any]:
        document: dict[str, Any] = {
            "sanitization_version": self.sanitization_version,
        }

        self._add(document, "tenant", self._compact({"id": self._stable_id(context.tenant_id)}))
        self._add(document, "route", self._compact({"id": self._stable_id(context.route_id)}))
        self._add(
            document,
            "provider",
            self._compact(
                {
                    "id": self._stable_id(context.provider_id),
                    "name": self._safe_string(context.provider),
                    "type": self._safe_string(context.provider_type),
                }
            ),
        )
        self._add(document, "model", self._safe_string(context.model))
        self._add(
            document,
            "request",
            self._compact(
                {
                    "direction": self._safe_string(context.direction).upper() if context.direction else None,
                    "type": self._safe_string(context.request_type),
                    "metadata": self._sanitize_mapping(context.request_metadata, omit_reserved=True),
                }
            ),
        )
        self._add(
            document,
            "entities",
            self._compact(
                {
                    "types": self._stable_string_list(context.entity_types),
                    "detected": self._normalize_detections(context.detected_entities),
                }
            ),
        )
        self._add(
            document,
            "policy",
            self._compact(
                {
                    "id": self._stable_id(context.policy_id),
                    "version": self._safe_string(context.policy_version),
                    "normalized": self._sanitize_mapping(context.normalized_policy),
                }
            ),
        )
        self._add(
            document,
            "matches",
            self._compact(
                {
                    "keywords": self._stable_string_list(context.keyword_matches),
                    "regexes": self._stable_string_list(context.regex_matches),
                }
            ),
        )
        self._add(document, "risk", self._sanitize_mapping(context.risk_metadata))
        self._add(document, "compliance", self._sanitize_mapping(context.compliance_metadata))
        self._add(document, "gateway", self._sanitize_mapping(context.gateway_metadata))

        return self._stable_mapping(document)

    def _normalize_detections(self, detections: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not detections:
            return None

        normalized: list[dict[str, Any]] = []
        for detection in detections:
            if not isinstance(detection, dict):
                continue
            item = self._compact(
                {
                    "entity_type": self._safe_string(detection.get("entity_type")),
                    "start": self._safe_int(detection.get("start")),
                    "end": self._safe_int(detection.get("end")),
                    "score": self._safe_float(detection.get("score")),
                }
            )
            if item:
                normalized.append(item)

        return sorted(
            normalized,
            key=lambda item: (
                str(item.get("entity_type", "")),
                int(item.get("start", -1)),
                int(item.get("end", -1)),
                float(item.get("score", 0.0)),
            ),
        ) or None

    def _sanitize_mapping(self, value: dict[str, Any] | None, *, omit_reserved: bool = False) -> dict[str, Any] | None:
        if not isinstance(value, dict) or not value:
            return None
        secret_values = collect_secret_values(value)
        sanitized = self._sanitize_value(value, secret_values=secret_values, omit_reserved=omit_reserved)
        return sanitized if isinstance(sanitized, dict) and sanitized else None

    def _sanitize_value(self, value: Any, *, secret_values: list[str], omit_reserved: bool = False) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for raw_key in sorted(value, key=lambda item: str(item)):
                key = str(raw_key)
                key_lower = key.lower()
                if omit_reserved and key_lower in _RESERVED_METADATA_KEYS:
                    continue
                if key_lower in _OPA_RAW_PAYLOAD_KEYS:
                    continue
                safe_key = self._safe_key(key)
                if key_lower in _OPA_SECRET_KEYS:
                    result[safe_key] = REDACTION_MARKER
                    continue
                nested = self._sanitize_value(value[raw_key], secret_values=secret_values, omit_reserved=omit_reserved)
                if nested is not _OMIT and nested is not None:
                    result[safe_key] = nested
            return result

        if isinstance(value, (list, tuple)):
            items = [
                self._sanitize_value(item, secret_values=secret_values, omit_reserved=omit_reserved)
                for item in value
            ]
            return [item for item in items if item is not _OMIT and item is not None]

        if isinstance(value, set):
            items = [
                self._sanitize_value(item, secret_values=secret_values, omit_reserved=omit_reserved)
                for item in value
            ]
            return sorted((item for item in items if item is not _OMIT and item is not None), key=str)

        if isinstance(value, uuid.UUID):
            return str(value)
        if isinstance(value, str):
            return self._safe_string(value, secret_values=secret_values)
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return value if value == value and value not in (float("inf"), float("-inf")) else None
        return self._safe_string(value, secret_values=secret_values)

    def _safe_string(self, value: Any, *, secret_values: list[str] | None = None) -> str:
        if value is None:
            return ""
        sanitized = sanitize_text(value, secret_values or [])
        return _VAULT_REF_PATTERN.sub(REDACTION_MARKER, sanitized)

    @staticmethod
    def _safe_key(value: Any) -> str:
        return _VAULT_REF_PATTERN.sub(REDACTION_MARKER, " ".join(str(value).replace("\x00", " ").split()))

    def _stable_string_list(self, values: list[str] | None) -> list[str] | None:
        if not values:
            return None
        sanitized = {self._safe_string(value) for value in values if self._safe_string(value)}
        return sorted(sanitized) or None

    @staticmethod
    def _stable_id(value: uuid.UUID | str | None) -> str | None:
        return str(value) if value else None

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _compact(value: dict[str, Any]) -> dict[str, Any] | None:
        compacted = {key: nested for key, nested in value.items() if nested not in (None, "", [], {})}
        return compacted or None

    @staticmethod
    def _add(document: dict[str, Any], key: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            document[key] = value

    def _stable_mapping(self, value: dict[str, Any]) -> dict[str, Any]:
        return {key: value[key] for key in sorted(value)}


def safe_policy_matches(prompt: str, policies: list[Policy]) -> tuple[list[str], list[str]]:
    keyword_matches: list[str] = []
    regex_matches: list[str] = []
    lower_prompt = prompt.lower()
    for policy in sorted(policies, key=lambda item: str(getattr(item, "id", ""))):
        for rule in sorted(getattr(policy, "rules", []) or [], key=lambda item: str(getattr(item, "id", ""))):
            if not getattr(rule, "is_active", False):
                continue
            conditions = getattr(rule, "conditions", {}) or {}
            keywords = conditions.get("keywords", conditions.get("blocked_terms", [])) or []
            if isinstance(keywords, str):
                keywords = [keywords]
            for keyword in keywords:
                keyword_text = str(keyword)
                if keyword_text and keyword_text.lower() in lower_prompt:
                    keyword_hash = hashlib.sha256(keyword_text.encode("utf-8")).hexdigest()[:12]
                    keyword_matches.append(
                        f"policy:{getattr(policy, 'id', '')}:rule:{getattr(rule, 'id', '')}:keyword:{keyword_hash}"
                    )
            patterns = conditions.get("regex_patterns", conditions.get("patterns", [])) or []
            if isinstance(patterns, str):
                patterns = [patterns]
            for pattern in patterns:
                try:
                    if re.search(str(pattern), prompt):
                        pattern_hash = hashlib.sha256(str(pattern).encode("utf-8")).hexdigest()[:12]
                        regex_matches.append(
                            f"policy:{getattr(policy, 'id', '')}:rule:{getattr(rule, 'id', '')}:regex:{pattern_hash}"
                        )
                except re.error:
                    continue
    return sorted(set(keyword_matches)), sorted(set(regex_matches))
