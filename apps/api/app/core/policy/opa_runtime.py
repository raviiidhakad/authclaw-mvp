from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any

import httpx

from app.core.policy.opa_input import SANITIZATION_VERSION
from app.services.api_safety import SECRET_FIELD_NAMES, collect_secret_values, sanitize_text


_VAULT_REF_PATTERN = re.compile(r"\b(?:vault|secret)://[^\s,;'\"]+", re.I)


class OpaFailureMode(str, Enum):
    """Runtime behavior when OPA cannot return a valid decision."""

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class OpaRuntimeStatus(str, Enum):
    OK = "ok"
    ERROR = "error"


class OpaErrorCategory(str, Enum):
    INVALID_INPUT = "invalid_input"
    MISSING_DECISION_FIELDS = "missing_decision_fields"
    MALFORMED_RESPONSE = "malformed_response"
    MALFORMED_JSON = "malformed_json"
    HTTP_ERROR = "http_error"
    TIMEOUT = "timeout"
    CONNECTION_FAILURE = "connection_failure"
    RUNTIME_ERROR = "runtime_error"
    HYBRID_MISMATCH = "hybrid_mismatch"


@dataclass(frozen=True)
class OpaRuntimeDecision:
    """Normalized OPA decision shape consumed by future runtime wiring."""

    allowed: bool
    action: str
    reason: str
    matched_rules: list[dict[str, Any]] = field(default_factory=list)
    redaction_required: bool = False
    runtime_status: OpaRuntimeStatus = OpaRuntimeStatus.OK
    error_category: OpaErrorCategory | None = None
    http_status: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "matched_rules": self.matched_rules,
            "redaction_required": self.redaction_required,
            "runtime_status": self.runtime_status.value,
            "error_category": self.error_category.value if self.error_category else None,
            "http_status": self.http_status,
            "metadata": self.metadata,
        }


@dataclass
class OpaRuntimeMetrics:
    cache_hits: int = 0
    cache_misses: int = 0
    runtime_failures: int = 0
    allow_count: int = 0
    deny_count: int = 0
    redact_count: int = 0
    evaluation_latencies_ms: list[int] = field(default_factory=list)

    def record_cache_hit(self) -> None:
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        self.cache_misses += 1

    def record_decision(self, decision: OpaRuntimeDecision, latency_ms: int) -> None:
        self.evaluation_latencies_ms.append(int(latency_ms))
        if decision.runtime_status != OpaRuntimeStatus.OK:
            self.runtime_failures += 1
        if decision.allowed:
            self.allow_count += 1
        else:
            self.deny_count += 1
        if decision.redaction_required:
            self.redact_count += 1

    def snapshot(self) -> dict[str, Any]:
        latencies = sorted(self.evaluation_latencies_ms)
        count = len(latencies)
        p95 = latencies[min(count - 1, int(count * 0.95))] if count else 0
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "runtime_failures": self.runtime_failures,
            "allow_count": self.allow_count,
            "deny_count": self.deny_count,
            "redact_count": self.redact_count,
            "evaluation_count": count,
            "evaluation_latency_p95_ms": p95,
        }


class OpaRuntimeEvaluator:
    """HTTP OPA runtime client for sanitized AuthClaw policy input documents.

    This layer only sends the T2 sanitized input document to a configured OPA
    data endpoint and normalizes the response. It does not select runtimes,
    evaluate YAML, modify gateway enforcement, or author Rego policies.
    """

    def __init__(
        self,
        policy_url: str,
        *,
        failure_mode: OpaFailureMode = OpaFailureMode.FAIL_CLOSED,
        timeout_seconds: float = 2.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.policy_url = policy_url
        self.failure_mode = failure_mode
        self.timeout_seconds = timeout_seconds
        self._http_client = http_client

    async def evaluate(self, input_document: dict[str, Any]) -> OpaRuntimeDecision:
        if not self._is_sanitized_input(input_document):
            return self._failure_decision(OpaErrorCategory.INVALID_INPUT)

        try:
            response = await self._post(input_document)
        except httpx.TimeoutException:
            return self._failure_decision(OpaErrorCategory.TIMEOUT)
        except (httpx.ConnectError, httpx.NetworkError):
            return self._failure_decision(OpaErrorCategory.CONNECTION_FAILURE)
        except httpx.HTTPError:
            return self._failure_decision(OpaErrorCategory.RUNTIME_ERROR)

        if response.status_code >= 400:
            return self._failure_decision(OpaErrorCategory.HTTP_ERROR, http_status=response.status_code)

        try:
            body = response.json()
        except ValueError:
            return self._failure_decision(OpaErrorCategory.MALFORMED_JSON, http_status=response.status_code)

        return self._normalize_body(body, http_status=response.status_code)

    async def _post(self, input_document: dict[str, Any]) -> httpx.Response:
        payload = {"input": input_document}
        if self._http_client is not None:
            return await self._http_client.post(self.policy_url, json=payload, timeout=self.timeout_seconds)

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            return await client.post(self.policy_url, json=payload)

    def _normalize_body(self, body: Any, *, http_status: int) -> OpaRuntimeDecision:
        if not isinstance(body, dict) or "result" not in body:
            return self._failure_decision(OpaErrorCategory.MALFORMED_RESPONSE, http_status=http_status)

        result = body.get("result")
        if isinstance(result, bool):
            return self._success_decision(
                allowed=result,
                action="allow" if result else "deny",
                reason="OPA allowed request." if result else "OPA denied request.",
                http_status=http_status,
            )
        if not isinstance(result, dict):
            return self._failure_decision(OpaErrorCategory.MALFORMED_RESPONSE, http_status=http_status)

        if "allow" in result:
            allowed = result.get("allow")
        else:
            allowed = result.get("allowed")
        if not isinstance(allowed, bool):
            return self._failure_decision(OpaErrorCategory.MISSING_DECISION_FIELDS, http_status=http_status)

        deny_reasons = self._safe_string_list(result.get("deny") or result.get("denies") or [])
        if deny_reasons:
            allowed = False

        action = self._safe_string(result.get("action") or ("allow" if allowed else "deny"))
        if not action:
            action = "allow" if allowed else "deny"

        reason = self._safe_string(result.get("reason"))
        if not reason and deny_reasons:
            reason = "; ".join(deny_reasons)
        if not reason:
            reason = "OPA allowed request." if allowed else "OPA denied request."

        matched_rules = self._safe_matched_rules(result.get("matched_rules") or result.get("matches") or [])
        metadata = self._safe_metadata(result.get("metadata") or {})
        metadata = self._stable_mapping(
            {
                **metadata,
                "failure_mode": self.failure_mode.value,
                "source": "opa",
            }
        )

        return OpaRuntimeDecision(
            allowed=allowed,
            action=action,
            reason=reason,
            matched_rules=matched_rules,
            redaction_required=bool(result.get("redaction_required", False)),
            runtime_status=OpaRuntimeStatus.OK,
            error_category=None,
            http_status=http_status,
            metadata=metadata,
        )

    def _success_decision(self, *, allowed: bool, action: str, reason: str, http_status: int) -> OpaRuntimeDecision:
        return OpaRuntimeDecision(
            allowed=allowed,
            action=action,
            reason=reason,
            runtime_status=OpaRuntimeStatus.OK,
            http_status=http_status,
            metadata=self._stable_mapping({"failure_mode": self.failure_mode.value, "source": "opa"}),
        )

    def _failure_decision(
        self,
        category: OpaErrorCategory,
        *,
        http_status: int | None = None,
    ) -> OpaRuntimeDecision:
        allowed = self.failure_mode == OpaFailureMode.FAIL_OPEN
        action = "allow" if allowed else "deny"
        return OpaRuntimeDecision(
            allowed=allowed,
            action=action,
            reason=(
                "OPA runtime could not produce a valid decision; fail-open mode allowed the request."
                if allowed
                else "OPA runtime could not produce a valid decision; fail-closed mode denied the request."
            ),
            matched_rules=[],
            redaction_required=False,
            runtime_status=OpaRuntimeStatus.ERROR,
            error_category=category,
            http_status=http_status,
            metadata=self._stable_mapping(
                {
                    "error_category": category.value,
                    "failure_mode": self.failure_mode.value,
                    "source": "opa",
                }
            ),
        )

    @staticmethod
    def _is_sanitized_input(input_document: dict[str, Any]) -> bool:
        if not isinstance(input_document, dict):
            return False
        return input_document.get("sanitization_version") == SANITIZATION_VERSION

    def _safe_matched_rules(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        rules: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                safe_item = self._safe_metadata(item)
                if safe_item:
                    rules.append(safe_item)
            elif item:
                rules.append({"id": self._safe_string(item)})
        return sorted(rules, key=lambda item: str(item))

    def _safe_metadata(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        secret_values = collect_secret_values(value)
        sanitized = self._sanitize_value(value, secret_values)
        return sanitized if isinstance(sanitized, dict) else {}

    def _sanitize_value(self, value: Any, secret_values: list[str]) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key in sorted(value, key=lambda item: str(item)):
                key_text = str(key)
                key_lower = key_text.lower()
                if key_lower in SECRET_FIELD_NAMES or key_lower in {"authorization", "x-api-key", "x_api_key"}:
                    result[key_text] = "[redacted]"
                    continue
                result[key_text] = self._sanitize_value(value[key], secret_values)
            return result
        if isinstance(value, list):
            return [self._sanitize_value(item, secret_values) for item in value]
        if isinstance(value, str):
            return self._safe_string(value, secret_values)
        if isinstance(value, (bool, int)) or value is None:
            return value
        if isinstance(value, float):
            return value if value == value and value not in (float("inf"), float("-inf")) else None
        return self._safe_string(value, secret_values)

    def _safe_string_list(self, value: Any) -> list[str]:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        return sorted({self._safe_string(item) for item in value if self._safe_string(item)})

    @staticmethod
    def _safe_string(value: Any, extra_secret_values: list[str] | None = None) -> str:
        if value is None:
            return ""
        return _VAULT_REF_PATTERN.sub("[redacted]", sanitize_text(value, extra_secret_values or []))

    @staticmethod
    def _stable_mapping(value: dict[str, Any]) -> dict[str, Any]:
        return {key: value[key] for key in sorted(value)}
