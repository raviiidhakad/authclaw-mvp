from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from app.core.engine.evaluator import EvaluationResult, PolicyEngine, RuleViolation
from app.core.policy.opa_input import (
    OpaInputBuilder,
    OpaInputContext,
    OpaPolicyVersion,
    OpaPolicyVersionTracker,
    safe_policy_matches,
)
from app.core.policy.opa_runtime import (
    OpaErrorCategory,
    OpaFailureMode,
    OpaRuntimeMetrics,
    OpaRuntimeDecision,
    OpaRuntimeEvaluator,
    OpaRuntimeStatus,
)
from app.core.policy.yaml_policy import OpaEvaluationContext, OpaRuntimeMode, OpaPolicyAdapter, PythonPolicyAdapter, normalized_from_policy
from app.models.gateway_route import GatewayRoute
from app.models.policy import Policy
from app.models.provider import Provider
from app.schemas.security_events import PolicyEvaluatedEvent
from app.services.api_safety import sanitize_text


@dataclass(frozen=True)
class OpaIntegrationResult:
    decision_id: str
    decision: OpaRuntimeDecision
    policy_version: str
    policy_hash: str
    cache_hit: bool
    evaluation_latency_ms: int
    engine_mode: str = "opa"

    def audit_metadata(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "engine_mode": self.engine_mode,
            "runtime": "opa",
            "runtime_status": self.decision.runtime_status.value,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "matched_rules": self.decision.matched_rules,
            "action": self.decision.action,
            "evaluation_latency_ms": self.evaluation_latency_ms,
            "cache_hit": self.cache_hit,
            "error_category": self.decision.error_category.value if self.decision.error_category else None,
        }


@dataclass(frozen=True)
class OpaAuthoritativeDecision:
    evaluation_result: EvaluationResult
    runtime_result: OpaIntegrationResult | None
    adapter_name: str
    decision_source: str

    def metadata(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "adapter": self.adapter_name,
            "decision_source": self.decision_source,
        }
        if self.runtime_result is not None:
            payload["opa"] = self.runtime_result.audit_metadata()
        return payload


class OpaDecisionCache:
    """Small in-process decision cache for sanitized OPA decisions."""

    def __init__(self) -> None:
        self._items: dict[str, OpaRuntimeDecision] = {}
        self._tenant_keys: dict[str, set[str]] = {}

    def make_key(
        self,
        *,
        tenant_id: uuid.UUID,
        route_id: uuid.UUID | None,
        model: str,
        policy_hash: str,
        input_document: dict[str, Any],
    ) -> str:
        payload = {
            "tenant_id": str(tenant_id),
            "route_id": str(route_id) if route_id else None,
            "model": model,
            "policy_hash": policy_hash,
            "input_hash": hashlib.sha256(
                json.dumps(input_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
            ).hexdigest(),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def get(self, tenant_id: uuid.UUID, key: str) -> OpaRuntimeDecision | None:
        if key not in self._tenant_keys.get(str(tenant_id), set()):
            return None
        return self._items.get(key)

    def set(self, tenant_id: uuid.UUID, key: str, decision: OpaRuntimeDecision) -> None:
        if decision.runtime_status != OpaRuntimeStatus.OK:
            return
        self._items[key] = decision
        self._tenant_keys.setdefault(str(tenant_id), set()).add(key)

    def invalidate_tenant(self, tenant_id: uuid.UUID) -> int:
        keys = self._tenant_keys.pop(str(tenant_id), set())
        for key in keys:
            self._items.pop(key, None)
        return len(keys)

    def health(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "backend": "in_memory",
            "entries": len(self._items),
            "tenant_count": len(self._tenant_keys),
        }


class OpaRuntimeIntegration:
    """Gateway policy integration point for authoritative OPA-adapter decisions."""

    VALID_POLICY_ENGINE_MODES = {"python", "opa", "hybrid"}

    def __init__(
        self,
        *,
        enabled: bool,
        policy_url: str,
        runtime_mode: str = "STRICT",
        policy_engine_mode: str | None = None,
        strict_mode: bool = True,
        fail_closed: bool = True,
        timeout_seconds: float = 2.0,
        cache: OpaDecisionCache | None = None,
        metrics: OpaRuntimeMetrics | None = None,
        evaluator_factory: Callable[[OpaFailureMode], OpaRuntimeEvaluator] | None = None,
        adapter: OpaPolicyAdapter | None = None,
    ) -> None:
        self.policy_engine_mode = self._normalize_policy_engine_mode(
            policy_engine_mode or ("opa" if enabled else "python")
        )
        self.enabled = self.policy_engine_mode in {"opa", "hybrid"}
        self.policy_url = policy_url
        self.runtime_mode = runtime_mode.upper()
        self.strict_mode = bool(strict_mode)
        self.fail_closed = bool(fail_closed)
        self.timeout_seconds = float(timeout_seconds)
        self.cache = cache or opa_decision_cache
        self.metrics = metrics or opa_runtime_metrics
        self._evaluator_factory = evaluator_factory
        self.adapter = adapter or PythonPolicyAdapter()

    @classmethod
    def from_settings(cls) -> "OpaRuntimeIntegration":
        from app.core.config import settings

        engine_mode = str(getattr(settings, "POLICY_ENGINE_MODE", "python")).lower()
        if bool(settings.ENABLE_OPA_RUNTIME_INTEGRATION) and engine_mode == "python":
            engine_mode = "opa"
        policy_url = str(getattr(settings, "OPA_URL", "") or settings.OPA_POLICY_URL)
        strict_mode = bool(getattr(settings, "OPA_STRICT_MODE", True))
        return cls(
            enabled=bool(settings.ENABLE_OPA_RUNTIME_INTEGRATION),
            policy_url=policy_url,
            runtime_mode=settings.OPA_RUNTIME_MODE,
            policy_engine_mode=engine_mode,
            strict_mode=strict_mode,
            fail_closed=bool(getattr(settings, "OPA_FAIL_CLOSED", True)),
            timeout_seconds=float(getattr(settings, "OPA_TIMEOUT_SECONDS", 2.0)),
        )

    async def evaluate_authoritative(
        self,
        *,
        prompt: str,
        tenant_id: uuid.UUID,
        api_key_id: uuid.UUID,
        route: GatewayRoute,
        provider: Provider,
        model: str,
        policies: list[Policy],
        request_metadata: dict[str, Any] | None = None,
    ) -> OpaAuthoritativeDecision:
        adapter_result = self._evaluate_with_adapter(
            prompt=prompt,
            tenant_id=tenant_id,
            route=route,
            model=model,
            policies=policies,
        )
        if self.policy_engine_mode == "python" or not self.enabled:
            return OpaAuthoritativeDecision(
                evaluation_result=adapter_result,
                runtime_result=None,
                adapter_name=self.adapter.name,
                decision_source="adapter",
            )

        runtime_result = await self.evaluate_gateway(
            tenant_id=tenant_id,
            api_key_id=api_key_id,
            route=route,
            provider=provider,
            model=model,
            policies=policies,
            prompt=prompt,
            action=adapter_result.action_taken,
            matched_rule_count=len(adapter_result.violations),
            adapter_result=adapter_result,
            request_metadata=request_metadata,
        )
        if runtime_result is None:
            return OpaAuthoritativeDecision(
                evaluation_result=adapter_result,
                runtime_result=None,
                adapter_name=self.adapter.name,
                decision_source="adapter",
            )

        if runtime_result.decision.runtime_status == OpaRuntimeStatus.ERROR and self._uses_compatibility_fallback():
            return OpaAuthoritativeDecision(
                evaluation_result=adapter_result,
                runtime_result=runtime_result,
                adapter_name=self.adapter.name,
                decision_source="adapter_compatibility_fallback",
            )

        if self.policy_engine_mode == "hybrid":
            mismatch = self._hybrid_mismatch(adapter_result, runtime_result.decision)
            if mismatch:
                mismatch_result = OpaIntegrationResult(
                    decision_id=runtime_result.decision_id,
                    decision=self._hybrid_mismatch_decision(mismatch),
                    policy_version=runtime_result.policy_version,
                    policy_hash=runtime_result.policy_hash,
                    cache_hit=runtime_result.cache_hit,
                    evaluation_latency_ms=runtime_result.evaluation_latency_ms,
                    engine_mode=self.policy_engine_mode,
                )
                return OpaAuthoritativeDecision(
                    evaluation_result=self._evaluation_result_from_runtime(prompt, mismatch_result.decision),
                    runtime_result=mismatch_result,
                    adapter_name=self.adapter.name,
                    decision_source="hybrid_mismatch_fail_closed",
                )

        if (
            runtime_result.decision.runtime_status == OpaRuntimeStatus.OK
            and not adapter_result.allowed
            and runtime_result.decision.allowed
        ):
            return OpaAuthoritativeDecision(
                evaluation_result=adapter_result,
                runtime_result=runtime_result,
                adapter_name=self.adapter.name,
                decision_source="adapter_policy_deny",
            )

        return OpaAuthoritativeDecision(
            evaluation_result=self._evaluation_result_from_runtime(
                prompt,
                runtime_result.decision,
                adapter_result=adapter_result,
            ),
            runtime_result=runtime_result,
            adapter_name=self.adapter.name,
            decision_source="opa_runtime",
        )

    async def evaluate_gateway(
        self,
        *,
        tenant_id: uuid.UUID,
        api_key_id: uuid.UUID,
        route: GatewayRoute,
        provider: Provider,
        model: str,
        policies: list[Policy],
        prompt: str = "",
        action: str,
        matched_rule_count: int,
        adapter_result: EvaluationResult | None = None,
        request_metadata: dict[str, Any] | None = None,
    ) -> OpaIntegrationResult | None:
        if not self.enabled:
            return None

        version = OpaPolicyVersionTracker.from_policies(policies)
        keyword_matches, regex_matches = safe_policy_matches(prompt, policies)
        normalized_policies = [normalized_from_policy(policy) for policy in policies]
        input_document = OpaInputBuilder().build(
            OpaInputContext(
                tenant_id=tenant_id,
                route_id=getattr(route, "id", None),
                provider_id=getattr(provider, "id", None),
                provider=getattr(provider, "name", None),
                provider_type=getattr(getattr(provider, "type", None), "value", getattr(provider, "type", None)),
                model=model,
                direction="INBOUND",
                request_type="chat.completions",
                request_metadata=request_metadata or {},
                entity_types=[],
                normalized_policy={"policies": normalized_policies},
                keyword_matches=keyword_matches,
                regex_matches=regex_matches,
                policy_version=version.policy_version,
                gateway_metadata={
                    "engine_mode": self.policy_engine_mode,
                    "policy_hash": version.policy_hash,
                    "policy_ids": version.policy_ids,
                    "python_action": action,
                    "python_allowed": bool(adapter_result.allowed) if adapter_result else action != "block",
                    "python_matched_rule_count": matched_rule_count,
                    "python_redaction_required": bool(adapter_result and adapter_result.modified_prompt != prompt),
                    "strict_mode": self.strict_mode,
                },
            )
        )
        cache_key = self.cache.make_key(
            tenant_id=tenant_id,
            route_id=getattr(route, "id", None),
            model=model,
            policy_hash=version.policy_hash,
            input_document=input_document,
        )
        cached = self.cache.get(tenant_id, cache_key)
        if cached:
            self.metrics.record_cache_hit()
            result = OpaIntegrationResult(
                decision_id=self._decision_id(cache_key, version.policy_hash, cached),
                decision=cached,
                policy_version=version.policy_version,
                policy_hash=version.policy_hash,
                cache_hit=True,
                evaluation_latency_ms=0,
                engine_mode=self.policy_engine_mode,
            )
            self._publish_decision_event(tenant_id, api_key_id, result)
            return result

        self.metrics.record_cache_miss()
        started = time.monotonic()
        decision = await self._evaluator().evaluate(input_document)
        latency_ms = int((time.monotonic() - started) * 1000)
        self.metrics.record_decision(decision, latency_ms)
        self.cache.set(tenant_id, cache_key, decision)
        result = OpaIntegrationResult(
            decision_id=self._decision_id(cache_key, version.policy_hash, decision),
            decision=decision,
            policy_version=version.policy_version,
            policy_hash=version.policy_hash,
            cache_hit=False,
            evaluation_latency_ms=latency_ms,
            engine_mode=self.policy_engine_mode,
        )
        self._publish_decision_event(tenant_id, api_key_id, result)
        return result

    def health(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "policy_engine_mode": self.policy_engine_mode,
            "runtime_available": bool(self.policy_url),
            "runtime_mode": self.runtime_mode,
            "strict_mode": self.strict_mode,
            "fail_closed": self.fail_closed,
            "cache": self.cache.health(),
            "policy_version_status": "deterministic_hash",
            "metrics": self.metrics.snapshot(),
        }

    def _evaluator(self) -> OpaRuntimeEvaluator:
        failure_mode = OpaFailureMode.FAIL_OPEN if self._uses_compatibility_fallback() else OpaFailureMode.FAIL_CLOSED
        if self._evaluator_factory:
            return self._evaluator_factory(failure_mode)
        return OpaRuntimeEvaluator(
            self.policy_url,
            failure_mode=failure_mode,
            timeout_seconds=self.timeout_seconds,
        )

    def _evaluate_with_adapter(
        self,
        *,
        prompt: str,
        tenant_id: uuid.UUID,
        route: GatewayRoute,
        model: str,
        policies: list[Policy],
    ) -> EvaluationResult:
        sorted_policies = sorted(policies, key=lambda policy: int(getattr(policy, "priority", 0) or 0), reverse=True)
        combined = EvaluationResult(allowed=True, modified_prompt=prompt, violations=[], action_taken="allow")
        current_prompt = prompt

        for policy in sorted_policies:
            if not getattr(policy, "is_active", False):
                continue
            context = OpaEvaluationContext(
                tenant_id=tenant_id,
                route_id=getattr(route, "id", None),
                policy_id=getattr(policy, "id", None),
                target_model=model,
                runtime_mode=(
                    OpaRuntimeMode.COMPATIBILITY
                    if self.runtime_mode == "COMPATIBILITY"
                    else OpaRuntimeMode.STRICT
                ),
            )
            decision = self.adapter.evaluate(
                current_prompt,
                normalized_from_policy(policy),
                context,
            )
            violations = self._violations_from_adapter(policy, decision)
            combined.violations.extend(violations)

            action = str(decision.get("action") or "allow").lower()
            if not bool(decision.get("allowed", True)) or action in {"block", "deny"}:
                combined.allowed = False
                combined.action_taken = "block"
                combined.modified_prompt = current_prompt
                return combined
            if bool(decision.get("redaction_required", False)) and combined.action_taken != "block":
                combined.action_taken = "warn"
                policy_eval = PolicyEngine().evaluate(current_prompt, [policy], target_model=model)
                if policy_eval.modified_prompt != current_prompt:
                    current_prompt = policy_eval.modified_prompt
            elif violations and combined.action_taken == "allow":
                combined.action_taken = "warn"

        combined.modified_prompt = current_prompt
        return combined

    @staticmethod
    def _violations_from_adapter(policy: Policy, decision: dict[str, Any]) -> list[RuleViolation]:
        violations: list[RuleViolation] = []
        for index, matched_rule in enumerate(decision.get("matched_rules") or []):
            if not isinstance(matched_rule, dict):
                matched_rule = {"message": str(matched_rule)}
            rules = list(getattr(policy, "rules", []) or [])
            rule = rules[index] if index < len(rules) else (rules[0] if rules else None)
            action = str(matched_rule.get("action") or decision.get("action") or "block")
            message = sanitize_text(matched_rule.get("message") or decision.get("reason") or "Policy rule matched.")
            violations.append(
                RuleViolation(
                    policy_id=str(getattr(policy, "id", "")),
                    rule_id=str(getattr(rule, "id", "")) if rule is not None else "",
                    rule_type=str(matched_rule.get("rule_type") or getattr(getattr(rule, "rule_type", None), "value", "") or getattr(rule, "rule_type", "")),
                    action=action,
                    message=message,
                    context={"source": "opa_adapter"},
                )
            )
        return violations

    @staticmethod
    def _evaluation_result_from_runtime(
        prompt: str,
        decision: OpaRuntimeDecision,
        *,
        adapter_result: EvaluationResult | None = None,
    ) -> EvaluationResult:
        allowed = bool(decision.allowed)
        wants_redaction = bool(decision.redaction_required or str(decision.action).lower() in {"redact", "warn"})
        action_taken = "allow" if allowed else "block"
        violations: list[RuleViolation] = []
        if not allowed:
            matches = decision.matched_rules or [{"message": decision.reason, "action": decision.action}]
            for index, matched_rule in enumerate(matches):
                violations.append(
                    RuleViolation(
                        policy_id="opa",
                        rule_id=str(matched_rule.get("id") or index) if isinstance(matched_rule, dict) else str(index),
                        rule_type="opa",
                        action=str(decision.action or "deny"),
                        message=sanitize_text(
                            matched_rule.get("message") if isinstance(matched_rule, dict) else decision.reason
                        )
                        or sanitize_text(decision.reason)
                        or "OPA denied request.",
                        context={"source": "opa_runtime"},
                    )
                )
        elif wants_redaction:
            action_taken = "warn"
            matches = decision.matched_rules or [{"message": decision.reason, "action": decision.action}]
            for index, matched_rule in enumerate(matches):
                violations.append(
                    RuleViolation(
                        policy_id="opa",
                        rule_id=str(matched_rule.get("id") or index) if isinstance(matched_rule, dict) else str(index),
                        rule_type="opa",
                        action="redact",
                        message=sanitize_text(
                            matched_rule.get("message") if isinstance(matched_rule, dict) else decision.reason
                        )
                        or sanitize_text(decision.reason)
                        or "OPA required redaction.",
                        context={"source": "opa_runtime"},
                    )
                )
            if adapter_result is None or adapter_result.modified_prompt == prompt:
                return EvaluationResult(
                    allowed=False,
                    modified_prompt=prompt,
                    violations=[
                        RuleViolation(
                            policy_id="opa",
                            rule_id="redaction_unavailable",
                            rule_type="opa",
                            action="deny",
                            message="OPA required redaction but no safe redacted prompt was available.",
                            context={"source": "opa_runtime"},
                        )
                    ],
                    action_taken="block",
                )
        return EvaluationResult(
            allowed=allowed,
            modified_prompt=adapter_result.modified_prompt if wants_redaction and adapter_result else prompt,
            violations=violations,
            action_taken=action_taken,
        )

    @classmethod
    def _normalize_policy_engine_mode(cls, value: str) -> str:
        mode = str(value or "python").lower()
        if mode not in cls.VALID_POLICY_ENGINE_MODES:
            return "python"
        return mode

    def _uses_compatibility_fallback(self) -> bool:
        return (
            self.runtime_mode == "COMPATIBILITY"
            or not self.strict_mode
            or not self.fail_closed
        )

    @staticmethod
    def _hybrid_mismatch(adapter_result: EvaluationResult, runtime_decision: OpaRuntimeDecision) -> str | None:
        if runtime_decision.runtime_status != OpaRuntimeStatus.OK:
            return None
        runtime_redaction = bool(runtime_decision.redaction_required or str(runtime_decision.action).lower() in {"redact", "warn"})
        if bool(adapter_result.allowed) != bool(runtime_decision.allowed):
            return "allowed_mismatch"
        if bool(adapter_result.action_taken == "block") != bool(str(runtime_decision.action).lower() in {"deny", "block"}):
            return "action_mismatch"
        if runtime_redaction and adapter_result.modified_prompt == "":
            return "redaction_unavailable"
        if bool(adapter_result.action_taken == "warn") != runtime_redaction and adapter_result.allowed:
            return "redaction_mismatch"
        return None

    @staticmethod
    def _hybrid_mismatch_decision(reason: str) -> OpaRuntimeDecision:
        return OpaRuntimeDecision(
            allowed=False,
            action="deny",
            reason=f"OPA/Python policy decision mismatch: {reason}.",
            matched_rules=[{"id": "hybrid_mismatch", "category": reason}],
            redaction_required=False,
            runtime_status=OpaRuntimeStatus.ERROR,
            error_category=OpaErrorCategory.HYBRID_MISMATCH,
            metadata={"error_category": OpaErrorCategory.HYBRID_MISMATCH.value, "source": "opa"},
        )

    @staticmethod
    def _decision_id(cache_key: str, policy_hash: str, decision: OpaRuntimeDecision) -> str:
        payload = {
            "cache_key": cache_key,
            "policy_hash": policy_hash,
            "decision": decision.as_dict(),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()

    @staticmethod
    def _publish_decision_event(tenant_id: uuid.UUID, api_key_id: uuid.UUID, result: OpaIntegrationResult) -> None:
        async def publish() -> None:
            try:
                from app.core.events.producer import producer

                await producer.publish_security_event(
                    PolicyEvaluatedEvent(
                        event_type="policy.opa_evaluated",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="INBOUND",
                        shadow_mode=False,
                        payload=result.audit_metadata(),
                    )
                )
            except Exception:
                return

        try:
            asyncio.create_task(publish())
        except RuntimeError:
            return


opa_decision_cache = OpaDecisionCache()
opa_runtime_metrics = OpaRuntimeMetrics()


def opa_runtime_health() -> dict[str, Any]:
    return OpaRuntimeIntegration.from_settings().health()
