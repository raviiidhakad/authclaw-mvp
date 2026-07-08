"""
AuthClaw AI Gateway Engine
--------------------------
Handles policy evaluation, provider routing, and audit logging for all
AI chat-completion requests proxied through the AuthClaw gateway.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.engine.audit import AuditEngine
from app.core.engine.evaluator import PolicyEngine
from app.core.policy.opa_integration import OpaRuntimeIntegration
from app.models.gateway_route import GatewayRoute
from app.models.policy import Policy
from app.models.provider import Provider, ProviderType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed response container — eliminates magic dict bugs
# ---------------------------------------------------------------------------

@dataclass
class ProviderResponse:
    """Typed result returned by AIProviderClient."""
    status_code: int          # Always an integer HTTP status
    body: Dict[str, Any]      # Parsed JSON body from provider
    provider_name: str        # Human-readable provider name
    provider_type: str        # ProviderType enum value
    latency_ms: int           # Wall-clock ms for the provider call

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def error_message(self) -> Optional[str]:
        err = self.body.get("error")
        if not err:
            return None
        if isinstance(err, dict):
            return err.get("message")
        return str(err)

    @property
    def error_type(self) -> Optional[str]:
        err = self.body.get("error")
        if isinstance(err, dict):
            return err.get("type")
        return None

    @property
    def error_code(self) -> Optional[str]:
        """Always returns a string or None — never an integer."""
        err = self.body.get("error")
        if isinstance(err, dict):
            code = err.get("code")
            if code is not None:
                return str(code)
        return None


@dataclass
class GatewayRouteResolution:
    """Resolved route/provider metadata for one gateway request."""
    provider: Provider
    route: GatewayRoute
    model: str
    redaction_mode: str


# ---------------------------------------------------------------------------
# Provider URL / payload routing
# ---------------------------------------------------------------------------

def _get_provider_url(provider: Provider) -> str:
    """Return the correct chat-completions URL for a given provider type."""
    custom_base = (provider.config or {}).get("base_url")
    if custom_base:
        return custom_base.rstrip("/") + "/chat/completions"

    routes: Dict[ProviderType, str] = {
        ProviderType.openai:      "https://api.openai.com/v1/chat/completions",
        ProviderType.anthropic:   "https://api.anthropic.com/v1/messages",
        ProviderType.gemini:      "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        ProviderType.cohere:      "https://api.cohere.ai/v1/chat",
        ProviderType.azure_openai: "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions?api-version=2024-02-01",
        ProviderType.groq:        "https://api.groq.com/openai/v1/chat/completions",
    }
    return routes.get(provider.type, "https://api.openai.com/v1/chat/completions")


def _build_headers(provider: Provider, api_key: str) -> Dict[str, str]:
    """Return provider-specific request headers."""
    if provider.type == ProviderType.anthropic:
        return {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
    # OpenAI-compatible (openai, gemini, cohere, azure_openai)
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _normalize_anthropic_response(body: Dict[str, Any]) -> Dict[str, Any]:
    """Convert Anthropic Messages API response to OpenAI-compatible format."""
    if "content" not in body:
        return body  # already an error or unknown format
    text_blocks = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
    return {
        "id": body.get("id", ""),
        "object": "chat.completion",
        "model": body.get("model", ""),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "\n".join(text_blocks)},
                "finish_reason": body.get("stop_reason", "stop"),
            }
        ],
        "usage": {
            "prompt_tokens": body.get("usage", {}).get("input_tokens", 0),
            "completion_tokens": body.get("usage", {}).get("output_tokens", 0),
            "total_tokens": (
                body.get("usage", {}).get("input_tokens", 0)
                + body.get("usage", {}).get("output_tokens", 0)
            ),
        },
    }


# ---------------------------------------------------------------------------
# AI Provider Client
# ---------------------------------------------------------------------------

class AIProviderClient:
    """Handles HTTP communication with upstream AI providers via Adapters."""

    async def get_provider_connection_details(self, provider: Provider) -> tuple[str, Dict[str, str]]:
        from app.core.providers.factory import ProviderAdapterFactory
        adapter = ProviderAdapterFactory.get_adapter(provider.type)
        return await adapter.get_connection_details(provider)

    async def chat_completion(
        self,
        provider: Provider,
        payload: Dict[str, Any],
    ) -> ProviderResponse:
        from app.core.providers.factory import ProviderAdapterFactory
        import time
        import httpx
        from fastapi import HTTPException
        import json

        adapter = ProviderAdapterFactory.get_adapter(provider.type)
        
        try:
            url, headers = await adapter.get_connection_details(provider)
        except Exception as exc:
            if isinstance(exc, HTTPException) and exc.status_code == 502:
                return ProviderResponse(
                    status_code=502,
                    body={"error": {"message": str(exc.detail), "type": "auth_error", "code": "azure_ad_unavailable"}},
                    provider_name=provider.name,
                    provider_type=provider.type.value,
                    latency_ms=0,
                )
            logger.error(
                "Failed to decrypt API key or fetch provider token.",
                extra={"provider_id": str(provider.id)},
            )
            return ProviderResponse(
                status_code=500,
                body={"error": {"message": "Gateway configuration error: cannot authenticate provider.", "type": "gateway_error", "code": "auth_failed"}},
                provider_name=provider.name,
                provider_type=provider.type.value,
                latency_ms=0,
            )

        request_payload = adapter.transform_request(payload)

        start_time = time.monotonic()
        status_code = 500
        body: Dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=request_payload, headers=headers)
                status_code = int(response.status_code)
                try:
                    raw_body = response.json()
                    if 200 <= status_code < 300:
                        body = adapter.transform_response(raw_body)
                    else:
                        body = adapter.normalize_error(status_code, response.text)
                except (ValueError, json.JSONDecodeError):
                    if 200 <= status_code < 300:
                        status_code = 502
                        body = {"error": {"message": "Provider returned non-JSON response.", "type": "parse_error", "code": "invalid_json"}}
                    else:
                        body = adapter.normalize_error(status_code, response.text)

        except httpx.ConnectError as exc:
            status_code = 502
            body = {"error": {"message": f"Cannot connect to provider: {exc}", "type": "connection_error", "code": "bad_gateway"}}
        except httpx.ReadTimeout:
            status_code = 504
            body = {"error": {"message": "Provider read timeout.", "type": "timeout_error", "code": "read_timeout"}}
        except httpx.WriteTimeout:
            status_code = 504
            body = {"error": {"message": "Provider write timeout.", "type": "timeout_error", "code": "write_timeout"}}
        except httpx.TimeoutException:
            status_code = 504
            body = {"error": {"message": "Provider request timed out.", "type": "timeout_error", "code": "timeout"}}
        except Exception as exc:
            logger.exception("Unexpected error calling provider %s", provider.id)
            status_code = 500
            body = {"error": {"message": "Internal gateway error while calling provider.", "type": "gateway_error", "code": "internal_error"}}

        latency_ms = int((time.monotonic() - start_time) * 1000)
        return ProviderResponse(
            status_code=status_code,
            body=body,
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Gateway Service
# ---------------------------------------------------------------------------

class GatewayService:
    """Main orchestrator for the AuthClaw AI Gateway."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.policy_engine = PolicyEngine()
        self.audit_engine = AuditEngine(db)
        self.ai_client = AIProviderClient()
        self.opa_integration = OpaRuntimeIntegration.from_settings()

    _SUPPORTED_ROUTE_REDACTION_MODES = {"NONE", "MASK", "HASH", "SYNTHETIC"}

    @staticmethod
    def _error_body(message: str, error_type: str, code: str) -> Dict[str, Any]:
        return {"error": {"message": message, "type": error_type, "code": code}}

    @staticmethod
    def _route_redaction_mode(route: GatewayRoute) -> str:
        value = getattr(getattr(route, "redaction", None), "value", None) or str(getattr(route, "redaction", "none"))
        mode = value.upper()
        return mode if mode in GatewayService._SUPPORTED_ROUTE_REDACTION_MODES else "UNSUPPORTED"

    @staticmethod
    def _hash_detections(text: str, detections: List[Dict[str, Any]]) -> str:
        result = text
        for detection in sorted(detections, key=lambda item: int(item.get("start", 0)), reverse=True):
            start = int(detection.get("start", 0))
            end = int(detection.get("end", 0))
            if start < 0 or end < start or end > len(text):
                continue
            entity_type = str(detection.get("entity_type", "PII")).upper()
            digest = hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()[:16]
            result = result[:start] + f"<HASHED_{entity_type}_{digest}>" + result[end:]
        return result

    @classmethod
    async def _apply_redaction(
        cls,
        text: str,
        detections: List[Dict[str, Any]],
        sanitized_text: str,
        route_mode: str,
        entity_actions: Dict[str, str],
        reversible_entities: List[str],
        tenant_id: str | uuid.UUID,
    ) -> tuple[str, str]:
        import hashlib
        import uuid
        from app.core.engine.pii import PIIRedactor
        from app.core.engine.token_vault import TokenVaultService

        requested_modes = {
            entity_actions.get(str(detection.get("entity_type", "")).upper(), "").upper()
            for detection in detections
        }
        mode = route_mode if route_mode in {"MASK", "HASH", "SYNTHETIC"} else ""
        if not mode:
            if "SYNTHETIC" in requested_modes:
                mode = "SYNTHETIC"
            elif "HASH" in requested_modes:
                mode = "HASH"
            else:
                mode = "MASK"

        has_reversible = any(str(d.get("entity_type", "")).upper() in reversible_entities for d in detections)
        if not has_reversible:
            if mode == "SYNTHETIC":
                return PIIRedactor.synthesize_detections(text, detections), mode
            if mode == "HASH":
                return cls._hash_detections(text, detections), mode
            return sanitized_text, "MASK"

        # Mixed pass: combine TokenVault and standard
        sorted_detections = sorted(detections, key=lambda item: int(item.get("start", 0)), reverse=True)
        result = text
        mappings = {}

        for idx, detection in enumerate(sorted_detections, start=1):
            start = int(detection.get("start", 0))
            end = int(detection.get("end", 0))
            if start < 0 or end < start or end > len(text):
                continue

            entity_type = str(detection.get("entity_type", "PII")).upper()
            original_value = text[start:end]

            if entity_type in reversible_entities:
                token_uuid = str(uuid.uuid4())
                placeholder = TokenVaultService.TOKEN_FORMAT.format(token_uuid=token_uuid)
                mappings[token_uuid] = original_value
                result = result[:start] + placeholder + result[end:]
            else:
                action = entity_actions.get(entity_type, mode)
                if action == "SYNTHETIC":
                    replacement = PIIRedactor.synthetic_value(entity_type, idx)
                elif action == "HASH":
                    digest = hashlib.sha256(original_value.encode("utf-8")).hexdigest()[:16]
                    replacement = f"<HASHED_{entity_type}_{digest}>"
                else:
                    replacement = f"[{entity_type}]"
                result = result[:start] + replacement + result[end:]

        if mappings:
            await TokenVaultService.store_batch(tenant_id, mappings)

        return result, mode

    @classmethod
    async def _detokenize_payload(cls, tenant_id: str | uuid.UUID, obj: Any) -> Any:
        from app.core.engine.token_vault import TokenVaultService
        if isinstance(obj, str):
            return await TokenVaultService.detokenize(tenant_id, obj)
        elif isinstance(obj, list):
            return [await cls._detokenize_payload(tenant_id, v) for v in obj]
        elif isinstance(obj, dict):
            return {k: await cls._detokenize_payload(tenant_id, v) for k, v in obj.items()}
        return obj

    async def _resolve_gateway_route(
        self,
        tenant_id: uuid.UUID,
        requested_model: str,
        route_id: Optional[uuid.UUID],
        route_name: Optional[str],
    ) -> tuple[Optional[GatewayRouteResolution], Optional[str], int, str]:
        route: Optional[GatewayRoute] = None
        explicit_route = bool(route_id or route_name)

        if route_id:
            result = await self.db.execute(
                select(GatewayRoute).where(GatewayRoute.tenant_id == tenant_id, GatewayRoute.id == route_id)
            )
            route = result.scalars().first()
        elif route_name:
            result = await self.db.execute(
                select(GatewayRoute).where(GatewayRoute.tenant_id == tenant_id, GatewayRoute.name == route_name)
            )
            route = result.scalars().first()
        else:
            result = await self.db.execute(
                select(GatewayRoute)
                .where(GatewayRoute.tenant_id == tenant_id, GatewayRoute.is_default == True)
                .order_by(GatewayRoute.created_at.asc())
            )
            route = result.scalars().first()

        if route is None:
            code = "route_not_found" if explicit_route else "no_default_route"
            message = "Gateway route not found." if explicit_route else "No default gateway route configured for this tenant."
            return None, code, 404 if explicit_route else 503, message
        if not route.is_active:
            return None, "route_disabled", 403, "Gateway route is disabled."
        if not route.provider_id:
            return None, "route_provider_missing", 503, "Gateway route has no provider configured."

        provider_result = await self.db.execute(
            select(Provider).where(
                Provider.tenant_id == tenant_id,
                Provider.id == route.provider_id,
                Provider.is_active == True,
            )
        )
        provider = provider_result.scalars().first()
        if not provider:
            return None, "route_provider_unavailable", 503, "Gateway route provider is unavailable."

        redaction_mode = self._route_redaction_mode(route)
        if redaction_mode == "UNSUPPORTED":
            return None, "unsupported_redaction_mode", 400, "Gateway route redaction mode is not supported."

        route_config = route.config or {}
        model = str(route_config.get("model") or route_config.get("default_model") or requested_model)
        return GatewayRouteResolution(provider=provider, route=route, model=model, redaction_mode=redaction_mode), None, 200, ""

    async def _log_safe_error(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        api_key_id: uuid.UUID,
        provider_id: Optional[uuid.UUID],
        model: str,
        payload: Dict[str, Any],
        modified_payload: Optional[Dict[str, Any]],
        status_code: int,
        message: str,
        error_type: str,
        error_code: str,
        evaluation_result: Any = None,
    ) -> None:
        try:
            await self.audit_engine.log_request(
                tenant_id=tenant_id,
                user_id=user_id,
                provider_id=provider_id,
                api_key_id=api_key_id,
                model=model,
                original_payload=payload,
                modified_payload=modified_payload or payload,
                response_payload=self._error_body(message, error_type, error_code),
                tokens_prompt=0,
                tokens_completion=0,
                latency_ms=0,
                status_code=status_code,
                error_message=message,
                error_type=error_type,
                error_code=error_code,
                evaluation_result=evaluation_result,
            )
        except Exception as exc:
            logger.warning("Failed to write safe gateway error audit record: %s", exc)

    # ── Main entrypoint ─────────────────────────────────────────────────────

    async def process_chat_request(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        api_key_id: uuid.UUID,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Full gateway flow:
        1. Extract prompt + model
        2. Load + evaluate policies
        3. If blocked → log + return 403
        4. Rebuild payload if redacted
        5. Select provider
        6. Forward to provider
        7. Log audit trail
        8. Return response
        """
        model: str = str(payload.get("model", "gpt-3.5-turbo"))
        messages: List[Dict[str, Any]] = payload.get("messages", [])
        route_id: Optional[uuid.UUID] = None
        if payload.get("route_id"):
            try:
                route_id = uuid.UUID(str(payload.get("route_id")))
            except ValueError:
                message = "Gateway route_id must be a valid UUID."
                await self._log_safe_error(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    provider_id=None,
                    model=model,
                    payload=payload,
                    modified_payload=None,
                    status_code=400,
                    message=message,
                    error_type="configuration_error",
                    error_code="route_id_invalid",
                )
                return {
                    "status_code": 400,
                    "data": self._error_body(message, "configuration_error", "route_id_invalid"),
                }
        route_name = payload.get("route_name") or payload.get("route")
        route_name = str(route_name) if route_name else None
        resolution, route_error, route_status, route_message = await self._resolve_gateway_route(
            tenant_id=tenant_id,
            requested_model=model,
            route_id=route_id,
            route_name=route_name,
        )
        if route_error or resolution is None:
            await self._log_safe_error(
                tenant_id=tenant_id,
                user_id=user_id,
                api_key_id=api_key_id,
                provider_id=None,
                model=model,
                payload=payload,
                modified_payload=None,
                status_code=route_status,
                message=route_message,
                error_type="configuration_error",
                error_code=route_error or "route_resolution_failed",
            )
            return {
                "status_code": route_status,
                "data": self._error_body(
                    route_message,
                    "configuration_error",
                    route_error or "route_resolution_failed",
                ),
            }

        active_route = resolution.route
        provider = resolution.provider
        model = resolution.model
        route_redaction_mode = resolution.redaction_mode
        route_config = active_route.config or {}
        route_policy_id = route_config.get("policy_id")
        route_attached_policies: Optional[List[Policy]] = None
        if route_policy_id:
            try:
                policy_uuid = uuid.UUID(str(route_policy_id))
                policy_result = await self.db.execute(
                    select(Policy)
                    .options(selectinload(Policy.rules))
                    .where(
                        Policy.id == policy_uuid,
                        Policy.tenant_id == tenant_id,
                        Policy.is_active == True,
                    )
                )
                route_policy = policy_result.scalars().first()
                if not route_policy:
                    raise RuntimeError("route policy unavailable")
                route_attached_policies = [route_policy]
            except Exception:
                message = "Gateway route policy is unavailable or disabled."
                await self._log_safe_error(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    provider_id=provider.id,
                    model=model,
                    payload=payload,
                    modified_payload=None,
                    status_code=503,
                    message=message,
                    error_type="security_pipeline_error",
                    error_code="route_policy_unavailable",
                )
                return {
                    "status_code": 503,
                    "data": self._error_body(message, "security_pipeline_error", "route_policy_unavailable"),
                }

        # Flatten all user messages to a single string for policy evaluation
        full_prompt = "\n".join(
            m.get("content", "")
            for m in messages
            if isinstance(m.get("content"), str)
        )
        original_full_prompt = full_prompt

        # ── Sprint 1: Inbound Security Pipeline ─────────────────────────────
        security_scan_count_inbound = 0
        if settings.FF_SECURITY_PIPELINE and settings.FF_INBOUND_SCAN:
            try:
                from app.core.detection.presidio_engine import presidio_engine
                from app.core.detection.classification import classifier
                from app.core.policy.cache import policy_cache
                from app.core.policy.evaluator import evaluator as policy_evaluator
                from app.schemas.security_events import (
                    PIIDetectedEvent, PHIDetectedEvent,
                    ContentRedactedEvent, RequestBlockedEvent,
                    PolicyEvaluatedEvent,
                )
                from app.core.events.producer import producer as event_producer

                # Use route-attached policy when configured; otherwise fall back to tenant compiled policy.
                compiled_policy = (
                    policy_cache.compile_policies(route_attached_policies)
                    if route_attached_policies is not None
                    else await policy_cache.get(tenant_id, self.db)
                )
                classification_overrides = compiled_policy.get("classification_overrides", {})

                # Run Presidio analysis
                scan_result = await presidio_engine.scan(full_prompt)
                security_scan_count_inbound = len(scan_result.detections)

                # Run embedded policy evaluation
                decision = policy_evaluator.evaluate(
                    detections=scan_result.detections,
                    text=full_prompt,
                    compiled_policy=compiled_policy,
                    shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                )

                if scan_result.has_detections or decision.keyword_hits:
                    entity_types = scan_result.entity_types
                    max_risk = classifier.max_risk(entity_types, classification_overrides) if entity_types else None

                    phi_entities = [et for et in entity_types if et.startswith("PHI_")]
                    pii_entities = [et for et in entity_types if not et.startswith("PHI_")]

                    detection_payload = {
                        "entity_types": entity_types,
                        "max_risk_level": max_risk.value if max_risk else "UNKNOWN",
                        "detection_count": security_scan_count_inbound,
                        "latency_presidio_ms": scan_result.latency_ms,
                        "policy_action": decision.action.value,
                        "shadow_mode": settings.FF_SECURITY_SHADOW_MODE,
                        "keyword_hits": decision.keyword_hits,
                    }

                    # Emit PII/PHI detection events (fire-and-forget)
                    if pii_entities:
                        asyncio.create_task(event_producer.publish_security_event(
                            PIIDetectedEvent(
                                event_type="prompt.pii_detected",
                                tenant_id=str(tenant_id),
                                request_id=str(api_key_id),
                                direction="INBOUND",
                                shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                                payload={**detection_payload, "pii_entities": pii_entities},
                            )
                        ))

                    if phi_entities:
                        asyncio.create_task(event_producer.publish_security_event(
                            PHIDetectedEvent(
                                event_type="prompt.phi_detected",
                                tenant_id=str(tenant_id),
                                request_id=str(api_key_id),
                                direction="INBOUND",
                                shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                                payload={**detection_payload, "phi_entities": phi_entities},
                            )
                        ))

                    # Emit policy evaluation audit event
                    asyncio.create_task(event_producer.publish_security_event(
                        PolicyEvaluatedEvent(
                            event_type="policy.evaluated",
                            tenant_id=str(tenant_id),
                            request_id=str(api_key_id),
                            direction="INBOUND",
                            shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                            payload={
                                "policies_evaluated": 1,
                                "rules_evaluated": len(compiled_policy.get("entity_actions", {})),
                                "violations_found": len(decision.violations),
                                "evaluation_ms": scan_result.latency_ms,
                                "action": decision.action.value,
                            },
                        )
                    ))

                    # Enforcement (skipped in shadow mode)
                    if decision.should_block:
                        asyncio.create_task(event_producer.publish_security_event(
                            RequestBlockedEvent(
                                event_type="request.blocked",
                                tenant_id=str(tenant_id),
                                request_id=str(api_key_id),
                                direction="INBOUND",
                                shadow_mode=False,
                                payload={
                                    "block_reason": decision.block_reason,
                                    "entity_types": entity_types,
                                    "keyword_hits": decision.keyword_hits,
                                },
                            )
                        ))
                        from app.core.engine.evaluator import EvaluationResult, RuleViolation
                        _rule_message: Optional[str] = None
                        if route_attached_policies and decision.keyword_hits:
                            for _pol in route_attached_policies:
                                for _rule in (_pol.rules or []):
                                    _rule_kws = (_rule.conditions or {}).get("keywords", [])
                                    if any(kw in decision.keyword_hits for kw in _rule_kws):
                                        _rule_message = _rule.message or None
                                        break
                                if _rule_message:
                                    break
                        _block_reason = _rule_message or decision.block_reason or "Blocked by policy."
                        _inbound_eval = EvaluationResult(
                            allowed=False,
                            modified_prompt=full_prompt,
                            action_taken="block",
                            violations=[
                                RuleViolation(
                                    policy_id=None,
                                    rule_id=None,
                                    rule_type="content_filter",
                                    action="block",
                                    message=_block_reason,
                                    context={"keyword_hits": decision.keyword_hits},
                                )
                            ],
                        )
                        await self.audit_engine.log_request(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            provider_id=provider.id,
                            api_key_id=api_key_id,
                            model=model,
                            original_payload=payload,
                            modified_payload=payload,
                            response_payload={"error": {"message": "Request blocked.", "code": 403}},
                            tokens_prompt=0,
                            tokens_completion=0,
                            latency_ms=0,
                            status_code=403,
                            error_message="Blocked by policy: " + _block_reason,
                            error_type="policy_violation",
                            error_code="blocked",
                            evaluation_result=_inbound_eval,
                        )
                        return {
                            "status_code": 403,
                            "data": {
                                "error": {
                                    "message": "Request blocked by AuthClaw security policy.",
                                    "type": "security_policy_violation",
                                    "code": 403,
                                    "block_reason": _block_reason,
                                }
                            },
                        }

                    if decision.should_redact and scan_result.detections:
                        entity_actions = compiled_policy.get("entity_actions", {})
                        reversible_entities = compiled_policy.get("reversible_entities", [])
                        transformed_prompt, redaction_mode = await self._apply_redaction(
                            full_prompt,
                            scan_result.detections,
                            scan_result.sanitized_text,
                            route_redaction_mode,
                            entity_actions,
                            reversible_entities,
                            tenant_id,
                        )
                        asyncio.create_task(event_producer.publish_security_event(
                            ContentRedactedEvent(
                                event_type="prompt.redacted",
                                tenant_id=str(tenant_id),
                                request_id=str(api_key_id),
                                direction="INBOUND",
                                shadow_mode=False,
                                payload={
                                    "redaction_mode": redaction_mode,
                                    "entities_redacted": decision.redact_entities,
                                    "entity_count": len(decision.redact_entities),
                                },
                            )
                        ))
                        messages = [
                            {**m, "content": transformed_prompt} if m.get("role") == "user" else m
                            for m in messages
                        ]
                        full_prompt = transformed_prompt

            except Exception as security_exc:
                logger.error("Inbound security pipeline error (failing closed): %s", security_exc, exc_info=True)
                message = "Gateway security scan failed before provider egress."
                await self._log_safe_error(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    provider_id=provider.id,
                    model=model,
                    payload=payload,
                    modified_payload=None,
                    status_code=503,
                    message=message,
                    error_type="security_pipeline_error",
                    error_code="inbound_security_failed",
                )
                return {
                    "status_code": 503,
                    "data": self._error_body(message, "security_pipeline_error", "inbound_security_failed"),
                }




        # ── 1. Load active policies ─────────────────────────────────────
        try:
            if route_attached_policies is not None:
                policies = route_attached_policies
            else:
                policy_result = await self.db.execute(
                    select(Policy)
                    .options(selectinload(Policy.rules))
                    .where(Policy.tenant_id == tenant_id, Policy.is_active == True)
                )
                policies = list(policy_result.scalars().all())

        # ── 2. Evaluate policies ────────────────────────────────────────
            authoritative_decision = await self.opa_integration.evaluate_authoritative(
                prompt=full_prompt,
                tenant_id=tenant_id,
                api_key_id=api_key_id,
                route=active_route,
                provider=provider,
                model=model,
                policies=policies,
                request_metadata={"stream": bool(payload.get("stream", False))},
            )
            eval_result = authoritative_decision.evaluation_result
        except Exception as policy_exc:
            logger.error("Gateway policy evaluation failed closed: %s", policy_exc)
            message = "Gateway policy evaluation failed before provider egress."
            await self._log_safe_error(
                tenant_id=tenant_id,
                user_id=user_id,
                api_key_id=api_key_id,
                provider_id=provider.id,
                model=model,
                payload=payload,
                modified_payload=None,
                status_code=503,
                message=message,
                error_type="security_pipeline_error",
                error_code="policy_evaluation_failed",
            )
            return {
                "status_code": 503,
                "data": self._error_body(message, "security_pipeline_error", "policy_evaluation_failed"),
            }

        # ── 3. Blocked? ─────────────────────────────────────────────────
        policy_decision_metadata = {
            "policy_ids": [str(policy.id) for policy in policies],
            "route_policy_id": str(route_policy_id) if route_policy_id else None,
            "action": eval_result.action_taken,
            "matched_rule_count": len(eval_result.violations),
        }
        policy_decision_metadata.update(authoritative_decision.metadata())

        if not eval_result.allowed:
            logger.info("Gateway blocked request for tenant=%s: %s", tenant_id, [v.message for v in eval_result.violations])
            await self.audit_engine.log_request(
                tenant_id=tenant_id,
                user_id=user_id,
                provider_id=None,
                api_key_id=api_key_id,
                model=model,
                original_payload=payload,
                modified_payload=payload,
                response_payload={"error": "Blocked by AuthClaw policy.", "policy_decision": policy_decision_metadata},
                tokens_prompt=0,
                tokens_completion=0,
                latency_ms=0,
                status_code=403,
                error_message="Blocked by policy: " + "; ".join(v.message for v in eval_result.violations),
                error_type="policy_violation",
                error_code="blocked",
                evaluation_result=eval_result,
            )
            return {
                "status_code": 403,
                "data": {
                    "error": {
                        "message": "Request blocked by AuthClaw security policy.",
                        "type": "policy_violation",
                        "code": 403,
                        "violations": [v.message for v in eval_result.violations],
                    }
                },
            }

        # ── 4. Rebuild payload if prompt was redacted ────────────────────
        modified_payload = dict(payload)
        if full_prompt != original_full_prompt:
            modified_payload["messages"] = [
                {**msg, "content": full_prompt} if msg.get("role") == "user" else msg
                for msg in messages
            ]
        elif eval_result.modified_prompt != full_prompt:
            new_messages = []
            for msg in messages:
                if msg.get("role") == "user":
                    msg_eval = self.policy_engine.evaluate(str(msg.get("content", "")), policies)
                    new_messages.append({**msg, "content": msg_eval.modified_prompt})
                else:
                    new_messages.append(msg)
            modified_payload["messages"] = new_messages
        modified_payload["model"] = model

        # ── 5. Select provider ───────────────────────────────────────────
        # Provider was resolved from the selected gateway route before security evaluation.
        if not provider:
            logger.warning("No active provider for tenant=%s", tenant_id)
            await self.audit_engine.log_request(
                tenant_id=tenant_id,
                user_id=user_id,
                provider_id=None,
                api_key_id=api_key_id,
                model=model,
                original_payload=payload,
                modified_payload=modified_payload,
                response_payload={},
                tokens_prompt=0,
                tokens_completion=0,
                latency_ms=0,
                status_code=503,
                error_message=(
                    "Route provider unavailable."
                    if route_error == "route_provider_unavailable"
                    else "No active AI provider configured for this tenant."
                ),
                error_type="configuration_error",
                error_code=route_error or "no_provider",
                evaluation_result=eval_result,
            )
            return {
                "status_code": 503,
                "data": {
                    "error": {
                        "message": (
                            "Route provider unavailable."
                            if route_error == "route_provider_unavailable"
                            else "No active AI provider configured for this tenant."
                        ),
                        "type": "configuration_error",
                        "code": route_error or "no_provider",
                    }
                },
            }

        # ── 6. Forward to provider ───────────────────────────────────────
        
        # Check if streaming is requested
        is_stream = payload.get("stream", False)
        
        # Strip internal fields that upstream providers reject
        streaming_mode = modified_payload.pop("streaming_mode", "buffered")
        modified_payload.pop("provider", None)
        modified_payload.pop("route", None)
        modified_payload.pop("route_id", None)
        modified_payload.pop("route_name", None)

        try:
            from app.core.rate_limit.limiter import check_gateway_limits

            await check_gateway_limits(
                str(tenant_id),
                str(api_key_id),
                self.db,
                provider_id=str(provider.id),
                route_id=str(active_route.id),
                model=str(model),
                include_base=False,
            )
        except Exception as rate_limit_exc:
            from fastapi import HTTPException

            if isinstance(rate_limit_exc, HTTPException) and rate_limit_exc.status_code == 429:
                await self._log_safe_error(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    provider_id=provider.id,
                    model=model,
                    payload=payload,
                    modified_payload=modified_payload,
                    status_code=429,
                    message="Rate limit exceeded. Please retry later.",
                    error_type="rate_limit_exceeded",
                    error_code="gateway_rate_limited",
                    evaluation_result=eval_result,
                )
                return {
                    "status_code": 429,
                    "data": self._error_body(
                        "Rate limit exceeded. Please retry later.",
                        "rate_limit_exceeded",
                        "gateway_rate_limited",
                    ),
                }
            logger.error("Gateway rate limit check failed closed before provider egress: %s", rate_limit_exc)
            return {
                "status_code": 503,
                "data": self._error_body(
                    "Gateway rate limit service unavailable.",
                    "rate_limit_unavailable",
                    "rate_limit_unavailable",
                ),
            }
        
        if is_stream:
            if streaming_mode == "passthrough":
                message = "Gateway passthrough streaming is disabled because it bypasses security filtering."
                await self._log_safe_error(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    provider_id=provider.id,
                    model=model,
                    payload=payload,
                    modified_payload=modified_payload,
                    status_code=400,
                    message=message,
                    error_type="security_configuration_error",
                    error_code="passthrough_streaming_disabled",
                    evaluation_result=eval_result,
                )
                return {
                    "status_code": 400,
                    "data": self._error_body(message, "security_configuration_error", "passthrough_streaming_disabled"),
                }
            if streaming_mode not in {"buffered", "strict", "safe"}:
                message = "Gateway streaming mode is unsupported. Use strict safe streaming or non-streaming requests."
                await self._log_safe_error(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    provider_id=provider.id,
                    model=model,
                    payload=payload,
                    modified_payload=modified_payload,
                    status_code=400,
                    message=message,
                    error_type="security_configuration_error",
                    error_code="streaming_mode_unsupported",
                    evaluation_result=eval_result,
                )
                return {
                    "status_code": 400,
                    "data": self._error_body(message, "security_configuration_error", "streaming_mode_unsupported"),
                }

            else:
                from app.core.providers.factory import ProviderAdapterFactory
                from fastapi import HTTPException
                
                adapter = ProviderAdapterFactory.get_adapter(provider.type)
                if not callable(getattr(adapter, "stream_response", None)):
                    message = "Selected provider adapter does not support safe streaming."
                    await self._log_safe_error(
                        tenant_id=tenant_id,
                        user_id=user_id,
                        api_key_id=api_key_id,
                        provider_id=provider.id,
                        model=model,
                        payload=payload,
                        modified_payload=modified_payload,
                        status_code=400,
                        message=message,
                        error_type="security_configuration_error",
                        error_code="safe_streaming_unsupported",
                        evaluation_result=eval_result,
                    )
                    return {
                        "status_code": 400,
                        "data": self._error_body(message, "security_configuration_error", "safe_streaming_unsupported"),
                    }
                
                try:
                    url, headers = await adapter.get_connection_details(provider)
                except HTTPException as e:
                    return {
                        "status_code": e.status_code,
                        "data": {"error": {"message": str(e.detail), "code": "auth_error"}}
                    }
                except Exception:
                    return {
                        "status_code": 500,
                        "data": {"error": {"message": "Gateway configuration error: cannot authenticate provider.", "code": "auth_failed"}}
                    }
                    
                from app.core.engine.streaming import StreamingEngine
                import json
                from fastapi.responses import StreamingResponse

                streaming_engine = StreamingEngine(self.audit_engine, db=self.db)
                streaming_response = await streaming_engine.stream_response(
                    tenant_id=tenant_id,
                    api_key_id=api_key_id,
                    provider_id=provider.id,
                    url=url,
                    headers=headers,
                    payload=modified_payload,
                    provider_name=provider.name,
                    streaming_mode=streaming_mode,
                    adapter=adapter
                )

                async def detokenize_generator(original_iterator):
                    async for chunk in original_iterator:
                        chunk_str = chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk)
                        
                        if not chunk_str.startswith("data: "):
                            yield chunk_str
                            continue
                            
                        data_str = chunk_str[len("data: "):].strip()
                        if data_str == "[DONE]":
                            yield chunk_str
                            continue
                            
                        try:
                            data_json = json.loads(data_str)
                            data_json = await self._detokenize_payload(tenant_id, data_json)
                            yield f"data: {json.dumps(data_json, separators=(',', ':'))}\n\n"
                        except Exception as e:
                            logger.error("Outbound streaming detokenization failed: %s", e)
                            # Fail closed: yield original chunk to keep token encrypted
                            yield chunk_str

                return {
                    "status_code": 200,
                    "response": StreamingResponse(
                        detokenize_generator(streaming_response.body_iterator),
                        status_code=streaming_response.status_code,
                        headers=dict(streaming_response.headers),
                        media_type=streaming_response.media_type
                    )
                }

        # Synchronous execution
        provider_resp: ProviderResponse = await self.ai_client.chat_completion(provider, modified_payload)
        logger.info(
            "Provider=%s type=%s status=%d latency=%dms",
            provider.name, provider.type.value, provider_resp.status_code, provider_resp.latency_ms,
        )

        # Extract token usage (OpenAI-compatible)
        usage = provider_resp.body.get("usage", {})
        tokens_prompt = int(usage.get("prompt_tokens", 0))
        tokens_completion = int(usage.get("completion_tokens", 0))

        # ── Sprint 1: Outbound Security Pipeline ────────────────────────────
        security_scan_count_outbound = 0
        outbound_response_body = provider_resp.body
        final_status_code = provider_resp.status_code
        if settings.FF_SECURITY_PIPELINE and settings.FF_OUTBOUND_SCAN and provider_resp.is_success:
            try:
                from app.core.detection.presidio_engine import presidio_engine
                from app.core.detection.classification import classifier
                from app.core.policy.cache import policy_cache
                from app.schemas.security_events import (
                    PIIDetectedEvent, PHIDetectedEvent,
                    ContentRedactedEvent, ResponseBlockedEvent,
                )
                from app.core.events.producer import producer as event_producer

                # Extract completion text
                completion_text = ""
                choices = provider_resp.body.get("choices", [])
                if choices:
                    completion_text = choices[0].get("message", {}).get("content", "") or ""

                if completion_text:
                    compiled_policy = await policy_cache.get(tenant_id, self.db)
                    entity_actions = compiled_policy.get("entity_actions", {})
                    classification_overrides = compiled_policy.get("classification_overrides", {})

                    scan_result = await presidio_engine.scan(completion_text)
                    security_scan_count_outbound = len(scan_result.detections)

                    if scan_result.has_detections:
                        entity_types = scan_result.entity_types
                        max_risk = classifier.max_risk(entity_types, classification_overrides)
                        phi_entities = [et for et in entity_types if et.startswith("PHI_")]
                        pii_entities = [et for et in entity_types if not et.startswith("PHI_")]

                        detection_payload = {
                            "entity_types": entity_types,
                            "max_risk_level": max_risk.value if max_risk else "UNKNOWN",
                            "detection_count": security_scan_count_outbound,
                            "latency_presidio_ms": scan_result.latency_ms,
                            "shadow_mode": settings.FF_SECURITY_SHADOW_MODE,
                        }

                        if pii_entities:
                            asyncio.create_task(event_producer.publish_security_event(
                                PIIDetectedEvent(
                                    event_type="completion.pii_detected",
                                    tenant_id=str(tenant_id),
                                    request_id=str(api_key_id),
                                    direction="OUTBOUND",
                                    shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                                    payload={**detection_payload, "pii_entities": pii_entities},
                                )
                            ))

                        if phi_entities:
                            asyncio.create_task(event_producer.publish_security_event(
                                PHIDetectedEvent(
                                    event_type="completion.phi_detected",
                                    tenant_id=str(tenant_id),
                                    request_id=str(api_key_id),
                                    direction="OUTBOUND",
                                    shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                                    payload={**detection_payload, "phi_entities": phi_entities},
                                )
                            ))

                        if not settings.FF_SECURITY_SHADOW_MODE:
                            blocked_entities = [
                                et for et in entity_types if entity_actions.get(et) == "BLOCK"
                            ]
                            if blocked_entities:
                                asyncio.create_task(event_producer.publish_security_event(
                                    ResponseBlockedEvent(
                                        event_type="response.blocked",
                                        tenant_id=str(tenant_id),
                                        request_id=str(api_key_id),
                                        direction="OUTBOUND",
                                        shadow_mode=False,
                                        payload={
                                            "block_reason": f"Completion blocked: entity types {blocked_entities} in response.",
                                            "entity_types": blocked_entities,
                                        },
                                    )
                                ))
                                # Replace response body with error — provider was already called
                                outbound_response_body = {
                                    "error": {
                                        "message": "Response blocked by AuthClaw security policy.",
                                        "type": "security_policy_violation",
                                        "code": "response_blocked",
                                    }
                                }
                                final_status_code = 403
                            else:
                                # Redact completion and patch back into body
                                sanitized_body = dict(provider_resp.body)
                                if choices:
                                    new_choices = list(choices)
                                    new_choices[0] = dict(choices[0])
                                    new_choices[0]["message"] = {
                                        **choices[0].get("message", {}),
                                        "content": scan_result.sanitized_text,
                                    }
                                    sanitized_body["choices"] = new_choices
                                outbound_response_body = sanitized_body
                                asyncio.create_task(event_producer.publish_security_event(
                                    ContentRedactedEvent(
                                        event_type="completion.redacted",
                                        tenant_id=str(tenant_id),
                                        request_id=str(api_key_id),
                                        direction="OUTBOUND",
                                        shadow_mode=False,
                                        payload={
                                            "redaction_mode": "MASK",
                                            "entities_redacted": entity_types,
                                            "entity_count": security_scan_count_outbound,
                                        },
                                    )
                                ))
            except Exception as security_exc:
                logger.error("Outbound security pipeline error (failing closed): %s", security_exc, exc_info=True)
                outbound_response_body = self._error_body(
                    "Gateway response security scan failed. Upstream response was not released.",
                    "security_pipeline_error",
                    "outbound_security_failed",
                )
                final_status_code = 502

        # ── 7. Log audit trail ───────────────────────────────────────────
        final_error = outbound_response_body.get("error") if isinstance(outbound_response_body, dict) else None
        final_error_message = provider_resp.error_message
        final_error_type = provider_resp.error_type
        final_error_code = provider_resp.error_code
        if final_status_code >= 400 and isinstance(final_error, dict):
            final_error_message = final_error.get("message")
            final_error_type = final_error.get("type")
            final_error_code = str(final_error.get("code")) if final_error.get("code") is not None else None

        await self.audit_engine.log_request(
            tenant_id=tenant_id,
            user_id=user_id,
            provider_id=provider.id,
            api_key_id=api_key_id,
            model=model,
            original_payload=payload,
            modified_payload=modified_payload,
            response_payload=outbound_response_body,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            latency_ms=provider_resp.latency_ms,
            status_code=final_status_code,
            error_message=final_error_message,
            error_type=final_error_type,
            error_code=final_error_code,
            evaluation_result=eval_result,
        )

        # ── 7b. Publish gateway analytics event to Kafka ─────────────────
        # Fire-and-forget: a Kafka failure must NEVER surface as a client error.
        # This event feeds the real-time analytics pipeline and dashboards.
        try:
            from app.core.events.producer import producer
            from app.schemas.events import GatewayEvent

            gw_event = GatewayEvent(
                event_type=(
                    "gateway.request.completed"
                    if 200 <= final_status_code < 300
                    else "gateway.request.error"
                ),
                tenant_id=str(tenant_id),
                # api_key_id serves as the per-request correlation handle;
                # a dedicated request_id will be added when the gateway
                # request model exposes a stable UUID field.
                request_id=str(api_key_id),
                provider=provider.name if provider else None,
                model=model,
                status=final_status_code,
                latency_ms=provider_resp.latency_ms,
                tokens_prompt=tokens_prompt,
                tokens_completion=tokens_completion,
                timestamp=datetime.utcnow().isoformat() + "Z",
                payload={
                    "error_type": provider_resp.error_type,
                    # Sprint 1: security event counts for real-time dashboards
                    "security_events_inbound": security_scan_count_inbound,
                    "security_events_outbound": security_scan_count_outbound,
                    "policy_decision": policy_decision_metadata,
                },
            )
            await producer.publish("authclaw.gateway.events", gw_event)
        except Exception:
            # Intentionally swallowed — event publishing is best-effort.
            # Operators should monitor the dead-letter topic and Kafka
            # producer error counters separately.
            pass

        # ── 8. Detokenize outbound response ──────────────────────────────────
        try:
            final_response_body = await self._detokenize_payload(tenant_id, outbound_response_body)
        except Exception as detok_exc:
            import logging
            logging.getLogger(__name__).error("Synchronous detokenization failed closed: %s", detok_exc)
            final_response_body = outbound_response_body

        # ── 9. Return response ───────────────────────────────────────────
        return {
            "status_code": final_status_code,
            "data": final_response_body,
        }

