"""
AuthClaw AI Gateway Engine
--------------------------
Handles policy evaluation, provider routing, and audit logging for all
AI chat-completion requests proxied through the AuthClaw gateway.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.engine.audit import AuditEngine
from app.core.engine.evaluator import PolicyEngine
from app.core.engine.token_vault import TokenVaultService
from app.core.policy.opa_integration import OpaRuntimeIntegration
from app.core.providers.client import AIProviderClient, ProviderResponse
from app.models.gateway_route import GatewayRoute
from app.models.policy import Policy
from app.models.provider import Provider

logger = logging.getLogger(__name__)


@dataclass
class GatewayRouteResolution:
    """Resolved route/provider metadata for one gateway request."""
    provider: Provider
    route: GatewayRoute
    model: str
    redaction_mode: str


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
                await self.audit_engine.log_safe_gateway_error(
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
            await self.audit_engine.log_safe_gateway_error(
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
                await self.audit_engine.log_safe_gateway_error(
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
                        return {
                            "status_code": 403,
                            "data": {
                                "error": {
                                    "message": "Request blocked by AuthClaw security policy.",
                                    "type": "security_policy_violation",
                                    "code": 403,
                                    "block_reason": decision.block_reason,
                                }
                            },
                        }

                    if decision.should_redact and scan_result.detections:
                        entity_actions = compiled_policy.get("entity_actions", {})
                        reversible_entities = compiled_policy.get("reversible_entities", [])
                        transformed_prompt, redaction_mode = await TokenVaultService.apply_redaction(
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
                await self.audit_engine.log_safe_gateway_error(
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
            await self.audit_engine.log_safe_gateway_error(
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
                await self.audit_engine.log_safe_gateway_error(
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
                await self.audit_engine.log_safe_gateway_error(
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
                await self.audit_engine.log_safe_gateway_error(
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
                    await self.audit_engine.log_safe_gateway_error(
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
                    
                from app.core.engine.streaming import StreamingEngine, detokenize_sse_chunks
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

                return {
                    "status_code": 200,
                    "response": StreamingResponse(
                        detokenize_sse_chunks(tenant_id, streaming_response.body_iterator),
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
            final_response_body = await TokenVaultService.detokenize_payload(tenant_id, outbound_response_body)
        except Exception as detok_exc:
            import logging
            logging.getLogger(__name__).error("Synchronous detokenization failed closed: %s", detok_exc)
            final_response_body = outbound_response_body

        # ── 9. Return response ───────────────────────────────────────────
        return {
            "status_code": final_status_code,
            "data": final_response_body,
        }

