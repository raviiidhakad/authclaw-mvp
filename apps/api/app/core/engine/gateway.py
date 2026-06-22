"""
AuthClaw AI Gateway Engine
--------------------------
Handles policy evaluation, provider routing, and audit logging for all
AI chat-completion requests proxied through the AuthClaw gateway.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.encryption import decrypt_value
from app.core.engine.audit import AuditEngine
from app.core.engine.evaluator import PolicyEngine
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
            logger.error("Failed to decrypt API key or fetch token for provider %s: %s", provider.id, exc)
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
                        body = {"error": {"message": f"Provider returned non-JSON response (HTTP {status_code})", "type": "parse_error", "code": "invalid_json"}}
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
            body = {"error": {"message": f"Internal gateway error: {exc}", "type": "gateway_error", "code": "internal_error"}}

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

    # ── Provider selection ──────────────────────────────────────────────────

    async def _select_provider(self, tenant_id: uuid.UUID) -> Optional[Provider]:
        """
        Deterministic provider selection:
        1. Active provider with is_default=True   (future)
        2. Active provider, oldest created first  (most stable / manually configured)
        3. None → 503
        """
        result = await self.db.execute(
            select(Provider)
            .where(Provider.tenant_id == tenant_id, Provider.is_active == True)
            .order_by(Provider.created_at.asc())   # oldest = intentionally configured
        )
        providers = result.scalars().all()
        if not providers:
            return None
        # Prefer providers whose name does NOT contain "bad" or "mock" (heuristic for test env)
        # In production every provider is real — this just improves local dev experience.
        preferred = [p for p in providers if "bad" not in p.name.lower() and "mock" not in p.name.lower()]
        return preferred[0] if preferred else providers[0]

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

        # Flatten all user messages to a single string for policy evaluation
        full_prompt = "\n".join(
            m.get("content", "")
            for m in messages
            if isinstance(m.get("content"), str)
        )

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
                    PolicyViolationEvent, PolicyEvaluatedEvent,
                )
                from app.core.events.producer import producer as event_producer

                # Fetch compiled policy from Redis cache (sub-ms on warm path)
                compiled_policy = await policy_cache.get(tenant_id, self.db)
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

                    if decision.should_redact and scan_result.sanitized_text != full_prompt:
                        asyncio.create_task(event_producer.publish_security_event(
                            ContentRedactedEvent(
                                event_type="prompt.redacted",
                                tenant_id=str(tenant_id),
                                request_id=str(api_key_id),
                                direction="INBOUND",
                                shadow_mode=False,
                                payload={
                                    "redaction_mode": "MASK",
                                    "entities_redacted": decision.redact_entities,
                                    "entity_count": len(decision.redact_entities),
                                },
                            )
                        ))
                        redacted_prompt = scan_result.sanitized_text
                        messages = [
                            {**m, "content": redacted_prompt} if m.get("role") == "user" else m
                            for m in messages
                        ]
                        full_prompt = redacted_prompt

            except Exception as security_exc:
                logger.error("Inbound security pipeline error (continuing unredacted): %s", security_exc)




        # ── 1. Load active policies ─────────────────────────────────────
        policy_result = await self.db.execute(
            select(Policy)
            .options(selectinload(Policy.rules))
            .where(Policy.tenant_id == tenant_id, Policy.is_active == True)
        )
        policies = list(policy_result.scalars().all())

        # ── 2. Evaluate policies ────────────────────────────────────────
        eval_result = self.policy_engine.evaluate(full_prompt, policies, target_model=model)

        # ── 3. Blocked? ─────────────────────────────────────────────────
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
                response_payload={"error": "Blocked by AuthClaw policy."},
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
        if eval_result.modified_prompt != full_prompt:
            new_messages = []
            for msg in messages:
                if msg.get("role") == "user":
                    msg_eval = self.policy_engine.evaluate(str(msg.get("content", "")), policies)
                    new_messages.append({**msg, "content": msg_eval.modified_prompt})
                else:
                    new_messages.append(msg)
            modified_payload["messages"] = new_messages

        # ── 5. Select provider ───────────────────────────────────────────
        provider = await self._select_provider(tenant_id)
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
                error_message="No active AI provider configured for this tenant.",
                error_type="configuration_error",
                error_code="no_provider",
                evaluation_result=eval_result,
            )
            return {
                "status_code": 503,
                "data": {
                    "error": {
                        "message": "No active AI provider configured for this tenant.",
                        "type": "configuration_error",
                        "code": 503,
                    }
                },
            }

        # ── 6. Forward to provider ───────────────────────────────────────
        
        # Check if streaming is requested
        is_stream = payload.get("stream", False)
        
        # Strip internal fields that upstream providers reject
        streaming_mode = modified_payload.pop("streaming_mode", "buffered")
        modified_payload.pop("provider", None)
        
        if is_stream:
            if streaming_mode == "strict":
                modified_payload["stream"] = False
                is_stream = False
            else:
                from app.core.providers.factory import ProviderAdapterFactory
                from fastapi import HTTPException
                
                adapter = ProviderAdapterFactory.get_adapter(provider.type)
                
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
                streaming_engine = StreamingEngine(self.audit_engine)
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
                    "response": streaming_response
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
                logger.error("Outbound security pipeline error (failing open): %s", security_exc)

        # ── 7. Log audit trail ───────────────────────────────────────────
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
            status_code=provider_resp.status_code,  # always int
            error_message=provider_resp.error_message,
            error_type=provider_resp.error_type,
            error_code=provider_resp.error_code,     # always str or None
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
                    if provider_resp.is_success
                    else "gateway.request.error"
                ),
                tenant_id=str(tenant_id),
                # api_key_id serves as the per-request correlation handle;
                # a dedicated request_id will be added when the gateway
                # request model exposes a stable UUID field.
                request_id=str(api_key_id),
                provider=provider.name if provider else None,
                model=model,
                status=provider_resp.status_code,
                latency_ms=provider_resp.latency_ms,
                tokens_prompt=tokens_prompt,
                tokens_completion=tokens_completion,
                timestamp=datetime.utcnow().isoformat() + "Z",
                payload={
                    "error_type": provider_resp.error_type,
                    # Sprint 1: security event counts for real-time dashboards
                    "security_events_inbound": security_scan_count_inbound,
                    "security_events_outbound": security_scan_count_outbound,
                },
            )
            await producer.publish("authclaw.gateway.events", gw_event)
        except Exception:
            # Intentionally swallowed — event publishing is best-effort.
            # Operators should monitor the dead-letter topic and Kafka
            # producer error counters separately.
            pass

        # ── 8. Return response ───────────────────────────────────────────
        return {
            "status_code": provider_resp.status_code,
            "data": outbound_response_body,
        }


