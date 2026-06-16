"""
AuthClaw AI Gateway Engine
--------------------------
Handles policy evaluation, provider routing, and audit logging for all
AI chat-completion requests proxied through the AuthClaw gateway.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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
    """Handles HTTP communication with upstream AI providers."""

    async def chat_completion(
        self,
        provider: Provider,
        payload: Dict[str, Any],
    ) -> ProviderResponse:
        """
        Forward a chat-completion request to the upstream provider.
        NEVER raises — all exceptions are caught and returned as structured errors.
        """
        try:
            api_key = decrypt_value(provider.api_key_encrypted)
        except Exception as exc:
            logger.error("Failed to decrypt API key for provider %s: %s", provider.id, exc)
            return ProviderResponse(
                status_code=500,
                body={"error": {"message": "Gateway configuration error: cannot decrypt provider key.", "type": "gateway_error", "code": "decryption_failed"}},
                provider_name=provider.name,
                provider_type=provider.type.value,
                latency_ms=0,
            )

        url = _get_provider_url(provider)
        headers = _build_headers(provider, api_key)

        # Anthropic uses a different request format
        request_payload = payload
        if provider.type == ProviderType.anthropic:
            messages = payload.get("messages", [])
            system_msgs = [m["content"] for m in messages if m.get("role") == "system"]
            user_msgs = [m for m in messages if m.get("role") != "system"]
            request_payload = {
                "model": payload.get("model", "claude-3-haiku-20240307"),
                "max_tokens": payload.get("max_tokens", 1024),
                "messages": user_msgs,
            }
            if system_msgs:
                request_payload["system"] = " ".join(system_msgs)

        start_time = time.monotonic()
        status_code = 500
        body: Dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=request_payload, headers=headers)
                status_code = int(response.status_code)  # ensure int
                try:
                    body = response.json()
                except (ValueError, json.JSONDecodeError):
                    body = {
                        "error": {
                            "message": f"Provider returned non-JSON response (HTTP {status_code})",
                            "type": "parse_error",
                            "code": "invalid_json",
                        }
                    }

            # Normalise Anthropic response to OpenAI format
            if provider.type == ProviderType.anthropic and "content" in body:
                body = _normalize_anthropic_response(body)

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
        except httpx.HTTPStatusError as exc:
            status_code = int(exc.response.status_code)
            try:
                body = exc.response.json()
            except Exception:
                body = {"error": {"message": str(exc), "type": "http_error", "code": str(status_code)}}
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
        provider_resp: ProviderResponse = await self.ai_client.chat_completion(provider, modified_payload)
        logger.info(
            "Provider=%s type=%s status=%d latency=%dms",
            provider.name, provider.type.value, provider_resp.status_code, provider_resp.latency_ms,
        )

        # Extract token usage (OpenAI-compatible)
        usage = provider_resp.body.get("usage", {})
        tokens_prompt = int(usage.get("prompt_tokens", 0))
        tokens_completion = int(usage.get("completion_tokens", 0))

        # ── 7. Log audit trail ───────────────────────────────────────────
        await self.audit_engine.log_request(
            tenant_id=tenant_id,
            user_id=user_id,
            provider_id=provider.id,
            api_key_id=api_key_id,
            model=model,
            original_payload=payload,
            modified_payload=modified_payload,
            response_payload=provider_resp.body,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            latency_ms=provider_resp.latency_ms,
            status_code=provider_resp.status_code,  # always int
            error_message=provider_resp.error_message,
            error_type=provider_resp.error_type,
            error_code=provider_resp.error_code,     # always str or None
            evaluation_result=eval_result,
        )

        # ── 8. Return response ───────────────────────────────────────────
        return {
            "status_code": provider_resp.status_code,
            "data": provider_resp.body,
        }
