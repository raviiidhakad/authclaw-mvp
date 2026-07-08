"""
AuthClaw Audit Engine
---------------------
Logs all gateway requests, responses, policy violations, and audit events
to PostgreSQL. Designed to never lose data, even on partial failures.
"""
from __future__ import annotations

import logging
import uuid
import hashlib
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.audit.integrity import append_canonical_audit_record
from app.core.audit.repository import PostgresAuditRepository
from app.core.engine.evaluator import EvaluationResult
from app.models.gateway import GatewayRequest, GatewayResponse, RequestStatus
from app.models.policy import PolicyViolation, ViolationSeverity, ViolationResolution
from app.models.audit import EventType, AuditAction
from app.models.tenant import Tenant
from app.services.api_safety import sanitize_text, sanitize_trace_text

logger = logging.getLogger(__name__)


class AuditEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def _hash_text(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_preview(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return sanitize_trace_text(value)

    async def _append_canonical_audit_log(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: Optional[uuid.UUID],
        event_type: EventType,
        resource: str,
        resource_id: Optional[str],
        action: AuditAction,
        metadata: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        from sqlalchemy import select, text

        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        await self.db.execute(
            select(Tenant.id)
            .where(Tenant.id == tenant_id)
            .with_for_update()
        )
        repo = PostgresAuditRepository(self.db)
        return await append_canonical_audit_record(
            repo,
            tenant_id=tenant_id,
            event_type=event_type,
            actor_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def log_request(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        provider_id: Optional[uuid.UUID],
        api_key_id: Optional[uuid.UUID],
        model: str,
        original_payload: Dict[str, Any],
        modified_payload: Dict[str, Any],
        response_payload: Dict[str, Any],
        tokens_prompt: int,
        tokens_completion: int,
        latency_ms: int,
        status_code: int,          # MUST be int — enforced here
        error_message: Optional[str] = None,
        error_type: Optional[str] = None,
        error_code: Optional[str] = None,  # MUST be str or None
        evaluation_result: Optional[EvaluationResult] = None,
    ) -> GatewayRequest:
        # ── Defensive type coercion (never crash on bad caller) ──────────
        try:
            status_code = int(status_code)
        except (TypeError, ValueError):
            logger.warning("status_code was not int (%r) — defaulting to 500", status_code)
            status_code = 500

        if error_code is not None:
            error_code = str(error_code)  # e.g. "invalid_api_key", never an int

        # ── Extract prompts ──────────────────────────────────────────────
        prompt_original = "\n".join(
            m.get("content", "")
            for m in original_payload.get("messages", [])
            if isinstance(m.get("content"), str)
        )
        prompt_redacted = "\n".join(
            m.get("content", "")
            for m in modified_payload.get("messages", [])
            if isinstance(m.get("content"), str)
        )
        prompt_original_hash = self._hash_text(prompt_original)
        if prompt_original == prompt_redacted:
            prompt_redacted = None

        if not settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION:
            sanitized_original_prompt = sanitize_trace_text(prompt_original) or ""
            sanitized_modified_prompt = sanitize_trace_text(prompt_redacted) if prompt_redacted else None
            prompt_original = sanitized_original_prompt
            prompt_redacted = (
                sanitized_modified_prompt
                if sanitized_modified_prompt and sanitized_modified_prompt != sanitized_original_prompt
                else None
            )

        # ── Determine request status ─────────────────────────────────────
        if evaluation_result and evaluation_result.action_taken == "block":
            status = RequestStatus.blocked
        elif status_code >= 400:
            status = RequestStatus.error
        elif prompt_redacted is not None:
            status = RequestStatus.completed   # redacted but forwarded
        else:
            status = RequestStatus.completed

        # ── 1. Gateway Request record ────────────────────────────────────
        gw_request = GatewayRequest(
            tenant_id=tenant_id,
            user_id=user_id,
            provider_id=provider_id,
            model=model,
            prompt_original=prompt_original,
            prompt_redacted=prompt_redacted,
            security_event_count=0,  # incremented by security pipeline
            status=status,
            token_count_prompt=tokens_prompt,
            latency_ms=latency_ms,
            provider_status_code=status_code,
            error_type=error_type,
            error_code=error_code,
            error_message=error_message,
        )
        self.db.add(gw_request)

        
        await self.db.flush()   # get gw_request.id without committing

        # ── 2. Gateway Response record ───────────────────────────────────
        response_original: Optional[str] = None
        if response_payload:
            if "choices" in response_payload:
                choices = response_payload.get("choices", [])
                if choices:
                    response_original = choices[0].get("message", {}).get("content", "")
            elif "error" in response_payload:
                err = response_payload["error"]
                response_original = err.get("message") if isinstance(err, dict) else str(err)
        response_original_hash = self._hash_text(response_original)
        response_redacted = None
        if not settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION:
            sanitized_response = self._safe_preview(response_original)
            response_original = sanitized_response
        else:
            sanitized_response = self._safe_preview(response_original)
            if sanitized_response != response_original:
                response_redacted = sanitized_response

        gw_response = GatewayResponse(
            request_id=gw_request.id,
            response_original=response_original,
            response_redacted=response_redacted,
            security_event_count=0,  # incremented by security pipeline
            token_count_completion=tokens_completion,
            latency_ms=latency_ms,
        )
        self.db.add(gw_response)

        # ── 3. Policy Violation records ──────────────────────────────────
        if evaluation_result and evaluation_result.violations:
            for v in evaluation_result.violations:
                severity = (
                    ViolationSeverity.high
                    if v.action in ("block", "BlockAction", "PolicyAction.block")
                    else ViolationSeverity.medium
                )
                violation = PolicyViolation(
                    tenant_id=tenant_id,
                    request_id=gw_request.id,
                    policy_id=uuid.UUID(v.policy_id) if v.policy_id else None,
                    rule_id=uuid.UUID(v.rule_id) if v.rule_id else None,
                    severity=severity,
                    description=v.message,
                    context=v.context,
                    resolution=ViolationResolution.pending,
                )
                self.db.add(violation)

        # ── 4. Audit Log entry ───────────────────────────────────────────
        if evaluation_result and evaluation_result.action_taken == "block":
            event_type = EventType.gateway_blocked
        else:
            event_type = EventType.gateway_request

        violation_summary = []
        if evaluation_result and evaluation_result.violations:
            violation_summary = [
                {"rule_type": v.rule_type, "action": v.action, "message": v.message}
                for v in evaluation_result.violations
            ]

        await self._append_canonical_audit_log(
            tenant_id=tenant_id,
            user_id=user_id,
            event_type=event_type,
            resource="gateway_request",
            resource_id=str(gw_request.id),
            action=AuditAction.execute,
            metadata={
                "http_status": status_code,
                "model": model,
                "provider_id": str(provider_id) if provider_id else None,
                "api_key_id": str(api_key_id) if api_key_id else None,
                "latency_ms": latency_ms,
                "tokens_prompt": tokens_prompt,
                "tokens_completion": tokens_completion,
                "error_type": error_type,
                "error_code": error_code,
                "error_message": sanitize_text(error_message) if error_message else None,
                "raw_gateway_audit_retention": bool(settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION),
                "prompt_original_hash": prompt_original_hash,
                "response_original_hash": response_original_hash,
                "stored_prompt": "raw" if settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION else "sanitized_preview",
                "stored_response": "raw" if settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION else "sanitized_preview",
                "action_taken": evaluation_result.action_taken if evaluation_result else "allow",
                "violations": violation_summary,
            },
        )

        try:
            await self.db.commit()
        except Exception as exc:
            logger.exception("Failed to commit audit log for request %s: %s", gw_request.id, exc)
            await self.db.rollback()
            raise

        return gw_request

    async def log_rate_limit_exceeded(self, tenant_id: uuid.UUID, api_key_id: uuid.UUID, limit_key: str):
        """Log a rate limit violation event."""
        await self._append_canonical_audit_log(
            tenant_id=tenant_id,
            user_id=None,
            action=AuditAction.update,
            event_type=EventType.gateway_rate_limit_exceeded,
            resource="gateway",
            resource_id=str(api_key_id),
            metadata={"reason": "Rate limit exceeded", "limit_key": limit_key},
            ip_address=None,
            user_agent=None,
        )
        await self.db.commit()

    async def publish_stream_started(self, stream_id: str, tenant_id: uuid.UUID, api_key_id: uuid.UUID, provider_id: Optional[uuid.UUID], security_mode: str, prompt_hash: str):
        from app.core.events.producer import producer
        from pydantic import BaseModel
        from datetime import datetime
        import time
        
        class StreamEvent(BaseModel):
            event_type: str
            stream_id: str
            tenant_id: str
            api_key_id: str
            provider_id: Optional[str]
            security_mode: str
            prompt_hash: str
            timestamp: str
            event_id: str
            
        import uuid
        event = StreamEvent(
            event_type="gateway.stream.started",
            stream_id=stream_id,
            tenant_id=str(tenant_id),
            api_key_id=str(api_key_id),
            provider_id=str(provider_id) if provider_id else None,
            security_mode=security_mode,
            prompt_hash=prompt_hash,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_id=str(uuid.uuid4())
        )
        await producer.publish("authclaw.audit.events", event)
        
        # Also log to PostgreSQL through the canonical exportable audit path.
        await self._append_canonical_audit_log(
            tenant_id=tenant_id,
            user_id=None,
            action=AuditAction.create,
            event_type=EventType.gateway_stream_started,
            resource="gateway.stream",
            resource_id=stream_id,
            metadata={"security_mode": security_mode, "prompt_hash": prompt_hash},
            ip_address=None,
            user_agent=None,
        )
        await self.db.commit()

    async def publish_stream_completed(self, stream_id: str, response_hash: str, prompt_tokens: int, completion_tokens: int, latency_ms: int):
        from app.core.events.producer import producer
        from pydantic import BaseModel
        from datetime import datetime
        
        class StreamEvent(BaseModel):
            event_type: str
            stream_id: str
            response_hash: str
            prompt_tokens: int
            completion_tokens: int
            latency_ms: int
            timestamp: str
            event_id: str
            
        import uuid
        event = StreamEvent(
            event_type="gateway.stream.completed",
            stream_id=stream_id,
            response_hash=response_hash,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_id=str(uuid.uuid4())
        )
        await producer.publish("authclaw.audit.events", event)

    async def publish_stream_failed(self, stream_id: str, partial_response_hash: str, failure_reason: str, policy_violation_details: Optional[Dict] = None):
        from app.core.events.producer import producer
        from pydantic import BaseModel
        from datetime import datetime
        
        class StreamEvent(BaseModel):
            event_type: str
            stream_id: str
            partial_response_hash: str
            failure_reason: str
            policy_violation_details: Optional[Dict]
            timestamp: str
            event_id: str
            
        import uuid
        event = StreamEvent(
            event_type="gateway.stream.failed",
            stream_id=stream_id,
            partial_response_hash=partial_response_hash,
            failure_reason=failure_reason,
            policy_violation_details=policy_violation_details,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_id=str(uuid.uuid4())
        )
        await producer.publish("authclaw.audit.events", event)
