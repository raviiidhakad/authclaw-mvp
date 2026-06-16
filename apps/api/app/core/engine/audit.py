"""
AuthClaw Audit Engine
---------------------
Logs all gateway requests, responses, policy violations, and audit events
to PostgreSQL. Designed to never lose data, even on partial failures.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.engine.evaluator import EvaluationResult
from app.models.gateway import GatewayRequest, GatewayResponse, RequestStatus
from app.models.policy import PolicyViolation, ViolationSeverity, ViolationResolution
from app.models.audit import AuditLog, EventType, AuditAction

logger = logging.getLogger(__name__)


class AuditEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

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
        if prompt_original == prompt_redacted:
            prompt_redacted = None

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
            pii_detections=[],
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

        gw_response = GatewayResponse(
            request_id=gw_request.id,
            response_original=response_original,
            response_redacted=None,
            pii_detections=[],
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

        audit = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            event_type=event_type,
            resource="gateway_request",
            resource_id=str(gw_request.id),
            action=AuditAction.execute,
            metadata_={
                "http_status": status_code,
                "model": model,
                "provider_id": str(provider_id) if provider_id else None,
                "api_key_id": str(api_key_id) if api_key_id else None,
                "latency_ms": latency_ms,
                "tokens_prompt": tokens_prompt,
                "tokens_completion": tokens_completion,
                "error_type": error_type,
                "error_code": error_code,
                "error_message": error_message,
                "action_taken": evaluation_result.action_taken if evaluation_result else "allow",
                "violations": violation_summary,
            },
        )
        self.db.add(audit)

        try:
            await self.db.commit()
        except Exception as exc:
            logger.exception("Failed to commit audit log for request %s: %s", gw_request.id, exc)
            await self.db.rollback()
            raise

        return gw_request
