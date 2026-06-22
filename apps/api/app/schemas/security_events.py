"""
AuthClaw Sprint 1 — Security Pipeline Event Schemas
----------------------------------------------------
Defines all Pydantic models for PII/PHI detection, redaction, policy
violation, and blocking events published to Kafka security topics.

Topics:
  authclaw.security.pipeline   →  All Sprint 1 security pipeline events
  security.dlq                 →  Dead Letter Queue for failed security events

All events include event_version for consumer-side schema evolution.

Event catalog:
  prompt.pii_detected       — PII found in user prompt
  prompt.phi_detected       — PHI found in user prompt
  prompt.redacted           — Prompt was sanitized before forwarding
  request.blocked           — Request blocked; provider was NOT called
  completion.pii_detected   — PII found in LLM completion
  completion.phi_detected   — PHI found in LLM completion
  completion.redacted       — Completion was sanitized before returning
  response.blocked          — Completion blocked; not returned to client
  policy.violation          — A policy rule was triggered (any action)
  policy.evaluated          — Policy evaluation completed (for audit trail)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Base security event ────────────────────────────────────────────────────────

class BaseSecurityEvent(BaseModel):
    """
    Base for all Sprint 1 security pipeline events.

    Fields:
        event_version:  Integer schema version. Consumers use this for
                        backward-compatible deserialization.
        event_id:       UUID v4 — unique ID for deduplication and tracing.
        event_type:     Dot-notation type string (e.g. "prompt.pii_detected").
        tenant_id:      UUID of the tenant that triggered this event.
        request_id:     Correlation ID linking the event to a gateway request.
        timestamp:      ISO-8601 UTC timestamp.
        direction:      "INBOUND" (prompt) or "OUTBOUND" (completion).
        shadow_mode:    True if FF_SECURITY_SHADOW_MODE was active (detect only).
        payload:        Event-specific metadata.
    """
    event_version: int = Field(1, description="Schema version for consumer deserialization")
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    tenant_id: str
    request_id: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    direction: str  # "INBOUND" | "OUTBOUND"
    shadow_mode: bool = False
    payload: Dict[str, Any] = Field(default_factory=dict)


# ── PII/PHI detection events ───────────────────────────────────────────────────

class PIIDetectedEvent(BaseSecurityEvent):
    """
    Emitted when Presidio detects PII entities in a prompt or completion.

    Additional payload fields:
      entity_types:   List of detected Presidio entity type strings.
      max_risk_level: Highest risk classification (LOW/MEDIUM/HIGH/CRITICAL).
      detection_count: Number of distinct PII spans detected.
      latency_presidio_ms: Time taken by Presidio analysis.
    """
    event_type: str = "prompt.pii_detected"


class PHIDetectedEvent(BaseSecurityEvent):
    """
    Emitted when Presidio detects PHI entities (MRN, NPI, Insurance ID, etc.).
    Treated separately from PII for HIPAA audit segregation.
    """
    event_type: str = "prompt.phi_detected"


# ── Redaction events ───────────────────────────────────────────────────────────

class ContentRedactedEvent(BaseSecurityEvent):
    """
    Emitted when content was successfully redacted before transmission.

    Additional payload fields:
      redaction_mode:  "MASK" | "HASH" | "SYNTHETIC"
      entities_redacted: List of entity types that were redacted.
      entity_count:    Total number of spans redacted.
    """
    event_type: str = "prompt.redacted"


# ── Blocking events ────────────────────────────────────────────────────────────

class RequestBlockedEvent(BaseSecurityEvent):
    """
    Emitted when an inbound request is fully blocked.
    The LLM provider is NEVER called when this event is raised.

    Additional payload fields:
      block_reason:   Human-readable reason (e.g. "CREDIT_CARD detected; policy=block")
      policy_ids:     List of policy UUIDs that triggered the block.
    """
    event_type: str = "request.blocked"


class ResponseBlockedEvent(BaseSecurityEvent):
    """
    Emitted when an outbound LLM completion is blocked.
    The completion is NOT returned to the client when this event is raised.

    Additional payload fields:
      block_reason:   Human-readable reason.
      entity_types:   Entities detected in the completion.
    """
    event_type: str = "response.blocked"


# ── Policy events ──────────────────────────────────────────────────────────────

class PolicyViolationEvent(BaseSecurityEvent):
    """
    Emitted for every policy rule violation, regardless of action taken.
    (Includes WARN-level violations that do not block the request.)

    Additional payload fields:
      policy_id:     UUID of the violated policy.
      rule_id:       UUID of the violated rule.
      rule_type:     Rule type string (pii_block, pii_redact, content_filter…)
      action_taken:  "WARN" | "REDACT" | "BLOCK"
      entity_types:  Entities involved in the violation.
    """
    event_type: str = "policy.violation"


class PolicyEvaluatedEvent(BaseSecurityEvent):
    """
    Emitted after every policy evaluation pass (both inbound and outbound).
    Provides a full audit record of the evaluation outcome even when no
    violations are found.

    Additional payload fields:
      policies_evaluated: Number of active policies evaluated.
      rules_evaluated:    Total number of rules evaluated.
      violations_found:   Number of violations triggered.
      evaluation_ms:      Time taken for the full evaluation.
    """
    event_type: str = "policy.evaluated"


# ── Dead Letter Queue event ────────────────────────────────────────────────────

class SecurityDLQEvent(BaseModel):
    """
    Wraps any security event that failed to publish to its primary topic.
    Published to the 'security.dlq' topic for monitoring and replay.

    Fields:
        original_topic:   The topic the event was originally destined for.
        original_event:   The full serialized original event dict.
        failure_reason:   Exception message or error description.
        retry_count:      Number of failed publish attempts before DLQ routing.
        timestamp:        ISO-8601 UTC timestamp of DLQ routing.
    """
    event_version: int = 1
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_topic: str
    original_event: Dict[str, Any]
    failure_reason: str
    retry_count: int = 0
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
