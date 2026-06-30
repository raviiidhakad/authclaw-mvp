"""
Canonical audit integrity helpers.

This module centralizes hash-chain record construction for existing audit
writers. It does not introduce a new audit store or change public APIs.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Mapping

from app.core.audit.repository import AuditRecord, AuditRepository
from app.core.events.audit_hash import GENESIS_HASH, compute_audit_hash


class AuditIntegrityError(ValueError):
    """Raised when an exportable audit record does not match the canonical hash path."""


def normalize_audit_value(value: Any) -> str:
    """Normalize enum/string values without importing model enums into the hash layer."""

    raw = getattr(value, "value", value)
    return str(raw) if raw is not None else "unknown"


def normalize_event_type(value: Any) -> str:
    return normalize_audit_value(value).replace(".", "_")


def normalize_action(value: Any) -> str:
    action = normalize_audit_value(value)
    if action not in {"create", "read", "update", "delete", "execute"}:
        return "execute"
    return action


def normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def compute_canonical_record_hash(record: AuditRecord) -> str:
    """Compute the canonical AuthClaw audit hash for an AuditRecord."""

    event_type = normalize_event_type(record.metadata.get("event_type", record.action))
    action = normalize_action(record.action)
    return compute_audit_hash(
        previous_hash=record.previous_hash,
        id_val=str(record.record_id),
        tenant_id=str(record.tenant_id),
        user_id=str(record.actor_id) if record.actor_id else "None",
        event_type=event_type,
        resource=record.resource or "system",
        resource_id=str(record.resource_id) if record.resource_id else "None",
        action=action,
        metadata=record.metadata,
        created_at=normalize_timestamp(record.created_at),
    )


def validate_canonical_record(record: AuditRecord) -> None:
    """Reject records whose stored integrity hash does not match canonical content."""

    if not record.tenant_id:
        raise AuditIntegrityError("tenant_id is required")
    if not record.previous_hash:
        raise AuditIntegrityError("previous_hash is required")
    if not record.integrity_hash:
        raise AuditIntegrityError("integrity_hash is required")
    expected_hash = compute_canonical_record_hash(record)
    if record.integrity_hash != expected_hash:
        raise AuditIntegrityError("integrity_hash_mismatch")


async def append_canonical_audit_record(
    repository: AuditRepository,
    *,
    tenant_id: uuid.UUID,
    event_type: Any,
    action: Any,
    metadata: Mapping[str, Any] | None = None,
    record_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    actor_type: str | None = None,
    frameworks_affected: list[str] | None = None,
    resource: str | None = None,
    resource_id: str | None = None,
    execution_trace: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    created_at: datetime | None = None,
) -> AuditRecord:
    """Build, hash, validate, and append an exportable canonical audit record."""

    resolved_created_at = normalize_timestamp(created_at or datetime.now(UTC))
    resolved_event_type = normalize_event_type(event_type)
    resolved_action = normalize_action(action)
    resolved_metadata = dict(metadata or {})
    resolved_metadata["event_type"] = resolved_event_type
    previous_hash = await repository.get_latest_hash(tenant_id) or GENESIS_HASH
    sequence_no = await repository.get_latest_sequence_no(tenant_id) + 1
    record = AuditRecord(
        record_id=record_id or uuid.uuid4(),
        tenant_id=tenant_id,
        sequence_no=sequence_no,
        created_at=resolved_created_at,
        actor_id=actor_id,
        actor_type=actor_type or ("user" if actor_id else "system"),
        action=resolved_action,
        frameworks_affected=list(frameworks_affected or resolved_metadata.get("frameworks_affected", [])),
        resource=resource or "system",
        resource_id=str(resource_id) if resource_id else None,
        execution_trace=execution_trace,
        metadata=resolved_metadata,
        ip_address=ip_address,
        user_agent=user_agent,
        previous_hash=previous_hash,
        integrity_hash="",
    )
    record = record.model_copy(update={"integrity_hash": compute_canonical_record_hash(record)})
    validate_canonical_record(record)
    await repository.append(record)
    return record
