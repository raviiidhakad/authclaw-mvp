from __future__ import annotations

import hashlib
import hmac
import inspect
import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.core.exceptions import ForbiddenException
from app.schemas.events import RemediationWorkerTokenEvent
from app.services.remediation_state_machine import REMEDIATION_EVENTS_TOPIC

logger = logging.getLogger(__name__)

WORKER_TOKEN_TTL_SECONDS = 300


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WorkerTokenScope:
    tenant_id: uuid.UUID
    worker_type: str
    job_id: uuid.UUID | None
    action_type: str
    provider_scope: str | None = None
    resource_scope: str | None = None
    created_by: uuid.UUID | str | None = None
    one_time: bool = True

    def matches(self, other: "WorkerTokenScope") -> bool:
        return (
            self.tenant_id == other.tenant_id
            and self.worker_type == other.worker_type
            and self.job_id == other.job_id
            and self.action_type == other.action_type
            and self.provider_scope == other.provider_scope
            and self.resource_scope == other.resource_scope
        )


@dataclass
class WorkerTokenRecord:
    token_id: str
    token_hash: str
    scope: WorkerTokenScope
    expires_at: datetime
    created_at: datetime = field(default_factory=_utcnow)
    revoked_at: datetime | None = None
    used_at: datetime | None = None


@dataclass(frozen=True)
class IssuedWorkerToken:
    token: str
    token_id: str
    expires_at: datetime
    scope: WorkerTokenScope


class WorkerTokenStore(Protocol):
    async def put(self, record: WorkerTokenRecord) -> None: ...
    async def get(self, token_hash: str) -> WorkerTokenRecord | None: ...
    async def update(self, record: WorkerTokenRecord) -> None: ...


class InMemoryWorkerTokenStore:
    def __init__(self) -> None:
        self.records: dict[str, WorkerTokenRecord] = {}

    async def put(self, record: WorkerTokenRecord) -> None:
        self.records[record.token_hash] = record

    async def get(self, token_hash: str) -> WorkerTokenRecord | None:
        return self.records.get(token_hash)

    async def update(self, record: WorkerTokenRecord) -> None:
        self.records[record.token_hash] = record


class WorkerTokenService:
    def __init__(
        self,
        *,
        store: WorkerTokenStore | None = None,
        event_producer=None,
        ttl_seconds: int = WORKER_TOKEN_TTL_SECONDS,
    ) -> None:
        self.store = store or InMemoryWorkerTokenStore()
        self.event_producer = event_producer
        self.ttl_seconds = max(1, int(ttl_seconds))

    async def issue_token(self, scope: WorkerTokenScope) -> IssuedWorkerToken:
        raw_token = "awt_" + secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)
        record = WorkerTokenRecord(
            token_id=uuid.uuid4().hex,
            token_hash=token_hash,
            scope=scope,
            expires_at=_utcnow() + timedelta(seconds=self.ttl_seconds),
        )
        await self.store.put(record)
        await self._emit(record, "issued", None)
        return IssuedWorkerToken(
            token=raw_token,
            token_id=record.token_id,
            expires_at=record.expires_at,
            scope=scope,
        )

    async def validate_token(
        self,
        raw_token: str,
        expected_scope: WorkerTokenScope,
        *,
        consume: bool = True,
    ) -> WorkerTokenRecord:
        token_hash = _hash_token(raw_token)
        record = await self.store.get(token_hash)
        if record is None:
            await self._emit_missing(expected_scope, "missing")
            raise ForbiddenException(detail="Worker execution token is invalid")
        if record.revoked_at is not None:
            await self._emit(record, "rejected", "revoked")
            raise ForbiddenException(detail="Worker execution token has been revoked")
        if record.expires_at < _utcnow():
            await self._emit(record, "rejected", "expired")
            raise ForbiddenException(detail="Worker execution token has expired")
        if not record.scope.matches(expected_scope):
            await self._emit(record, "rejected", "scope_mismatch")
            raise ForbiddenException(detail="Worker execution token scope mismatch")
        if record.scope.one_time and record.used_at is not None:
            await self._emit(record, "rejected", "replay")
            raise ForbiddenException(detail="Worker execution token has already been used")
        if not hmac.compare_digest(record.token_hash, token_hash):
            await self._emit(record, "rejected", "hash_mismatch")
            raise ForbiddenException(detail="Worker execution token is invalid")
        if consume and record.scope.one_time:
            record.used_at = _utcnow()
            await self.store.update(record)
        await self._emit(record, "validated", None)
        return record

    async def revoke_token(self, raw_token: str) -> None:
        record = await self.store.get(_hash_token(raw_token))
        if record is None:
            return
        record.revoked_at = _utcnow()
        await self.store.update(record)
        await self._emit(record, "revoked", None)

    async def _emit_missing(self, scope: WorkerTokenScope, reason_category: str) -> None:
        await self._publish(
            RemediationWorkerTokenEvent(
                tenant_id=scope.tenant_id,
                worker_type=scope.worker_type,
                job_id=scope.job_id,
                action_type=scope.action_type,
                token_id="unknown",
                status="rejected",
                reason_category=reason_category,
            )
        )

    async def _emit(
        self,
        record: WorkerTokenRecord,
        status: str,
        reason_category: str | None,
    ) -> None:
        await self._publish(
            RemediationWorkerTokenEvent(
                tenant_id=record.scope.tenant_id,
                worker_type=record.scope.worker_type,
                job_id=record.scope.job_id,
                action_type=record.scope.action_type,
                token_id=record.token_id,
                status=status,
                reason_category=reason_category,
            )
        )

    async def _publish(self, event: RemediationWorkerTokenEvent) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish worker token event %s: %s", event.event_type, exc)
