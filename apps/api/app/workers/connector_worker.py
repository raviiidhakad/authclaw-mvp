"""
Sprint 2 Phase 7: dedicated ConnectorWorker runtime.

This module runs outside FastAPI. It periodically discovers ACTIVE
CloudIntegration rows, acquires a Redis distributed lock per integration, runs
the provider connector through ConnectorRegistry, persists normalized findings,
stores raw provider payloads in ClickHouse, and emits lifecycle events.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import os
import signal
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from typing import Sequence

import redis.asyncio as aioredis
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.events.producer import producer as default_event_producer
from app.core.rate_limit.tenant_limiter import TenantPlanLimiter, tenant_plan_limiter
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.schemas.events import (
    FindingsDiscoveredEvent,
    IntegrationSyncCompletedEvent,
    IntegrationSyncFailedEvent,
    IntegrationSyncSkippedEvent,
    IntegrationSyncStartedEvent,
)
from app.services.connectors.base import RawFindingData
from app.services.connectors.lock import RedisIntegrationLock
from app.services.connectors.registry import ConnectorRegistry
from app.services.connectors.resiliency import CircuitOpenError, async_retry, with_scan_timeout
from app.services.finding_inventory import FindingInventoryService
from app.services.finding_raw_store import FindingRawStore
from app.services.vault_credentials import vault_credential_service
from app.services.worker_token_service import WorkerTokenScope, WorkerTokenService
from app.workers.consumer_base import KafkaConsumerBase

logger = logging.getLogger(__name__)


CONNECTOR_EVENTS_TOPIC = "authclaw.connector.events"


@dataclass
class ConnectorWorkerHealth:
    loop_alive: bool = False
    last_successful_scan_at: datetime | None = None
    last_failure_reason: str | None = None


@dataclass
class ConnectorScanResult:
    integration_id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    scan_id: uuid.UUID
    status: str
    findings: Sequence[RawFindingData] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    lock_acquired: bool = True
    duration_ms: int = 0
    created: int = 0
    updated: int = 0
    resolved: int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class ConnectorWorker(KafkaConsumerBase):
    def __init__(
        self,
        redis_client=None,
        credential_service=vault_credential_service,
        registry=ConnectorRegistry,
        inventory_service: FindingInventoryService | None = None,
        raw_store: FindingRawStore | None = None,
        event_producer=default_event_producer,
        poll_interval_seconds: int | None = None,
        lock_ttl_seconds: int | None = None,
        worker_token_service: WorkerTokenService | None = None,
        rate_limiter: TenantPlanLimiter | None = None,
    ) -> None:
        super().__init__(
            topics=[os.environ.get("KAFKA_CONNECTOR_TOPIC", "authclaw.connector.scan")],
            group_id="connector-worker-group",
        )
        self.redis = redis_client
        self.credential_service = credential_service
        self.registry = registry
        self.inventory_service = inventory_service or FindingInventoryService()
        self.raw_store = raw_store or FindingRawStore()
        self.event_producer = event_producer
        self.worker_token_service = worker_token_service or WorkerTokenService(event_producer=event_producer)
        self.rate_limiter = rate_limiter or tenant_plan_limiter
        self.poll_interval_seconds = (
            poll_interval_seconds
            if poll_interval_seconds is not None
            else settings.CONNECTOR_WORKER_POLL_INTERVAL_SECONDS
        )
        configured_ttl = (
            lock_ttl_seconds
            if lock_ttl_seconds is not None
            else settings.CONNECTOR_SCAN_LOCK_TTL_SECONDS
        )
        self.lock_ttl_seconds = max(
            int(configured_ttl),
            int(settings.MAX_SCAN_DURATION) + 1,
        )
        self.health = ConnectorWorkerHealth()
        self._owns_redis = redis_client is None
        self._stop_event = asyncio.Event()
        self._load_connector_modules()

    def _load_connector_modules(self) -> None:
        modules = {
            CloudProvider.aws: "app.services.connectors.aws",
            CloudProvider.github: "app.services.connectors.github",
            CloudProvider.gcp: "app.services.connectors.gcp",
            CloudProvider.azure: "app.services.connectors.azure",
        }
        registered_connectors = getattr(self.registry, "_connectors", None)
        for provider, module_name in modules.items():
            module = importlib.import_module(module_name)
            if registered_connectors is not None and provider not in registered_connectors:
                importlib.reload(module)

    async def start(self) -> None:
        if self.redis is None:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
            )
        await super().start()

    async def stop(self) -> None:
        await super().stop()
        if self.redis is not None and self._owns_redis:
            await self.redis.aclose()

    async def process(self, payload: dict, db: AsyncSession) -> None:
        integration_id = payload.get("integration_id")
        if not integration_id:
            raise ValueError("Connector scan event missing integration_id")
        await self.scan_integration(db, uuid.UUID(str(integration_id)))

    async def run_once(self) -> list[ConnectorScanResult]:
        """Discover and scan active integrations once. Used by tests/manual runs."""
        self.health.loop_alive = True
        async with AsyncSessionLocal() as db:
            integrations = await self.discover_integrations(db)
            return await self.scan_discovered_integrations(db, integrations)

    async def scan_discovered_integrations(
        self,
        db: AsyncSession,
        integrations: Sequence[CloudIntegration],
    ) -> list[ConnectorScanResult]:
        results: list[ConnectorScanResult] = []
        for integration in integrations:
            try:
                result = await self.scan_integration_loaded(db, integration)
                await db.commit()
                results.append(result)
            except Exception as exc:
                await db.rollback()
                self.health.last_failure_reason = self._sanitize_error(exc)
                logger.exception(
                    "ConnectorWorker integration loop failed for %s",
                    getattr(integration, "id", "unknown"),
                )
        return results

    async def run_forever(self) -> None:
        """Long-running interval mode for the dedicated container."""
        self.health.loop_alive = True
        while not self._stop_event.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=float(self.poll_interval_seconds),
                )
            except asyncio.TimeoutError:
                continue

    def request_stop(self) -> None:
        self._stop_event.set()

    async def discover_integrations(self, db: AsyncSession) -> list[CloudIntegration]:
        query = (
            select(CloudIntegration)
            .where(CloudIntegration.status == IntegrationStatus.active)
            .order_by(CloudIntegration.updated_at.asc())
        )
        return list((await db.execute(query)).scalars().all())

    async def scan_integration(
        self,
        db: AsyncSession,
        integration_id: uuid.UUID,
    ) -> ConnectorScanResult:
        integration = (
            await db.execute(
                select(CloudIntegration).where(CloudIntegration.id == integration_id)
            )
        ).scalar_one_or_none()
        if integration is None:
            raise ValueError(f"CloudIntegration not found: {integration_id}")
        return await self.scan_integration_loaded(db, integration)

    async def scan_integration_loaded(
        self,
        db: AsyncSession,
        integration: CloudIntegration,
    ) -> ConnectorScanResult:
        if self.redis is None:
            raise RuntimeError("ConnectorWorker redis client is not initialized")

        scan_id = uuid.uuid4()
        scan_started_at = datetime.now(timezone.utc)
        started = perf_counter()
        provider = integration.provider_type.value

        if not settings.FF_USE_REAL_CONNECTORS:
            return await self._skip(
                integration,
                scan_id,
                provider,
                "feature_flag_off",
                started,
            )

        if integration.status != IntegrationStatus.active:
            return await self._skip(
                integration,
                scan_id,
                provider,
                f"status_{integration.status.value}",
                started,
            )

        lock = RedisIntegrationLock(
            redis=self.redis,
            integration_id=integration.id,
            ttl_seconds=self.lock_ttl_seconds,
        )
        try:
            lock_acquired = await lock.acquire()
        except Exception as exc:
            logger.warning("Redis lock acquire failed for %s: %s", integration.id, exc)
            return await self._skip(integration, scan_id, provider, "lock_error", started)

        if not lock_acquired:
            return await self._skip(integration, scan_id, provider, "lock_held", started)

        limiter_acquired = False
        try:
            limit_decision = await self.rate_limiter.acquire_connector_scan(
                db,
                integration.tenant_id,
                provider,
                integration.id,
            )
            if not limit_decision.allowed:
                return await self._skip(integration, scan_id, provider, limit_decision.scope, started)
            limiter_acquired = True

            await self._emit_started(integration, scan_id, provider)
            await self._mark_syncing(db, integration)

            token_scope = WorkerTokenScope(
                tenant_id=integration.tenant_id,
                worker_type="connector_scan",
                job_id=scan_id,
                action_type="scan",
                provider_scope=provider,
                resource_scope=str(integration.id),
                created_by="connector-worker",
                one_time=True,
            )
            issued_worker_token = await self.worker_token_service.issue_token(token_scope)
            await self.worker_token_service.validate_token(issued_worker_token.token, token_scope)

            credentials = await self.credential_service.retrieve(
                integration.tenant_id,
                integration.vault_reference_id,
            )
            secret_values = self._secret_values(credentials)
            connector = self.registry.create(integration, credentials)
            breaker = self.registry.get_circuit_breaker(integration.provider_type)

            async def _run_scan() -> list[RawFindingData]:
                await connector.validate_credentials()
                return await with_scan_timeout(
                    async_retry(
                        connector.fetch_findings,
                        reraise_types=(PermissionError, ValueError),
                    )
                )

            findings = await breaker.call(_run_scan)
            await self.raw_store.store_batch(integration, scan_id, findings)
            persistence = await self.inventory_service.persist_scan_results(
                db,
                integration,
                findings,
                scan_started_at,
            )
            await self._emit_findings(integration, scan_id, provider, findings, started)
            await self._mark_active(db, integration, len(findings))
            result = ConnectorScanResult(
                integration_id=integration.id,
                tenant_id=integration.tenant_id,
                provider=provider,
                scan_id=scan_id,
                status="success",
                findings=findings,
                duration_ms=self._duration_ms(started),
                created=persistence.created,
                updated=persistence.updated,
                resolved=persistence.resolved,
            )
            await self._emit_completed(integration, result)
            self.health.last_successful_scan_at = datetime.now(timezone.utc)
            self.health.last_failure_reason = None
            return result
        except CircuitOpenError as exc:
            return await self._fail(
                db, integration, scan_id, provider, "circuit_open", exc, started, locals().get("secret_values")
            )
        except asyncio.TimeoutError as exc:
            return await self._fail(
                db, integration, scan_id, provider, "timeout", exc, started, locals().get("secret_values")
            )
        except Exception as exc:
            return await self._fail(
                db, integration, scan_id, provider, "connector_error", exc, started, locals().get("secret_values")
            )
        finally:
            if limiter_acquired:
                await self.rate_limiter.release_connector_scan(integration.tenant_id)
            try:
                released = await lock.release()
                if not released:
                    logger.warning(
                        "ConnectorWorker did not release lock for integration %s; "
                        "it may have expired or been reacquired.",
                        integration.id,
                    )
            except Exception as exc:
                logger.warning("Redis lock release failed for %s: %s", integration.id, exc)

    async def _mark_syncing(self, db: AsyncSession, integration: CloudIntegration) -> None:
        integration.status = IntegrationStatus.syncing
        integration.error_message = None
        await db.flush()

    async def _mark_active(
        self,
        db: AsyncSession,
        integration: CloudIntegration,
        finding_count: int,
    ) -> None:
        integration.status = IntegrationStatus.active
        integration.last_sync_at = datetime.now(timezone.utc)
        integration.last_sync_finding_count = finding_count
        integration.error_message = None
        await db.flush()

    async def _mark_error(
        self,
        db: AsyncSession,
        integration: CloudIntegration,
        message: str,
    ) -> None:
        integration.status = IntegrationStatus.error
        integration.error_message = self._sanitize_error(message)[:4000]
        await db.flush()

    async def _skip(
        self,
        integration: CloudIntegration,
        scan_id: uuid.UUID,
        provider: str,
        reason: str,
        started: float,
    ) -> ConnectorScanResult:
        result = ConnectorScanResult(
            integration_id=integration.id,
            tenant_id=integration.tenant_id,
            provider=provider,
            scan_id=scan_id,
            status=f"skipped_{reason}",
            error_code=reason,
            lock_acquired=False,
            duration_ms=self._duration_ms(started),
        )
        await self._emit_skipped(integration, result)
        return result

    async def _fail(
        self,
        db: AsyncSession,
        integration: CloudIntegration,
        scan_id: uuid.UUID,
        provider: str,
        error_code: str,
        exc: Exception,
        started: float,
        secret_values: Sequence[str] | None = None,
    ) -> ConnectorScanResult:
        message = self._sanitize_error(exc, secret_values)
        await self._mark_error(db, integration, message)
        result = ConnectorScanResult(
            integration_id=integration.id,
            tenant_id=integration.tenant_id,
            provider=provider,
            scan_id=scan_id,
            status="failed",
            error_code=error_code,
            error_message=message,
            duration_ms=self._duration_ms(started),
        )
        self.health.last_failure_reason = message
        await self._emit_failed(integration, result)
        return result

    async def _emit_started(
        self,
        integration: CloudIntegration,
        scan_id: uuid.UUID,
        provider: str,
    ) -> None:
        await self.event_producer.publish(
            CONNECTOR_EVENTS_TOPIC,
            IntegrationSyncStartedEvent(
                tenant_id=str(integration.tenant_id),
                integration_id=str(integration.id),
                provider_type=provider,
                scan_id=str(scan_id),
            ),
        )

    async def _emit_skipped(
        self,
        integration: CloudIntegration,
        result: ConnectorScanResult,
    ) -> None:
        await self.event_producer.publish(
            CONNECTOR_EVENTS_TOPIC,
            IntegrationSyncSkippedEvent(
                tenant_id=str(integration.tenant_id),
                integration_id=str(integration.id),
                provider_type=result.provider,
                scan_id=str(result.scan_id),
                duration_ms=result.duration_ms,
                error_code=result.error_code,
            ),
        )

    async def _emit_findings(
        self,
        integration: CloudIntegration,
        scan_id: uuid.UUID,
        provider: str,
        findings: Sequence[RawFindingData],
        started: float,
    ) -> None:
        await self.event_producer.publish(
            CONNECTOR_EVENTS_TOPIC,
            FindingsDiscoveredEvent(
                tenant_id=str(integration.tenant_id),
                integration_id=str(integration.id),
                provider_type=provider,
                scan_id=str(scan_id),
                finding_count=len(findings),
                max_severity=self._max_severity(findings),
                duration_ms=self._duration_ms(started),
            ),
        )

    async def _emit_completed(
        self,
        integration: CloudIntegration,
        result: ConnectorScanResult,
    ) -> None:
        await self.event_producer.publish(
            CONNECTOR_EVENTS_TOPIC,
            IntegrationSyncCompletedEvent(
                tenant_id=str(integration.tenant_id),
                integration_id=str(integration.id),
                provider_type=result.provider,
                scan_id=str(result.scan_id),
                finding_count=result.finding_count,
                max_severity=self._max_severity(result.findings),
                duration_ms=result.duration_ms,
                payload={
                    "created": result.created,
                    "updated": result.updated,
                    "resolved": result.resolved,
                },
            ),
        )

    async def _emit_failed(
        self,
        integration: CloudIntegration,
        result: ConnectorScanResult,
    ) -> None:
        await self.event_producer.publish(
            CONNECTOR_EVENTS_TOPIC,
            IntegrationSyncFailedEvent(
                tenant_id=str(integration.tenant_id),
                integration_id=str(integration.id),
                provider_type=result.provider,
                scan_id=str(result.scan_id),
                duration_ms=result.duration_ms,
                error_code=result.error_code,
            ),
        )

    def _duration_ms(self, started: float) -> int:
        return int((perf_counter() - started) * 1000)

    def _max_severity(self, findings: Sequence[RawFindingData]) -> str | None:
        if not findings:
            return None
        priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return max(
            (finding.severity.value for finding in findings),
            key=lambda severity: priority.get(severity, 0),
        )

    def _sanitize_error(
        self,
        exc: Exception | str,
        secret_values: Sequence[str] | None = None,
    ) -> str:
        message = str(exc)
        for secret_key in (
            "aws_secret_access_key",
            "aws_session_token",
            "github_token",
            "private_key",
            "client_secret",
            "azure_client_secret",
            "access_token",
        ):
            message = message.replace(secret_key, "[redacted]")
        for secret_value in secret_values or []:
            if len(secret_value) >= 4:
                message = message.replace(secret_value, "[redacted]")
        return message

    def _secret_values(self, credentials: object) -> list[str]:
        values: list[str] = []

        def walk(value: object) -> None:
            if isinstance(value, dict):
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, (list, tuple, set)):
                for nested in value:
                    walk(nested)
            elif isinstance(value, str):
                values.append(value)

        walk(credentials)
        return values

    async def health_check(self) -> dict:
        redis_ok = False
        if self.redis is not None:
            try:
                redis_ok = bool(await self.redis.ping())
            except Exception:
                redis_ok = False
        database_ok = await self._database_healthy()
        vault_status = await self._vault_status()
        return {
            "redis": "healthy" if redis_ok else "unhealthy",
            "database": "healthy" if database_ok else "unhealthy",
            "vault": vault_status,
            "registered_connector_providers": self.registry.registered_providers(),
            "loop_alive": self.health.loop_alive,
            "last_successful_scan_at": (
                self.health.last_successful_scan_at.isoformat()
                if self.health.last_successful_scan_at
                else None
            ),
            "last_failure_reason": self.health.last_failure_reason,
        }

    async def _database_healthy(self) -> bool:
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(text("SELECT 1"))
            return True
        except Exception as exc:
            logger.warning("ConnectorWorker database health check failed: %s", exc)
            return False

    async def _vault_status(self) -> str:
        health_check = getattr(self.credential_service, "is_healthy", None)
        if health_check is None:
            return "unknown"
        try:
            result = health_check()
            if inspect.isawaitable(result):
                result = await result
            return "healthy" if bool(result) else "unhealthy"
        except Exception as exc:
            logger.warning("ConnectorWorker vault health check failed: %s", exc)
            return "unhealthy"


async def run_worker() -> None:
    logging.basicConfig(level=logging.INFO)
    await default_event_producer.start()
    worker = ConnectorWorker()
    await worker.start()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, worker.request_stop)
        except NotImplementedError:
            signal.signal(sig, lambda *_: worker.request_stop())

    try:
        await worker.run_forever()
    finally:
        await worker.stop()
        await default_event_producer.stop()


if __name__ == "__main__":
    asyncio.run(run_worker())
