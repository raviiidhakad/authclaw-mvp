from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudProvider, IntegrationStatus
from app.services.connectors.base import RawFindingData
from app.services.connectors.lock import RedisIntegrationLock
from app.services.finding_inventory import FindingInventoryService
from app.workers.connector_worker import ConnectorWorker


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.ttls = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        self.ttls[key] = ex
        return True

    async def get(self, key):
        return self.values.get(key)

    async def delete(self, key):
        existed = key in self.values
        self.values.pop(key, None)
        self.ttls.pop(key, None)
        return 1 if existed else 0

    async def eval(self, _script, _numkeys, key, owner_token):
        if self.values.get(key) == owner_token:
            return await self.delete(key)
        return 0

    async def ping(self):
        return True


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        dumped = event.model_dump(mode="json")
        self.events.append((topic, dumped))


class FakeCredentialService:
    async def retrieve(self, tenant_id, vault_reference_id):
        return {"github_token": "super-secret-token", "github_org": "acme"}


class FakeBreaker:
    async def call(self, fn, *args, **kwargs):
        return await fn(*args, **kwargs)


class FakeRegistry:
    def __init__(self, connector):
        self.connector = connector
        self.breaker = FakeBreaker()

    def create(self, integration, credentials):
        self.credentials_seen = credentials
        return self.connector

    def get_circuit_breaker(self, provider):
        return self.breaker

    def registered_providers(self):
        return ["aws", "github", "gcp"]


class FakeConnector:
    def __init__(self, findings=None, validate_error=None, fetch_error=None, delay=0):
        self.findings = findings or []
        self.validate_error = validate_error
        self.fetch_error = fetch_error
        self.delay = delay
        self.validated = False

    async def validate_credentials(self):
        self.validated = True
        if self.validate_error:
            raise self.validate_error

    async def fetch_findings(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fetch_error:
            raise self.fetch_error
        return self.findings


class FakeInventory:
    def __init__(self):
        self.calls = []

    async def persist_scan_results(self, db, integration, findings, scan_started_at):
        self.calls.append((integration, list(findings), scan_started_at))
        return SimpleNamespace(created=len(findings), updated=0, resolved=0)


class FakeRawStore:
    def __init__(self):
        self.calls = []

    async def store_batch(self, integration, scan_id, findings):
        self.calls.append((integration, scan_id, list(findings)))


class FakeDb:
    def __init__(self):
        self.flush = AsyncMock()
        self.commit = AsyncMock()
        self.rollback = AsyncMock()


def make_integration(status=IntegrationStatus.active):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        provider_type=CloudProvider.github,
        target_identifier="acme",
        vault_reference_id="authclaw/tenants/t/integrations/i",
        status=status,
        error_message=None,
        last_sync_at=None,
        last_sync_finding_count=0,
        updated_at=datetime.now(timezone.utc),
    )


def make_worker(connector, redis=None, producer=None, inventory=None, raw_store=None):
    with patch.object(ConnectorWorker, "_load_connector_modules", lambda self: None):
        return ConnectorWorker(
            redis_client=redis or FakeRedis(),
            credential_service=FakeCredentialService(),
            registry=FakeRegistry(connector),
            inventory_service=inventory or FakeInventory(),
            raw_store=raw_store or FakeRawStore(),
            event_producer=producer or FakeProducer(),
            lock_ttl_seconds=30,
            poll_interval_seconds=1,
        )


@pytest.mark.asyncio
async def test_lock_acquire_success_sets_ttl():
    redis = FakeRedis()
    integration_id = uuid.uuid4()
    lock = RedisIntegrationLock(redis, integration_id, ttl_seconds=123)

    assert await lock.acquire() is True
    assert redis.values[f"lock:integration_sync:{integration_id}"] == lock.owner_token
    assert redis.ttls[f"lock:integration_sync:{integration_id}"] == 123


@pytest.mark.asyncio
async def test_lock_acquire_conflict():
    redis = FakeRedis()
    integration_id = uuid.uuid4()
    first = RedisIntegrationLock(redis, integration_id, ttl_seconds=60)
    second = RedisIntegrationLock(redis, integration_id, ttl_seconds=60)

    assert await first.acquire() is True
    assert await second.acquire() is False


@pytest.mark.asyncio
async def test_lock_release_with_correct_owner():
    redis = FakeRedis()
    lock = RedisIntegrationLock(redis, uuid.uuid4(), ttl_seconds=60)

    await lock.acquire()
    assert await lock.release() is True
    assert lock.key not in redis.values


@pytest.mark.asyncio
async def test_lock_release_blocked_for_wrong_owner():
    redis = FakeRedis()
    integration_id = uuid.uuid4()
    owner = RedisIntegrationLock(redis, integration_id, ttl_seconds=60)
    intruder = RedisIntegrationLock(redis, integration_id, ttl_seconds=60)

    await owner.acquire()
    assert await intruder.release() is False
    assert redis.values[owner.key] == owner.owner_token


@pytest.mark.asyncio
async def test_worker_skips_locked_integration(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    redis = FakeRedis()
    integration = make_integration()
    await RedisIntegrationLock(redis, integration.id, ttl_seconds=60).acquire()
    producer = FakeProducer()
    worker = make_worker(FakeConnector(), redis=redis, producer=producer)

    result = await worker.scan_integration_loaded(FakeDb(), integration)

    assert result.status == "skipped_lock_held"
    assert integration.status == IntegrationStatus.active
    assert producer.events[-1][1]["event_type"] == "integration.sync.skipped"
    assert producer.events[-1][1]["error_code"] == "lock_held"


@pytest.mark.asyncio
async def test_worker_scans_unlocked_integration(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    finding = RawFindingData(
        external_id="alert-1",
        resource_id="repo/acme",
        title="Public repo",
        severity=FindingSeverity.medium,
        raw_payload={"secret": "raw-provider-json"},
    )
    producer = FakeProducer()
    inventory = FakeInventory()
    raw_store = FakeRawStore()
    connector = FakeConnector(findings=[finding])
    integration = make_integration()
    worker = make_worker(
        connector,
        producer=producer,
        inventory=inventory,
        raw_store=raw_store,
    )

    result = await worker.scan_integration_loaded(FakeDb(), integration)

    assert result.status == "success"
    assert connector.validated is True
    assert integration.status == IntegrationStatus.active
    assert integration.last_sync_finding_count == 1
    assert len(inventory.calls) == 1
    assert len(raw_store.calls) == 1
    event_types = [event["event_type"] for _, event in producer.events]
    assert event_types == [
        "integration.sync.started",
        "integration.findings.discovered",
        "integration.sync.completed",
    ]
    assert "raw-provider-json" not in str(producer.events)
    assert "super-secret-token" not in str(producer.events)


@pytest.mark.asyncio
async def test_worker_does_not_crash_when_one_integration_fails(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    db = FakeDb()
    bad = make_integration()
    good = make_integration()
    producer = FakeProducer()
    worker = make_worker(
        FakeConnector(fetch_error=RuntimeError("provider unavailable")),
        producer=producer,
    )
    ok_worker = make_worker(FakeConnector(findings=[]), producer=producer, redis=worker.redis)

    first = await worker.scan_integration_loaded(db, bad)
    second = await ok_worker.scan_integration_loaded(db, good)

    assert first.status == "failed"
    assert bad.status == IntegrationStatus.error
    assert second.status == "success"
    assert good.status == IntegrationStatus.active


@pytest.mark.asyncio
async def test_worker_respects_feature_flag_false(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", False)
    integration = make_integration()
    producer = FakeProducer()
    worker = make_worker(FakeConnector(), producer=producer)

    result = await worker.scan_integration_loaded(FakeDb(), integration)

    assert result.status == "skipped_feature_flag_off"
    assert integration.status == IntegrationStatus.active
    assert producer.events[-1][1]["error_code"] == "feature_flag_off"


@pytest.mark.asyncio
async def test_worker_respects_max_scan_duration(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    monkeypatch.setattr("app.services.connectors.resiliency.settings.MAX_SCAN_DURATION", 0.01)
    integration = make_integration()
    producer = FakeProducer()
    worker = make_worker(FakeConnector(delay=0.05), producer=producer)

    result = await worker.scan_integration_loaded(FakeDb(), integration)

    assert result.status == "failed"
    assert result.error_code == "timeout"
    assert integration.status == IntegrationStatus.error
    assert producer.events[-1][1]["event_type"] == "integration.sync.failed"


class InMemoryInventory(FindingInventoryService):
    def __init__(self, existing):
        self.existing = existing

    async def _find_by_hash(self, db, dedup_hash):
        return self.existing.get(dedup_hash)

    async def _find_stale_active(self, db, integration_id, scan_started_at):
        return [
            finding
            for finding in self.existing.values()
            if finding.integration_id == integration_id
            and finding.status == FindingStatus.active
            and finding.updated_at < scan_started_at
        ]


@pytest.mark.asyncio
async def test_inventory_persists_findings_and_resolves_stale():
    integration = make_integration()
    service = InMemoryInventory(existing={})
    stale_hash = service.make_dedup_hash(integration.id, "old", "res-old")
    stale = SecurityFinding(
        integration_id=integration.id,
        dedup_hash=stale_hash,
        external_id="old",
        resource_id="res-old",
        title="Old finding",
        severity=FindingSeverity.high,
        status=FindingStatus.active,
        updated_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    service.existing[stale_hash] = stale
    fresh = RawFindingData(
        external_id="new",
        resource_id="res-new",
        title="New finding",
        severity=FindingSeverity.critical,
    )
    db = FakeDb()
    db.add = lambda finding: service.existing.setdefault(finding.dedup_hash, finding)

    result = await service.persist_scan_results(
        db,
        integration,
        [fresh],
        datetime.now(timezone.utc),
    )

    assert result.created == 1
    assert result.resolved == 1
    assert stale.status == FindingStatus.resolved
    assert any(f.external_id == "new" for f in service.existing.values())


@pytest.mark.asyncio
async def test_worker_emits_failed_event_without_raw_credentials(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    integration = make_integration()
    producer = FakeProducer()
    worker = make_worker(
        FakeConnector(validate_error=ValueError("github_token private_key failed")),
        producer=producer,
    )

    result = await worker.scan_integration_loaded(FakeDb(), integration)

    assert result.status == "failed"
    assert producer.events[-1][1]["event_type"] == "integration.sync.failed"
    assert "github_token" not in integration.error_message
    assert "private_key" not in integration.error_message
    assert "super-secret-token" not in str(producer.events)


def test_connector_worker_entrypoint_importable():
    import app.workers.connector_worker as module

    assert hasattr(module, "ConnectorWorker")
    assert hasattr(module, "run_worker")

