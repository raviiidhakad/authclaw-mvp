from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.api.v1.endpoints import findings as findings_api
from app.api.v1.endpoints import integrations as integrations_api
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudProvider
from app.schemas.integration import IntegrationCreate
from app.services.connectors.base import RawFindingData
from app.services.finding_inventory import FindingInventoryService
from app.services.findings_context import FindingContextRow, FindingsContextBuilder
from app.workers.connector_worker import ConnectorWorker


SECRET_TOKEN = "ghp_supersecretsecretsecretsecret"
RAW_PROVIDER_VALUE = "raw-provider-json-with-sensitive-context"


class FakeScalarResult:
    def __init__(self, items):
        self.items = items

    def first(self):
        return self.items[0] if self.items else None

    def all(self):
        return self.items


class FakeResult:
    def __init__(self, rows=None):
        self.rows = rows or []

    def scalars(self):
        return FakeScalarResult(self.rows)

    def all(self):
        return self.rows

    def first(self):
        return self.rows[0] if self.rows else None


class EndpointDb:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.added = []
        self.flushed = False
        self.committed = False

    async def execute(self, _query):
        if self.results:
            return self.results.pop(0)
        return FakeResult()

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flushed = True

    async def refresh(self, obj):
        now = datetime.now(timezone.utc)
        if getattr(obj, "created_at", None) is None:
            obj.created_at = now
        if getattr(obj, "updated_at", None) is None:
            obj.updated_at = now

    async def commit(self):
        self.committed = True

    async def rollback(self):
        pass


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


class FakeVault:
    def __init__(self):
        self.stored = []
        self.secrets = {}

    async def store(self, tenant_id, integration_id, credentials):
        ref = f"authclaw/tenants/{tenant_id}/integrations/{integration_id}"
        self.stored.append((tenant_id, integration_id, credentials))
        self.secrets[ref] = dict(credentials)
        return ref

    async def retrieve(self, _tenant_id, vault_reference_id):
        return dict(self.secrets[vault_reference_id])


class FakeRedis:
    def __init__(self):
        self.values = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def eval(self, _script, _numkeys, key, owner_token):
        if self.values.get(key) == owner_token:
            self.values.pop(key, None)
            return 1
        return 0

    async def ping(self):
        return True


class FakeBreaker:
    async def call(self, fn, *args, **kwargs):
        return await fn(*args, **kwargs)


class FakeConnector:
    def __init__(self, findings):
        self.findings = findings
        self.validated = False

    async def validate_credentials(self):
        self.validated = True

    async def fetch_findings(self):
        return self.findings


class FakeRegistry:
    def __init__(self, connector):
        self.connector = connector
        self.credentials_seen = None

    def create(self, _integration, credentials):
        self.credentials_seen = credentials
        return self.connector

    def get_circuit_breaker(self, _provider):
        return FakeBreaker()


class FakeRawStore:
    def __init__(self):
        self.calls = []

    async def store_batch(self, integration, scan_id, findings):
        self.calls.append((integration, scan_id, list(findings)))


class MemoryInventory(FindingInventoryService):
    def __init__(self):
        self.records = {}

    async def _find_by_hash(self, _db, dedup_hash):
        return self.records.get(dedup_hash)

    async def _find_stale_active(self, _db, integration_id, scan_started_at):
        return [
            finding
            for finding in self.records.values()
            if finding.integration_id == integration_id
            and finding.status == FindingStatus.active
            and finding.updated_at < scan_started_at
        ]


class InventoryDb(EndpointDb):
    def __init__(self, inventory):
        super().__init__()
        self.inventory = inventory

    def add(self, finding):
        now = datetime.now(timezone.utc)
        if getattr(finding, "id", None) is None:
            finding.id = uuid.uuid4()
        if getattr(finding, "created_at", None) is None:
            finding.created_at = now
        if getattr(finding, "updated_at", None) is None:
            finding.updated_at = now
        self.inventory.records[finding.dedup_hash] = finding
        super().add(finding)


class MemoryContextBuilder(FindingsContextBuilder):
    def __init__(self, inventory, integration):
        super().__init__(db=None)
        self.inventory = inventory
        self.integration = integration

    async def _fetch_active_findings(self, tenant_id, integration_id=None, provider_type=None):
        rows = []
        for finding in self.inventory.records.values():
            if self.integration.tenant_id != tenant_id:
                continue
            if finding.status != FindingStatus.active:
                continue
            if integration_id is not None and finding.integration_id != integration_id:
                continue
            if provider_type is not None and self.integration.provider_type != provider_type:
                continue
            rows.append(
                FindingContextRow(
                    finding=finding,
                    provider_type=self.integration.provider_type,
                    integration_id=self.integration.id,
                )
            )
        return rows


@pytest.mark.asyncio
async def test_sprint2_fake_connector_end_to_end_flow_is_safe(monkeypatch):
    tenant = SimpleNamespace(id=uuid.uuid4())
    user = SimpleNamespace(id=uuid.uuid4())
    credentials = {"github_token": SECRET_TOKEN, "github_org": "acme"}
    vault = FakeVault()
    api_events = FakeProducer()

    async def valid(*_args, **_kwargs):
        return SimpleNamespace(valid=True)

    monkeypatch.setattr(integrations_api, "_validate_credentials", valid)
    monkeypatch.setattr(integrations_api, "vault_credential_service", vault)
    monkeypatch.setattr(integrations_api, "producer", api_events)

    create_db = EndpointDb()
    integration_response = await integrations_api.create_integration(
        IntegrationCreate(
            provider_type=CloudProvider.github,
            target_identifier="acme",
            display_name="GitHub prod",
            credentials=credentials,
        ),
        tenant=tenant,
        db=create_db,
        current_user=user,
    )
    integration = create_db.added[0]

    assert vault.stored[0][2] == credentials
    assert not hasattr(integration, "credentials")
    assert integration.vault_reference_id.startswith(f"authclaw/tenants/{tenant.id}/")
    assert SECRET_TOKEN not in str(integration_response.model_dump(mode="json"))

    sync_response = await integrations_api.request_integration_sync(
        integration.id,
        tenant=tenant,
        db=EndpointDb(results=[FakeResult([integration])]),
        current_user=user,
    )
    assert sync_response.queued is True
    assert "authclaw.connector.scan" in [topic for topic, _event in api_events.events]
    assert SECRET_TOKEN not in str(api_events.events)

    raw_finding = RawFindingData(
        external_id="github-alert-1",
        resource_id="acme/app",
        title="Branch protection disabled",
        description=f"Provider detail contained token={SECRET_TOKEN}",
        remediation_instructions="Require reviews before merging.",
        severity=FindingSeverity.high,
        raw_payload={"provider": "github", "raw_payload": RAW_PROVIDER_VALUE},
    )
    inventory = MemoryInventory()
    stale_hash = inventory.make_dedup_hash(integration.id, "old-alert", "acme/old")
    inventory.records[stale_hash] = SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration.id,
        dedup_hash=stale_hash,
        external_id="old-alert",
        resource_id="acme/old",
        title="Old alert",
        severity=FindingSeverity.low,
        status=FindingStatus.active,
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
        updated_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    raw_store = FakeRawStore()
    connector_events = FakeProducer()
    connector = FakeConnector([raw_finding])
    registry = FakeRegistry(connector)
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    monkeypatch.setattr(ConnectorWorker, "_load_connector_modules", lambda self: None)

    worker = ConnectorWorker(
        redis_client=FakeRedis(),
        credential_service=vault,
        registry=registry,
        inventory_service=inventory,
        raw_store=raw_store,
        event_producer=connector_events,
        lock_ttl_seconds=30,
        poll_interval_seconds=1,
    )
    worker_result = await worker.scan_integration_loaded(InventoryDb(inventory), integration)

    assert worker_result.status == "success"
    assert connector.validated is True
    assert registry.credentials_seen == credentials
    assert raw_store.calls[0][2][0].raw_payload["raw_payload"] == RAW_PROVIDER_VALUE
    assert worker_result.created == 1
    assert worker_result.resolved == 1
    assert SECRET_TOKEN not in str(connector_events.events)
    assert RAW_PROVIDER_VALUE not in str(connector_events.events)

    new_finding = next(
        finding for finding in inventory.records.values() if finding.external_id == "github-alert-1"
    )
    new_finding.status = FindingStatus.active
    findings_response = await findings_api.list_findings(
        skip=0,
        limit=25,
        provider_type=CloudProvider.github,
        integration_id=integration.id,
        severity=None,
        status=None,
        service=None,
        tenant=tenant,
        db=EndpointDb(results=[FakeResult([(new_finding, CloudProvider.github)])]),
        _user=user,
    )

    findings_dump = str(findings_response.model_dump(mode="json"))
    assert findings_response.total == 1
    assert "raw_payload" not in findings_dump
    assert RAW_PROVIDER_VALUE not in findings_dump
    assert SECRET_TOKEN not in findings_dump

    context = await MemoryContextBuilder(inventory, integration).build_for_tenant(tenant.id)
    context_dump = str(context)
    assert isinstance(context, list)
    assert all(isinstance(item, str) for item in context)
    assert "Branch protection disabled" in context_dump
    assert "raw_payload" not in context_dump
    assert RAW_PROVIDER_VALUE not in context_dump
    assert SECRET_TOKEN not in context_dump
