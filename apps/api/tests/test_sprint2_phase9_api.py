from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.api.v1.endpoints import findings as findings_api
from app.api.v1.endpoints import integrations as integrations_api
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.schemas.finding import FindingStatusUpdate
from app.schemas.integration import IntegrationCreate, IntegrationUpdate, IntegrationValidateRequest


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


class FakeVault:
    def __init__(self):
        self.stored = []
        self.deleted = []
        self.retrieved = {}

    async def store(self, tenant_id, integration_id, credentials):
        self.stored.append((tenant_id, integration_id, credentials))
        return f"authclaw/tenants/{tenant_id}/integrations/{integration_id}"

    async def delete(self, tenant_id, vault_reference_id):
        self.deleted.append((tenant_id, vault_reference_id))

    async def retrieve(self, tenant_id, vault_reference_id):
        return self.retrieved[vault_reference_id]


class FakeScalarResult:
    def __init__(self, items):
        self.items = items

    def first(self):
        return self.items[0] if self.items else None

    def all(self):
        return self.items


class FakeResult:
    def __init__(self, rows=None, scalar_value=None):
        self.rows = rows or []
        self.scalar_value = scalar_value

    def scalars(self):
        return FakeScalarResult(self.rows)

    def all(self):
        return self.rows

    def first(self):
        return self.rows[0] if self.rows else None

    def scalar(self):
        return self.scalar_value


class FakeDb:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.added = []
        self.deleted = []
        self.flushed = False
        self.committed = False

    async def execute(self, _query):
        if self.results:
            return self.results.pop(0)
        return FakeResult()

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        self.deleted.append(obj)

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


def make_tenant(tenant_id=None):
    return SimpleNamespace(id=tenant_id or uuid.uuid4())


def make_user(user_id=None):
    return SimpleNamespace(id=user_id or uuid.uuid4())


def make_integration(tenant_id=None, status=IntegrationStatus.active):
    tenant_id = tenant_id or uuid.uuid4()
    now = datetime.now(timezone.utc)
    return CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=CloudProvider.aws,
        target_identifier="123456789012",
        display_name="AWS prod",
        status=status,
        vault_reference_id=f"authclaw/tenants/{tenant_id}/integrations/i",
        last_sync_finding_count=0,
        created_at=now,
        updated_at=now,
    )


def make_finding(integration_id, severity=FindingSeverity.high, status=FindingStatus.active):
    now = datetime.now(timezone.utc)
    return SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration_id,
        dedup_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        external_id="provider-finding",
        resource_id="arn:aws:s3:::bucket",
        title="Public S3 bucket",
        description="Normalized description",
        remediation_instructions="Block public access",
        severity=severity,
        status=status,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_create_integration_stores_credentials_in_vault_not_postgres(monkeypatch):
    tenant = make_tenant()
    user = make_user()
    db = FakeDb()
    vault = FakeVault()
    producer = FakeProducer()
    credentials = {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "very-secret",
    }

    async def valid(*_args, **_kwargs):
        return SimpleNamespace(valid=True)

    monkeypatch.setattr(integrations_api, "_validate_credentials", valid)
    monkeypatch.setattr(integrations_api, "vault_credential_service", vault)
    monkeypatch.setattr(integrations_api, "producer", producer)

    response = await integrations_api.create_integration(
        IntegrationCreate(
            provider_type=CloudProvider.aws,
            target_identifier="123456789012",
            credentials=credentials,
        ),
        tenant=tenant,
        db=db,
        current_user=user,
    )

    assert vault.stored[0][2] == credentials
    assert db.added[0].vault_reference_id.startswith(f"authclaw/tenants/{tenant.id}")
    assert not hasattr(db.added[0], "credentials")
    assert "very-secret" not in str(response.model_dump(mode="json"))
    assert "AKIAIOSFODNN7EXAMPLE" not in str(response.model_dump(mode="json"))
    assert producer.events[-1][1]["event_type"] == "integration.created"


def test_create_integration_validates_provider_type():
    with pytest.raises(ValidationError):
        IntegrationCreate(
            provider_type="azure",
            target_identifier="target",
            credentials={"token": "secret"},
        )


@pytest.mark.asyncio
async def test_get_integration_enforces_tenant_scope():
    with pytest.raises(NotFoundException):
        await integrations_api._get_integration_or_404(
            uuid.uuid4(),
            uuid.uuid4(),
            FakeDb(results=[FakeResult([])]),
        )


@pytest.mark.asyncio
async def test_update_credentials_writes_vault_safely(monkeypatch):
    tenant = make_tenant()
    integration = make_integration(tenant.id)
    vault = FakeVault()

    async def valid(*_args, **_kwargs):
        return SimpleNamespace(valid=True)

    monkeypatch.setattr(integrations_api, "_validate_credentials", valid)
    monkeypatch.setattr(integrations_api, "vault_credential_service", vault)
    monkeypatch.setattr(integrations_api, "producer", FakeProducer())

    response = await integrations_api.update_integration(
        integration.id,
        IntegrationUpdate(credentials={"aws_secret_access_key": "new-secret"}),
        tenant=tenant,
        db=FakeDb(results=[FakeResult([integration])]),
        current_user=make_user(),
    )

    assert vault.stored[0][1] == integration.id
    assert "new-secret" not in str(response.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_delete_integration_disables_and_removes_vault_secret(monkeypatch):
    tenant = make_tenant()
    integration = make_integration(tenant.id)
    vault = FakeVault()
    monkeypatch.setattr(integrations_api, "vault_credential_service", vault)
    monkeypatch.setattr(integrations_api, "producer", FakeProducer())

    await integrations_api.delete_integration(
        integration.id,
        tenant=tenant,
        db=FakeDb(results=[FakeResult([integration])]),
        current_user=make_user(),
    )

    assert vault.deleted == [(tenant.id, integration.vault_reference_id)]
    assert integration.status == IntegrationStatus.disabled


@pytest.mark.asyncio
async def test_validation_endpoint_sanitizes_provider_errors(monkeypatch):
    class FakeConnector:
        async def validate_credentials(self):
            raise ValueError("github_token=super-secret-token missing scope")

    monkeypatch.setattr(integrations_api, "_load_connector_modules", lambda: None)
    monkeypatch.setattr(
        integrations_api.ConnectorRegistry,
        "create",
        classmethod(lambda cls, integration, credentials: FakeConnector()),
    )

    result = await integrations_api._validate_credentials(
        uuid.uuid4(),
        CloudProvider.github,
        "acme",
        {"github_token": "super-secret-token"},
    )

    assert result.valid is False
    assert "super-secret-token" not in result.error_code
    assert "github_token" not in result.error_code


@pytest.mark.asyncio
async def test_manual_sync_returns_accepted_and_does_not_execute_scan(monkeypatch):
    tenant = make_tenant()
    integration = make_integration(tenant.id)
    producer = FakeProducer()
    monkeypatch.setattr(integrations_api, "producer", producer)

    response = await integrations_api.request_integration_sync(
        integration.id,
        tenant=tenant,
        db=FakeDb(results=[FakeResult([integration])]),
        current_user=make_user(),
    )

    assert response.status == "accepted"
    assert [topic for topic, _event in producer.events] == [
        "authclaw.connector.scan",
        "authclaw.integration.events",
    ]
    assert producer.events[0][1]["event_type"] == "integration.sync.requested"


@pytest.mark.asyncio
async def test_manual_sync_rejects_disabled_integration(monkeypatch):
    tenant = make_tenant()
    integration = make_integration(tenant.id, status=IntegrationStatus.disabled)
    monkeypatch.setattr(integrations_api, "producer", FakeProducer())

    with pytest.raises(BadRequestException):
        await integrations_api.request_integration_sync(
            integration.id,
            tenant=tenant,
            db=FakeDb(results=[FakeResult([integration])]),
            current_user=make_user(),
        )


@pytest.mark.asyncio
async def test_list_findings_filters_and_paginates_tenant_rows():
    tenant = make_tenant()
    integration_id = uuid.uuid4()
    high = make_finding(integration_id, severity=FindingSeverity.high)
    low = make_finding(integration_id, severity=FindingSeverity.low)
    rows = [(low, CloudProvider.aws), (high, CloudProvider.aws)]

    response = await findings_api.list_findings(
        skip=0,
        limit=1,
        provider_type=CloudProvider.aws,
        integration_id=integration_id,
        severity=None,
        status=FindingStatus.active,
        service="s3",
        tenant=tenant,
        db=FakeDb(results=[FakeResult(rows)]),
        _user=make_user(),
    )

    assert response.total == 2
    assert len(response.items) == 1
    assert response.items[0].severity == FindingSeverity.high
    assert "raw_payload" not in str(response.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_get_finding_blocks_cross_tenant_access():
    with pytest.raises(NotFoundException):
        await findings_api._get_finding_or_404(
            uuid.uuid4(),
            uuid.uuid4(),
            FakeDb(results=[FakeResult([])]),
        )


@pytest.mark.asyncio
async def test_patch_finding_status_enforces_allowed_transitions(monkeypatch):
    tenant = make_tenant()
    integration_id = uuid.uuid4()
    finding = make_finding(integration_id, status=FindingStatus.active)
    producer = FakeProducer()
    monkeypatch.setattr(findings_api, "producer", producer)

    response = await findings_api.update_finding_status(
        finding.id,
        FindingStatusUpdate(status=FindingStatus.suppressed),
        tenant=tenant,
        db=FakeDb(results=[FakeResult([(finding, CloudProvider.aws)])]),
        current_user=make_user(),
    )

    assert response.status == FindingStatus.suppressed
    assert producer.events[-1][1]["event_type"] == "finding.status.changed"


@pytest.mark.asyncio
async def test_patch_finding_status_rejects_unapproved_transition():
    tenant = make_tenant()
    finding = make_finding(uuid.uuid4(), status=FindingStatus.resolved)

    with pytest.raises(BadRequestException):
        await findings_api.update_finding_status(
            finding.id,
            FindingStatusUpdate(status=FindingStatus.suppressed),
            tenant=tenant,
            db=FakeDb(results=[FakeResult([(finding, CloudProvider.aws)])]),
            current_user=make_user(),
        )


def test_connector_health_response_is_sanitized():
    integration = make_integration(status=IntegrationStatus.error)
    integration.error_message = "aws_secret_access_key=super-secret failed"

    response = integrations_api._health_response(
        integration,
        registered={"aws"},
        breakers={"aws": {"state": "closed"}},
    )

    assert response.registered_connector_available is True
    assert response.circuit_breaker_state == {"state": "closed"}
    assert "super-secret" not in response.last_error_code
    assert "aws_secret_access_key" not in response.last_error_code
