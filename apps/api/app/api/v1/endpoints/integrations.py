from __future__ import annotations

import importlib
import logging
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_tenant, get_db, require_roles
from app.core.exceptions import BadRequestException, NotFoundException
from app.core.events.producer import producer
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.events import (
    IntegrationCreatedEvent,
    IntegrationDeletedEvent,
    IntegrationSyncRequestedEvent,
    IntegrationUpdatedEvent,
    IntegrationValidationCompletedEvent,
    IntegrationValidationRequestedEvent,
)
from app.schemas.integration import (
    ConnectorHealthListResponse,
    IntegrationCreate,
    IntegrationHealthResponse,
    IntegrationListResponse,
    IntegrationResponse,
    IntegrationSyncResponse,
    IntegrationUpdate,
    IntegrationValidateRequest,
    IntegrationValidationResponse,
)
from app.services.api_safety import collect_secret_values, sanitize_text
from app.services.connectors.registry import ConnectorRegistry
from app.services.vault_credentials import vault_credential_service

logger = logging.getLogger(__name__)
router = APIRouter()

INTEGRATION_EVENTS_TOPIC = "authclaw.integration.events"
CONNECTOR_SCAN_TOPIC = "authclaw.connector.scan"


def _load_connector_modules() -> None:
    for module_name in (
        "app.services.connectors.aws",
        "app.services.connectors.github",
        "app.services.connectors.gcp",
    ):
        importlib.import_module(module_name)


async def _get_integration_or_404(
    integration_id: uuid.UUID,
    tenant_id: uuid.UUID,
    db: AsyncSession,
) -> CloudIntegration:
    result = await db.execute(
        select(CloudIntegration).where(
            CloudIntegration.id == integration_id,
            CloudIntegration.tenant_id == tenant_id,
        )
    )
    integration = result.scalars().first()
    if not integration:
        raise NotFoundException(detail="Integration not found")
    return integration


def _temporary_integration(
    tenant_id: uuid.UUID,
    provider_type: CloudProvider,
    target_identifier: str,
) -> CloudIntegration:
    return CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=provider_type,
        target_identifier=target_identifier,
        status=IntegrationStatus.active,
        vault_reference_id="validation-only",
    )


async def _validate_credentials(
    tenant_id: uuid.UUID,
    provider_type: CloudProvider,
    target_identifier: str,
    credentials: dict,
) -> IntegrationValidationResponse:
    _load_connector_modules()
    secret_values = collect_secret_values(credentials)
    try:
        connector = ConnectorRegistry.create(
            _temporary_integration(tenant_id, provider_type, target_identifier),
            credentials,
        )
        await connector.validate_credentials()
        return IntegrationValidationResponse(provider_type=provider_type, valid=True)
    except Exception as exc:
        missing_permissions = getattr(exc, "missing_permissions", []) or []
        sanitized = sanitize_text(exc, secret_values)[:240]
        return IntegrationValidationResponse(
            provider_type=provider_type,
            valid=False,
            error_code=sanitized or exc.__class__.__name__,
            missing_permissions=[sanitize_text(item, secret_values) for item in missing_permissions],
        )


async def _publish_event(topic: str, event) -> None:
    try:
        await producer.publish(topic, event)
    except Exception as exc:
        logger.warning("Failed to publish integration event %s: %s", event.event_type, exc)


def _lifecycle_event(event_cls, integration: CloudIntegration, actor_id: uuid.UUID | None = None, **payload):
    return event_cls(
        tenant_id=str(integration.tenant_id),
        integration_id=str(integration.id),
        provider_type=integration.provider_type.value,
        target_identifier=integration.target_identifier,
        status=integration.status.value,
        actor_id=str(actor_id) if actor_id else None,
        payload=payload,
    )


def _integration_response(integration: CloudIntegration) -> IntegrationResponse:
    return IntegrationResponse(
        id=integration.id,
        tenant_id=integration.tenant_id,
        provider_type=integration.provider_type,
        target_identifier=integration.target_identifier,
        display_name=integration.display_name,
        status=integration.status,
        vault_reference_id=integration.vault_reference_id,
        last_sync_at=integration.last_sync_at,
        last_sync_finding_count=integration.last_sync_finding_count,
        error_message=sanitize_text(integration.error_message)[:4000]
        if integration.error_message
        else None,
        created_at=integration.created_at,
        updated_at=integration.updated_at,
    )


@router.get("", response_model=IntegrationListResponse)
async def list_integrations(
    skip: int = 0,
    limit: int = 50,
    provider_type: CloudProvider | None = None,
    status: IntegrationStatus | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    query = select(CloudIntegration).where(CloudIntegration.tenant_id == tenant.id)
    if provider_type is not None:
        query = query.where(CloudIntegration.provider_type == provider_type)
    if status is not None:
        query = query.where(CloudIntegration.status == status)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
    items = (
        await db.execute(
            query.order_by(CloudIntegration.created_at.desc()).offset(skip).limit(limit)
        )
    ).scalars().all()
    return IntegrationListResponse(items=[_integration_response(item) for item in items], total=total)


@router.post("", response_model=IntegrationResponse, status_code=201)
async def create_integration(
    body: IntegrationCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    validation = await _validate_credentials(
        tenant.id, body.provider_type, body.target_identifier, body.credentials
    )
    if not validation.valid:
        raise BadRequestException(detail=f"Integration validation failed: {validation.error_code}")

    integration_id = uuid.uuid4()
    vault_reference_id = await vault_credential_service.store(
        tenant.id,
        integration_id,
        body.credentials,
    )
    integration = CloudIntegration(
        id=integration_id,
        tenant_id=tenant.id,
        provider_type=body.provider_type,
        target_identifier=body.target_identifier,
        display_name=body.display_name,
        status=IntegrationStatus.active,
        vault_reference_id=vault_reference_id,
        last_sync_finding_count=0,
    )
    db.add(integration)
    await db.flush()
    await db.refresh(integration)
    await db.commit()
    await _publish_event(
        INTEGRATION_EVENTS_TOPIC,
        _lifecycle_event(IntegrationCreatedEvent, integration, current_user.id),
    )
    return _integration_response(integration)


@router.post("/validate", response_model=IntegrationValidationResponse)
async def validate_integration_credentials(
    body: IntegrationValidateRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    await _publish_event(
        INTEGRATION_EVENTS_TOPIC,
        IntegrationValidationRequestedEvent(
            tenant_id=str(tenant.id),
            integration_id=str(uuid.uuid4()),
            provider_type=body.provider_type.value,
            target_identifier=body.target_identifier,
            actor_id=str(current_user.id),
        ),
    )
    validation = await _validate_credentials(
        tenant.id, body.provider_type, body.target_identifier, body.credentials
    )
    await _publish_event(
        INTEGRATION_EVENTS_TOPIC,
        IntegrationValidationCompletedEvent(
            tenant_id=str(tenant.id),
            integration_id=str(uuid.uuid4()),
            provider_type=body.provider_type.value,
            target_identifier=body.target_identifier,
            actor_id=str(current_user.id),
            valid=validation.valid,
            error_code=validation.error_code,
            missing_permissions=validation.missing_permissions,
        ),
    )
    return validation


@router.get("/health", response_model=ConnectorHealthListResponse)
async def connector_health(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    _load_connector_modules()
    items = (
        await db.execute(
            select(CloudIntegration)
            .where(CloudIntegration.tenant_id == tenant.id)
            .order_by(CloudIntegration.updated_at.desc())
        )
    ).scalars().all()
    registered = set(ConnectorRegistry.registered_providers())
    breakers = ConnectorRegistry.circuit_breaker_status()
    return ConnectorHealthListResponse(
        registered_providers=sorted(registered),
        circuit_breakers=breakers,
        items=[_health_response(item, registered, breakers) for item in items],
    )


@router.get("/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    return _integration_response(await _get_integration_or_404(integration_id, tenant.id, db))


@router.patch("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: uuid.UUID,
    body: IntegrationUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    integration = await _get_integration_or_404(integration_id, tenant.id, db)
    new_target = body.target_identifier or integration.target_identifier

    if body.credentials is not None:
        validation = await _validate_credentials(
            tenant.id,
            integration.provider_type,
            new_target,
            body.credentials,
        )
        if not validation.valid:
            raise BadRequestException(detail=f"Integration validation failed: {validation.error_code}")
        integration.vault_reference_id = await vault_credential_service.store(
            tenant.id,
            integration.id,
            body.credentials,
        )

    if body.target_identifier is not None:
        integration.target_identifier = body.target_identifier
    if body.display_name is not None:
        integration.display_name = body.display_name
    if body.status is not None:
        integration.status = body.status

    await db.flush()
    await db.refresh(integration)
    await db.commit()
    await _publish_event(
        INTEGRATION_EVENTS_TOPIC,
        _lifecycle_event(IntegrationUpdatedEvent, integration, current_user.id),
    )
    return _integration_response(integration)


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    integration = await _get_integration_or_404(integration_id, tenant.id, db)
    await vault_credential_service.delete(tenant.id, integration.vault_reference_id)
    integration.status = IntegrationStatus.disabled
    integration.error_message = None
    await db.flush()
    await db.commit()
    await _publish_event(
        INTEGRATION_EVENTS_TOPIC,
        _lifecycle_event(IntegrationDeletedEvent, integration, current_user.id, deletion_mode="disabled"),
    )


@router.post("/{integration_id}/validate", response_model=IntegrationValidationResponse)
async def validate_existing_integration(
    integration_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    integration = await _get_integration_or_404(integration_id, tenant.id, db)
    credentials = await vault_credential_service.retrieve(tenant.id, integration.vault_reference_id)
    validation = await _validate_credentials(
        tenant.id,
        integration.provider_type,
        integration.target_identifier,
        credentials,
    )
    await _publish_event(
        INTEGRATION_EVENTS_TOPIC,
        IntegrationValidationCompletedEvent(
            tenant_id=str(tenant.id),
            integration_id=str(integration.id),
            provider_type=integration.provider_type.value,
            target_identifier=integration.target_identifier,
            actor_id=str(current_user.id),
            valid=validation.valid,
            error_code=validation.error_code,
            missing_permissions=validation.missing_permissions,
        ),
    )
    return validation


@router.post("/{integration_id}/sync", response_model=IntegrationSyncResponse, status_code=202)
async def request_integration_sync(
    integration_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    integration = await _get_integration_or_404(integration_id, tenant.id, db)
    if integration.status == IntegrationStatus.disabled:
        raise BadRequestException(detail="Disabled integrations cannot be synced")

    event = IntegrationSyncRequestedEvent(
        tenant_id=str(tenant.id),
        integration_id=str(integration.id),
        provider_type=integration.provider_type.value,
        target_identifier=integration.target_identifier,
        status=integration.status.value,
        actor_id=str(current_user.id),
    )
    await _publish_event(CONNECTOR_SCAN_TOPIC, event)
    await _publish_event(INTEGRATION_EVENTS_TOPIC, event)
    return IntegrationSyncResponse(integration_id=integration.id)


@router.get("/{integration_id}/health", response_model=IntegrationHealthResponse)
async def integration_health(
    integration_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    _load_connector_modules()
    integration = await _get_integration_or_404(integration_id, tenant.id, db)
    registered = set(ConnectorRegistry.registered_providers())
    breakers = ConnectorRegistry.circuit_breaker_status()
    return _health_response(integration, registered, breakers)


def _health_response(
    integration: CloudIntegration,
    registered: set[str],
    breakers: dict[str, dict],
) -> IntegrationHealthResponse:
    provider = integration.provider_type.value
    return IntegrationHealthResponse(
        integration_id=integration.id,
        provider_type=integration.provider_type,
        status=integration.status,
        last_sync_at=integration.last_sync_at,
        last_success_at=integration.last_sync_at if integration.status == IntegrationStatus.active else None,
        last_failure_at=integration.updated_at if integration.status == IntegrationStatus.error else None,
        last_error_code=sanitize_text(integration.error_message)[:240]
        if integration.error_message
        else None,
        circuit_breaker_state=breakers.get(provider),
        registered_connector_available=provider in registered,
    )
