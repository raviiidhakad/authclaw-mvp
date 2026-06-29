"""
Gateway Route CRUD endpoints.
All operations are tenant-scoped.
Manages the routing rules that map client requests to AI providers.
"""
import uuid
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException, BadRequestException
from app.models.gateway_route import GatewayRoute, RedactionStrategy
from app.models.policy import Policy
from app.models.provider import Provider
from app.models.tenant import Tenant
from app.models.user import User
from app.services.api_safety import SECRET_FIELD_NAMES, sanitize_text

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class GatewayRouteCreate(BaseModel):
    """Request body for creating a new gateway route."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    provider_id: uuid.UUID
    is_default: bool = False
    is_active: bool = True
    redaction: RedactionStrategy = RedactionStrategy.none
    config: Dict[str, Any] = Field(default_factory=dict)


class GatewayRouteUpdate(BaseModel):
    """Request body for partially updating a gateway route (PATCH semantics)."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    provider_id: Optional[uuid.UUID] = None
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None
    redaction: Optional[RedactionStrategy] = None
    config: Optional[Dict[str, Any]] = None


class GatewayRouteResponse(BaseModel):
    """Serialised representation of a GatewayRoute returned to callers."""
    id: uuid.UUID
    tenant_id: uuid.UUID
    provider_id: Optional[uuid.UUID]
    name: str
    description: Optional[str]
    is_default: bool
    is_active: bool
    redaction: RedactionStrategy
    config: Dict[str, Any]
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


SAFE_ROUTE_CONFIG_FIELDS = {"model", "default_model", "temperature", "max_tokens", "policy_id"}


def _sanitize_route_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in dict(config or {}).items():
        lowered = str(key).lower()
        if lowered in SECRET_FIELD_NAMES or "vault" in lowered or "raw" in lowered:
            continue
        if key not in SAFE_ROUTE_CONFIG_FIELDS:
            continue
        sanitized[key] = sanitize_text(value) if isinstance(value, str) else value
    return sanitized


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_route_or_404(
    route_id: uuid.UUID,
    tenant_id: uuid.UUID,
    db: AsyncSession,
) -> GatewayRoute:
    """Fetch a single route scoped to a tenant, raising 404 if absent."""
    result = await db.execute(
        select(GatewayRoute).where(
            GatewayRoute.id == route_id,
            GatewayRoute.tenant_id == tenant_id,
        )
    )
    route = result.scalars().first()
    if not route:
        raise NotFoundException(detail="Gateway route not found")
    return route


async def _ensure_single_default(
    tenant_id: uuid.UUID,
    exclude_id: Optional[uuid.UUID],
    db: AsyncSession,
) -> None:
    """
    Demotes any existing default route for the tenant so that only one
    route ever carries is_default=True.  The route identified by
    `exclude_id` (i.e. the one being promoted) is skipped.
    """
    stmt = select(GatewayRoute).where(
        GatewayRoute.tenant_id == tenant_id,
        GatewayRoute.is_default == True,  # noqa: E712 — SQLAlchemy requires == not 'is'
    )
    if exclude_id:
        stmt = stmt.where(GatewayRoute.id != exclude_id)
    result = await db.execute(stmt)
    for r in result.scalars().all():
        r.is_default = False


def _serialize(route: GatewayRoute) -> GatewayRouteResponse:
    """Convert an ORM instance to the response schema."""
    data = {c.key: getattr(route, c.key) for c in route.__table__.columns}
    data["config"] = _sanitize_route_config(data.get("config"))
    data["created_at"] = route.created_at.isoformat()
    data["updated_at"] = route.updated_at.isoformat()
    return GatewayRouteResponse(**data)


async def _ensure_tenant_provider(provider_id: uuid.UUID, tenant_id: uuid.UUID, db: AsyncSession) -> Provider:
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.tenant_id == tenant_id)
    )
    provider = result.scalars().first()
    if not provider:
        raise BadRequestException(detail="Gateway route provider must belong to this tenant.")
    return provider


async def _ensure_tenant_policy(policy_id_value: Any, tenant_id: uuid.UUID, db: AsyncSession) -> Policy | None:
    if not policy_id_value:
        return None
    try:
        policy_id = uuid.UUID(str(policy_id_value))
    except ValueError as exc:
        raise BadRequestException(detail="Gateway route policy_id must be a valid UUID.") from exc
    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_id,
            Policy.tenant_id == tenant_id,
            Policy.is_active == True,
        )
    )
    policy = result.scalars().first()
    if not policy:
        raise BadRequestException(detail="Gateway route policy must belong to this tenant and be active.")
    return policy


def _validate_redaction(redaction: RedactionStrategy) -> None:
    if redaction not in {RedactionStrategy.mask, RedactionStrategy.hash, RedactionStrategy.synthetic}:
        raise BadRequestException(detail="Gateway route redaction must be mask, hash, or synthetic.")


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[GatewayRouteResponse])
async def list_gateway_routes(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    """List all gateway routes for the current tenant, default route first."""
    result = await db.execute(
        select(GatewayRoute)
        .where(GatewayRoute.tenant_id == tenant.id)
        .order_by(GatewayRoute.is_default.desc(), GatewayRoute.created_at.asc())
    )
    return [_serialize(r) for r in result.scalars().all()]


@router.post("", response_model=GatewayRouteResponse, status_code=201)
async def create_gateway_route(
    body: GatewayRouteCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """
    Create a new gateway route.

    If `is_default=True`, any existing default for this tenant is demoted
    first so the invariant of a single default per tenant is maintained.
    Fires an audit event to Kafka on success.
    """
    _validate_redaction(body.redaction)
    await _ensure_tenant_provider(body.provider_id, tenant.id, db)
    sanitized_config = _sanitize_route_config(body.config)
    await _ensure_tenant_policy(sanitized_config.get("policy_id"), tenant.id, db)
    if body.is_default:
        await _ensure_single_default(tenant.id, None, db)

    route = GatewayRoute(
        tenant_id=tenant.id,
        provider_id=body.provider_id,
        name=body.name,
        description=body.description,
        is_default=body.is_default,
        is_active=body.is_active,
        redaction=body.redaction,
        config=sanitized_config,
    )
    db.add(route)
    await db.flush()
    await db.refresh(route)
    await db.commit()

    # Publish audit event
    from app.core.events.producer import producer
    from app.schemas.events import AuditEvent
    from datetime import datetime
    await producer.publish(
        "authclaw.audit.events",
        AuditEvent(
            event_type="admin.gateway_route_created",
            tenant_id=str(tenant.id),
            actor_id=str(current_user.id),
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload={
                "action": "create",
                "resource": "gateway_route",
                "resource_id": str(route.id),
                "name": route.name,
            },
        ),
    )

    return _serialize(route)


@router.get("/{route_id}", response_model=GatewayRouteResponse)
async def get_gateway_route(
    route_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator"])),
):
    """Get a specific gateway route by ID (tenant-scoped)."""
    route = await _get_route_or_404(route_id, tenant.id, db)
    return _serialize(route)


@router.patch("/{route_id}", response_model=GatewayRouteResponse)
async def update_gateway_route(
    route_id: uuid.UUID,
    body: GatewayRouteUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """
    Partially update a gateway route (PATCH semantics — only supplied
    fields are written).

    Promoting a route to default automatically demotes the previous default.
    Fires an audit event to Kafka on success.
    """
    route = await _get_route_or_404(route_id, tenant.id, db)

    if body.is_default is True:
        await _ensure_single_default(tenant.id, route_id, db)
    if body.redaction is not None:
        _validate_redaction(body.redaction)
    if body.provider_id is not None:
        await _ensure_tenant_provider(body.provider_id, tenant.id, db)

    if body.name is not None:
        route.name = body.name
    if body.description is not None:
        route.description = body.description
    if body.provider_id is not None:
        route.provider_id = body.provider_id
    if body.is_default is not None:
        route.is_default = body.is_default
    if body.is_active is not None:
        route.is_active = body.is_active
    if body.redaction is not None:
        route.redaction = body.redaction
    if body.config is not None:
        sanitized_config = _sanitize_route_config(body.config)
        await _ensure_tenant_policy(sanitized_config.get("policy_id"), tenant.id, db)
        route.config = sanitized_config

    await db.flush()
    await db.refresh(route)
    await db.commit()

    from app.core.events.producer import producer
    from app.schemas.events import AuditEvent
    from datetime import datetime
    await producer.publish(
        "authclaw.audit.events",
        AuditEvent(
            event_type="admin.gateway_route_updated",
            tenant_id=str(tenant.id),
            actor_id=str(current_user.id),
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload={
                "action": "update",
                "resource": "gateway_route",
                "resource_id": str(route.id),
            },
        ),
    )

    return _serialize(route)


@router.delete("/{route_id}", status_code=204)
async def delete_gateway_route(
    route_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """
    Delete a gateway route.

    Returns HTTP 204 No Content on success.
    Fires an audit event to Kafka.
    """
    route = await _get_route_or_404(route_id, tenant.id, db)
    await db.delete(route)
    await db.commit()

    from app.core.events.producer import producer
    from app.schemas.events import AuditEvent
    from datetime import datetime
    await producer.publish(
        "authclaw.audit.events",
        AuditEvent(
            event_type="admin.gateway_route_deleted",
            tenant_id=str(tenant.id),
            actor_id=str(current_user.id),
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload={
                "action": "delete",
                "resource": "gateway_route",
                "resource_id": str(route_id),
            },
        ),
    )
