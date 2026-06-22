"""
Policy CRUD endpoints + Violation management.
All operations are tenant-scoped.
"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.api.dependencies import get_db, get_current_user, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException
from app.models.policy import Policy, PolicyRule, PolicyViolation, ViolationSeverity
from app.models.user import User
from app.models.tenant import Tenant
from app.schemas.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    PolicyListResponse,
    ViolationResponse,
    ViolationListResponse,
    ViolationUpdateResolution,
)

router = APIRouter()


# ── Event helpers ─────────────────────────────────────────────────
async def _publish_policy_event(
    event_type: str,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    policy_id: uuid.UUID,
    policy_name: str,
) -> None:
    """Fire a Kafka audit event for policy lifecycle changes.

    Args:
        event_type:   Dot-separated event identifier, e.g. ``"policy.created"``.
        tenant_id:    UUID of the owning tenant.
        user_id:      UUID of the acting user.
        policy_id:    UUID of the affected policy.
        policy_name:  Human-readable name of the policy for log enrichment.
    """
    from app.core.events.producer import producer
    from app.schemas.events import AuditEvent

    await producer.publish(
        "authclaw.audit.events",
        AuditEvent(
            event_type=event_type,
            tenant_id=str(tenant_id),
            actor_id=str(user_id),
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload={
                "action": event_type.split(".")[-1],
                "resource": "policy",
                "resource_id": str(policy_id),
                "name": policy_name,
            },
        ),
    )


# ── helpers ──────────────────────────────────────────────────────
async def _get_policy_or_404(
    policy_id: uuid.UUID,
    tenant_id: uuid.UUID,
    db: AsyncSession,
) -> Policy:
    result = await db.execute(
        select(Policy)
        .options(selectinload(Policy.rules))
        .where(Policy.id == policy_id, Policy.tenant_id == tenant_id)
    )
    policy = result.scalars().first()
    if not policy:
        raise NotFoundException(detail="Policy not found")
    return policy


# ── Policy routes ────────────────────────────────────────────────
@router.get("", response_model=PolicyListResponse)
async def list_policies(
    skip: int = 0,
    limit: int = 50,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    """List all policies for the current tenant."""
    count_q = select(func.count()).select_from(Policy).where(Policy.tenant_id == tenant.id)
    total = (await db.execute(count_q)).scalar() or 0

    items_q = (
        select(Policy)
        .options(selectinload(Policy.rules))
        .where(Policy.tenant_id == tenant.id)
        .order_by(Policy.priority.desc(), Policy.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    items = (await db.execute(items_q)).scalars().all()
    return PolicyListResponse(items=items, total=total)


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    body: PolicyCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """Create a new policy with optional inline rules."""
    policy = Policy(
        tenant_id=tenant.id,
        name=body.name,
        description=body.description,
        is_active=body.is_active,
        priority=body.priority,
    )
    db.add(policy)
    await db.flush()

    # Create inline rules if provided
    for rule_data in body.rules:
        rule = PolicyRule(
            policy_id=policy.id,
            rule_type=rule_data.rule_type,
            conditions=rule_data.conditions,
            action=rule_data.action,
            message=rule_data.message,
            is_active=rule_data.is_active,
        )
        db.add(rule)

    await db.commit()
    await _publish_policy_event(
        "policy.created", tenant.id, current_user.id, policy.id, policy.name
    )
    # Sprint 1: Invalidate Redis policy cache for this tenant
    from app.core.policy.cache import policy_cache
    await policy_cache.invalidate(tenant.id)

    # Re-fetch with eager-loaded rules
    return await _get_policy_or_404(policy.id, tenant.id, db)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator"])),
):
    """Get a specific policy by ID."""
    return await _get_policy_or_404(policy_id, tenant.id, db)


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """Update a policy's metadata and optionally replace all its rules."""
    policy = await _get_policy_or_404(policy_id, tenant.id, db)

    if body.name is not None:
        policy.name = body.name
    if body.description is not None:
        policy.description = body.description
    if body.is_active is not None:
        policy.is_active = body.is_active
    if body.priority is not None:
        policy.priority = body.priority

    if body.rules is not None:
        # TODO: Future support for partial nested updates.
        # MVP Implementation: Delete all existing rules and insert the submitted rules.
        
        # SQLAlchemy cascade deletes the rules if we replace the collection or delete them.
        # However, it's safer to explicitly delete them.
        await db.execute(
            select(PolicyRule).where(PolicyRule.policy_id == policy.id)
        )
        
        # We can just empty the policy.rules list (since cascade="all, delete-orphan" is set)
        policy.rules = []
        
        # Add the new rules
        for rule_data in body.rules:
            new_rule = PolicyRule(
                policy_id=policy.id,
                rule_type=rule_data.rule_type,
                conditions=rule_data.conditions,
                action=rule_data.action,
                message=rule_data.message,
                is_active=rule_data.is_active,
            )
            policy.rules.append(new_rule)

    await db.commit()
    await _publish_policy_event(
        "policy.updated", tenant.id, current_user.id, policy.id, policy.name
    )
    # Sprint 1: Invalidate Redis policy cache for this tenant
    from app.core.policy.cache import policy_cache
    await policy_cache.invalidate(tenant.id)
    # Refresh to ensure relationships are loaded
    return await _get_policy_or_404(policy.id, tenant.id, db)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """Delete a policy and all its rules."""
    policy = await _get_policy_or_404(policy_id, tenant.id, db)

    # Capture identity fields before the ORM object is expunged by delete()
    deleted_policy_id: uuid.UUID = policy.id
    deleted_policy_name: str = policy.name

    await db.delete(policy)
    await db.commit()
    await _publish_policy_event(
        "policy.deleted", tenant.id, current_user.id, deleted_policy_id, deleted_policy_name
    )
    # Sprint 1: Invalidate Redis policy cache for this tenant
    from app.core.policy.cache import policy_cache
    await policy_cache.invalidate(tenant.id)



# ── Violation routes ─────────────────────────────────────────────
@router.get("/violations/list", response_model=ViolationListResponse)
async def list_violations(
    skip: int = 0,
    limit: int = 50,
    severity: ViolationSeverity | None = Query(None),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    """List policy violations for the current tenant."""
    base = select(PolicyViolation).where(PolicyViolation.tenant_id == tenant.id)
    if severity:
        base = base.where(PolicyViolation.severity == severity)

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    items_q = base.order_by(PolicyViolation.created_at.desc()).offset(skip).limit(limit)
    items = (await db.execute(items_q)).scalars().all()
    return ViolationListResponse(items=items, total=total)


@router.patch("/violations/{violation_id}", response_model=ViolationResponse)
async def update_violation_resolution(
    violation_id: uuid.UUID,
    body: ViolationUpdateResolution,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator"])),
):
    """Update the resolution status of a violation."""
    result = await db.execute(
        select(PolicyViolation).where(
            PolicyViolation.id == violation_id,
            PolicyViolation.tenant_id == tenant.id,
        )
    )
    violation = result.scalars().first()
    if not violation:
        raise NotFoundException(detail="Violation not found")

    violation.resolution = body.resolution
    await db.flush()
    await db.refresh(violation)
    await db.commit()
    return violation
