"""
Policy CRUD endpoints + Violation management.
All operations are tenant-scoped.
"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
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
    PolicyRuleResponse,
    PolicyListResponse,
    PolicyTestRequest,
    PolicyTestResponse,
    PolicyYamlExportResponse,
    PolicyYamlImportResponse,
    PolicyYamlRequest,
    PolicyYamlValidationResponse,
    ViolationResponse,
    ViolationListResponse,
    ViolationUpdateResolution,
)
from app.core.policy.yaml_policy import (
    PythonPolicyAdapter,
    export_policy_yaml,
    normalized_from_policy,
    policy_from_normalized,
    validate_policy_yaml,
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


def _build_policy_response(policy: Policy, rules: list[PolicyRule]) -> PolicyResponse:
    return PolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        name=policy.name,
        description=policy.description,
        is_active=policy.is_active,
        priority=policy.priority,
        rules=[PolicyRuleResponse.model_validate(rule) for rule in rules],
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


# ── Policy routes ────────────────────────────────────────────────
def _validation_response(yaml_source: str) -> PolicyYamlValidationResponse:
    return PolicyYamlValidationResponse(**validate_policy_yaml(yaml_source).as_response())


@router.post("/validate", response_model=PolicyYamlValidationResponse)
async def validate_policy(
    body: PolicyYamlRequest,
    _tenant: Tenant = Depends(get_current_tenant),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    """Validate YAML policy-as-code without saving it."""
    return _validation_response(body.yaml_source)


@router.post("/test", response_model=PolicyTestResponse)
async def test_policy(
    body: PolicyTestRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor"])),
):
    """Evaluate sample text against a YAML or stored policy without echoing the text."""
    validation_payload: PolicyYamlValidationResponse | None = None
    if body.yaml_source:
        validation_payload = _validation_response(body.yaml_source)
        if not validation_payload.valid or not validation_payload.normalized:
            return PolicyTestResponse(
                allowed=False,
                blocked=True,
                action="validation_failed",
                matched_rules=[],
                redaction_required=False,
                reason="Policy validation failed.",
                validation=validation_payload,
            )
        normalized = validation_payload.normalized
    elif body.policy_id:
        policy = await _get_policy_or_404(body.policy_id, tenant.id, db)
        normalized = normalized_from_policy(policy)
    else:
        raise HTTPException(status_code=400, detail="Provide yaml_source or policy_id.")

    decision = PythonPolicyAdapter().evaluate(body.sample_text, normalized)
    return PolicyTestResponse(
        allowed=bool(decision["allowed"]),
        blocked=not bool(decision["allowed"]),
        action=str(decision["action"]),
        matched_rules=decision["matched_rules"],
        redaction_required=bool(decision["redaction_required"]),
        reason=str(decision["reason"]),
        validation=validation_payload,
    )


@router.post("/import-yaml", response_model=PolicyYamlImportResponse, status_code=201)
async def import_policy_yaml(
    body: PolicyYamlRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["owner", "admin"])),
):
    """Import YAML policy-as-code into the existing policy/rule tables."""
    validation = _validation_response(body.yaml_source)
    if not validation.valid or not validation.normalized:
        raise HTTPException(status_code=400, detail={"message": "Policy YAML validation failed.", "errors": validation.errors})

    policy = policy_from_normalized(validation.normalized, tenant.id)
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    response = _build_policy_response(policy, list(policy.rules))
    await db.commit()
    await _publish_policy_event("policy.created", tenant.id, current_user.id, policy.id, policy.name)
    from app.core.policy.cache import policy_cache
    await policy_cache.invalidate(tenant.id)
    return PolicyYamlImportResponse(policy=response, validation=validation)


@router.get("/{policy_id}/export-yaml", response_model=PolicyYamlExportResponse)
async def export_policy(
    policy_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor"])),
):
    """Export a stored policy as AuthClaw YAML policy-as-code."""
    policy = await _get_policy_or_404(policy_id, tenant.id, db)
    return PolicyYamlExportResponse(
        policy_id=policy.id,
        schema_version="authclaw.policy/v1",
        yaml_source=export_policy_yaml(policy),
    )


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
    created_rules: list[PolicyRule] = []
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
        created_rules.append(rule)

    await db.flush()
    response = _build_policy_response(policy, created_rules)
    await db.commit()
    await _publish_policy_event(
        "policy.created", tenant.id, current_user.id, policy.id, policy.name
    )
    # Sprint 1: Invalidate Redis policy cache for this tenant
    from app.core.policy.cache import policy_cache
    await policy_cache.invalidate(tenant.id)

    return response


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
    return policy


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
