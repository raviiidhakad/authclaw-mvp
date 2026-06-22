"""
AuthClaw HITL (Human-In-The-Loop) Approval Endpoints.

Security Properties Enforced:
  1. MFA-gated:        Approval requires a valid TOTP code.
  2. Non-transferable: Only the requesting user (or an Admin/Owner) can approve.
  3. Single-use:       Only pending approvals can be actioned.
  4. Expiring:         Approvals older than 30 minutes auto-expire.
  5. Audited:          Every approval action fires an audit event to Kafka.
"""
import uuid
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.api.dependencies import get_current_tenant, get_current_user, require_roles
from app.models.user import User
from app.models.tenant import Tenant
from app.models.approval import Approval, ApprovalStatus
from app.schemas.approval import ApprovalResponse
from app.schemas.auth import MFAVerifyRequest
from app.core.exceptions import UnauthorizedException, BadRequestException, NotFoundException
import pyotp

router = APIRouter()

APPROVAL_TTL_MINUTES = 30


async def _publish_approval_event(
    event_type: str,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    approval_id: uuid.UUID,
    extra: dict = None,
) -> None:
    """
    Publishes an approval lifecycle event to the audit Kafka topic.

    Parameters
    ----------
    event_type  : Dotted event name, e.g. ``"approval.approved"``.
    tenant_id   : UUID of the tenant that owns the approval.
    user_id     : UUID of the user performing the action.
    approval_id : UUID of the approval being actioned.
    extra       : Optional extra key/value pairs merged into the payload.
    """
    from app.core.events.producer import producer
    from app.schemas.events import AuditEvent

    payload = {
        "action": event_type.split(".")[-1],
        "resource": "approval",
        "resource_id": str(approval_id),
    }
    if extra:
        payload.update(extra)

    await producer.publish(
        "authclaw.audit.events",
        AuditEvent(
            event_type=event_type,
            tenant_id=str(tenant_id),
            actor_id=str(user_id),
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload=payload,
        ),
    )


@router.get("", response_model=List[ApprovalResponse])
async def list_approvals(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "operator", "auditor", "viewer"])),
):
    """List all approvals for the current tenant, ordered newest first."""
    result = await db.execute(
        select(Approval)
        .where(Approval.tenant_id == tenant.id)
        .order_by(Approval.created_at.desc())
    )
    return result.scalars().all()


@router.post("/{approval_id}/approve", response_model=ApprovalResponse)
async def approve_action(
    approval_id: uuid.UUID,
    mfa_request: MFAVerifyRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve a pending action.

    Security gates (evaluated in order):
      1. Approval must exist and belong to this tenant.
      2. Approval must be in ``pending`` status.
      3. Approval must not have exceeded its 30-minute TTL.
      4. Caller must be the original requester OR hold an Admin/Owner role.
      5. Caller must supply a valid TOTP MFA code.
    """
    # ── Gate 1: Existence ────────────────────────────────────────────────────
    result = await db.execute(
        select(Approval).where(
            Approval.id == approval_id,
            Approval.tenant_id == tenant.id,
        )
    )
    approval = result.scalars().first()
    if not approval:
        raise NotFoundException(detail="Approval not found")

    # ── Gate 2: Status ───────────────────────────────────────────────────────
    if approval.status != ApprovalStatus.pending:
        raise BadRequestException(
            detail=f"Only pending approvals can be approved. Current status: {approval.status.value}"
        )

    # ── Gate 3: Expiry ───────────────────────────────────────────────────────
    if approval.expires_at and datetime.utcnow() > approval.expires_at:
        approval.status = ApprovalStatus.expired
        approval.resolved_at = datetime.utcnow()
        await db.commit()
        await _publish_approval_event(
            "approval.expired", tenant.id, current_user.id, approval.id
        )
        raise BadRequestException(
            detail="This approval has expired. Please request a new remediation plan."
        )

    # ── Gate 4: Non-transferable RBAC ────────────────────────────────────────
    from app.models.role import UserRole, Role
    role_result = await db.execute(
        select(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .where(
            UserRole.user_id == current_user.id,
            UserRole.tenant_id == tenant.id,
        )
    )
    user_roles = {row[0] for row in role_result.all()}
    is_privileged = bool(user_roles & {"owner", "admin"})

    if not is_privileged:
        # Non-admin users can only approve their own requests
        if (
            approval.requested_by_user_id
            and approval.requested_by_user_id != current_user.id
        ):
            raise UnauthorizedException(
                detail=(
                    "Approvals are non-transferable. "
                    "Only the requesting user or an Admin can approve this action."
                )
            )

    # ── Gate 5: MFA ──────────────────────────────────────────────────────────
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise BadRequestException(detail="You must set up MFA before approving actions.")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(mfa_request.code):
        raise UnauthorizedException(detail="Invalid MFA code. Approval denied.")

    # ── All gates passed — execute ────────────────────────────────────────────
    approval.status = ApprovalStatus.executed
    approval.resolved_at = datetime.utcnow()
    await db.flush()
    await db.refresh(approval)
    await db.commit()

    await _publish_approval_event(
        "approval.approved",
        tenant.id,
        current_user.id,
        approval.id,
        extra={"action_type": approval.action_type.value, "title": approval.title},
    )

    return approval


@router.post("/{approval_id}/reject", response_model=ApprovalResponse)
async def reject_action(
    approval_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Reject a pending action.

    Any authenticated tenant user can reject. Fires an audit event to Kafka.
    """
    result = await db.execute(
        select(Approval).where(
            Approval.id == approval_id,
            Approval.tenant_id == tenant.id,
        )
    )
    approval = result.scalars().first()
    if not approval:
        raise NotFoundException(detail="Approval not found")

    if approval.status != ApprovalStatus.pending:
        raise BadRequestException(
            detail=f"Only pending approvals can be rejected. Current status: {approval.status.value}"
        )

    approval.status = ApprovalStatus.rejected
    approval.resolved_at = datetime.utcnow()
    await db.flush()
    await db.refresh(approval)
    await db.commit()

    await _publish_approval_event(
        "approval.rejected",
        tenant.id,
        current_user.id,
        approval.id,
        extra={"action_type": approval.action_type.value, "title": approval.title},
    )

    return approval
