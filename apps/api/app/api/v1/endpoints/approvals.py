import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.api.dependencies import get_current_tenant, get_current_user
from app.models.user import User
from app.models.tenant import Tenant
from app.models.approval import Approval, ApprovalStatus
from app.schemas.approval import ApprovalResponse
from app.schemas.auth import MFAVerifyRequest
from app.core.exceptions import UnauthorizedException, BadRequestException
import pyotp

router = APIRouter()

@router.get("/", response_model=List[ApprovalResponse])
async def list_approvals(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """List all approvals for the current tenant."""
    result = await db.execute(
        select(Approval).where(Approval.tenant_id == tenant.id).order_by(Approval.created_at.desc())
    )
    return result.scalars().all()

@router.post("/{approval_id}/approve", response_model=ApprovalResponse)
async def approve_action(
    approval_id: uuid.UUID,
    mfa_request: MFAVerifyRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Approve a pending action and execute it."""
    # Verify MFA Code
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise BadRequestException(detail="You must setup MFA before approving actions.")
        
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(mfa_request.code):
        raise UnauthorizedException(detail="Invalid MFA code. Approval denied.")

    result = await db.execute(
        select(Approval).where(Approval.id == approval_id, Approval.tenant_id == tenant.id)
    )
    approval = result.scalars().first()
    
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
        
    if approval.status != ApprovalStatus.pending:
        raise HTTPException(status_code=400, detail="Only pending actions can be approved")
        
    # Mock execution logic
    # In a real app, this would trigger the 'executor_node' in LangGraph or run the terraform script
    
    approval.status = ApprovalStatus.executed
    approval.resolved_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(approval)
    
    return approval

@router.post("/{approval_id}/reject", response_model=ApprovalResponse)
async def reject_action(
    approval_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Reject a pending action."""
    result = await db.execute(
        select(Approval).where(Approval.id == approval_id, Approval.tenant_id == tenant.id)
    )
    approval = result.scalars().first()
    
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
        
    if approval.status != ApprovalStatus.pending:
        raise HTTPException(status_code=400, detail="Only pending actions can be rejected")
        
    approval.status = ApprovalStatus.rejected
    approval.resolved_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(approval)
    
    return approval
