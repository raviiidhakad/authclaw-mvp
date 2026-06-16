import io
import csv
import uuid
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from datetime import datetime, timedelta

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException
from app.models.tenant import Tenant
from app.models.user import User
from app.models.audit import AuditLog, EventType
from app.models.gateway import GatewayRequest
from app.models.policy import PolicyViolation

router = APIRouter()

@router.get("/logs")
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    event_type: EventType | None = Query(None),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve audit logs for the current tenant."""
    base = select(AuditLog).where(AuditLog.tenant_id == tenant.id)
    if event_type:
        base = base.where(AuditLog.event_type == event_type)

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    items_q = base.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)
    logs = (await db.execute(items_q)).scalars().all()
    
    return {
        "items": [{
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "event_type": log.event_type.value,
            "resource": log.resource,
            "resource_id": log.resource_id,
            "action": log.action.value,
            "metadata": log.metadata_,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat(),
        } for log in logs],
        "total": total
    }


@router.get("/logs/export")
async def export_audit_logs(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Export all audit logs for the current tenant as CSV."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant.id)
        .order_by(AuditLog.created_at.asc())
    )
    logs = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "user_id", "event_type", "resource", "resource_id", "action", "ip_address", "created_at"])
    for log in logs:
        writer.writerow([
            str(log.id),
            str(log.user_id) if log.user_id else "",
            log.event_type.value,
            log.resource or "",
            log.resource_id or "",
            log.action.value,
            log.ip_address or "",
            log.created_at.isoformat(),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
    )


@router.get("/logs/{log_id}")
async def get_audit_log(
    log_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve a single audit log entry by ID."""
    result = await db.execute(
        select(AuditLog).where(AuditLog.id == log_id, AuditLog.tenant_id == tenant.id)
    )
    log = result.scalars().first()
    if not log:
        raise NotFoundException(detail="Audit log not found")

    return {
        "id": str(log.id),
        "user_id": str(log.user_id) if log.user_id else None,
        "event_type": log.event_type.value,
        "resource": log.resource,
        "resource_id": log.resource_id,
        "action": log.action.value,
        "metadata": log.metadata_,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "created_at": log.created_at.isoformat(),
    }




@router.get("/stats")
async def get_audit_stats(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve aggregate statistics from the gateway_requests table (accurate counts)."""
    from app.models.gateway import GatewayRequest, RequestStatus

    # Total gateway requests (NOT all audit log entries)
    total_q = select(func.count(GatewayRequest.id)).where(GatewayRequest.tenant_id == tenant.id)
    total_events = (await db.execute(total_q)).scalar() or 0

    # By status from gateway_requests — ground truth
    status_q = (
        select(GatewayRequest.status, func.count(GatewayRequest.id))
        .where(GatewayRequest.tenant_id == tenant.id)
        .group_by(GatewayRequest.status)
    )
    status_rows = (await db.execute(status_q)).all()
    gateway_by_status = {row[0].value: row[1] for row in status_rows}

    # Map to the dict keys the frontend expects
    events_by_type = {
        "gateway.request": gateway_by_status.get("completed", 0),
        "gateway.blocked": gateway_by_status.get("blocked", 0),
        "gateway.error":   gateway_by_status.get("error", 0),
        # Keep policy.violation count from actual violations table
        "policy.violation": 0,  # filled below
    }

    # Violation count from policy_violations table
    from app.models.policy import PolicyViolation
    viol_q = select(func.count(PolicyViolation.id)).where(PolicyViolation.tenant_id == tenant.id)
    events_by_type["policy.violation"] = (await db.execute(viol_q)).scalar() or 0

    # Events in last 24h / 7d (gateway requests)
    since_24h = datetime.utcnow() - timedelta(hours=24)
    recent_q = select(func.count(GatewayRequest.id)).where(
        GatewayRequest.tenant_id == tenant.id,
        GatewayRequest.created_at >= since_24h
    )
    events_last_24h = (await db.execute(recent_q)).scalar() or 0

    since_7d = datetime.utcnow() - timedelta(days=7)
    week_q = select(func.count(GatewayRequest.id)).where(
        GatewayRequest.tenant_id == tenant.id,
        GatewayRequest.created_at >= since_7d
    )
    events_last_7d = (await db.execute(week_q)).scalar() or 0

    return {
        "total_events": total_events,
        "events_last_24h": events_last_24h,
        "events_last_7d": events_last_7d,
        "events_by_type": events_by_type,
        "gateway_by_status": gateway_by_status,
    }


@router.get("/violations")
async def get_policy_violations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve policy violations for the current tenant."""
    result = await db.execute(
        select(PolicyViolation)
        .where(PolicyViolation.tenant_id == tenant.id)
        .order_by(desc(PolicyViolation.created_at))
        .offset(skip)
        .limit(limit)
    )
    violations = result.scalars().all()
    
    return [{
        "id": str(v.id),
        "request_id": str(v.request_id) if v.request_id else None,
        "policy_id": str(v.policy_id) if v.policy_id else None,
        "severity": v.severity.value,
        "description": v.description,
        "resolution": v.resolution.value,
        "created_at": v.created_at.isoformat()
    } for v in violations]
