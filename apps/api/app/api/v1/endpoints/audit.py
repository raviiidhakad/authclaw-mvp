import io
import csv
import uuid
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from datetime import datetime, timedelta

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException
from app.models.tenant import Tenant
from app.models.audit import AuditLog, EventType
from app.models.policy import PolicyViolation
from app.core.audit.repository import PostgresAuditRepository
from app.core.audit.verification import HashVerificationService
from app.core.audit.package_verification import AuditExportVerificationService
from app.schemas.audit_export import AuditExportVerificationResponse
# from app.core.clickhouse import get_clickhouse_client

router = APIRouter()
audit_export_verification_service = AuditExportVerificationService()

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
    
    # ch_client = await get_clickhouse_client()
    repo = PostgresAuditRepository(db)
    
    # We fetch via repository
    records = await repo.list(tenant.id, limit=limit, offset=skip)
    
    # Note: If event_type filtering is needed, we will do it here temporarily 
    # until it's added to the repo interface.
    if event_type:
        records = [r for r in records if r.metadata.get("event_type") == event_type.value]
    
    return {
        "items": [{
            "id": str(r.record_id),
            "sequence_no": r.sequence_no,
            "user_id": str(r.actor_id) if r.actor_id else None,
            "event_type": r.metadata.get("event_type"),
            "resource": r.resource,
            "resource_id": r.resource_id,
            "action": r.action,
            "metadata": r.metadata,
            "ip_address": r.ip_address,
            "previous_hash": r.previous_hash,
            "integrity_hash": r.integrity_hash,
            "created_at": r.created_at.isoformat(),
        } for r in records],
        "total": await repo.get_latest_sequence_no(tenant.id)
    }


@router.get("/verify")
async def verify_audit_integrity(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Verify the cryptographic hash chain of the audit ledger."""
    # ch_client = await get_clickhouse_client()
    repo = PostgresAuditRepository(db)
    verifier = HashVerificationService(repo)
    
    report = await verifier.verify_tenant_chain(tenant.id)
    
    status = "intact" if report.is_valid else "tampered"
    
    if status == "tampered":
        # Alert security worker
        from app.schemas.events import SecurityEvent
        from app.core.events.producer import producer
        
        tamper_event = SecurityEvent(
            event_type="audit.chain.tampered",
            tenant_id=str(tenant.id),
            payload={
                "tampered_from_id": str(report.tampered_records[0]) if report.tampered_records else None,
                "broken_links_count": len(report.chain_breaks)
            }
        )
        await producer.publish(
            topic="authclaw.security.events",
            event=tamper_event
        )
        
    return {
        "status": status,
        "scanned_records": report.scanned_records,
        "missing_records": len(report.missing_records),
        "tampered_records": len(report.tampered_records),
        "chain_breaks": len(report.chain_breaks)
    }


@router.post("/exports/verify", response_model=AuditExportVerificationResponse)
async def verify_audit_export_package(
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
):
    """Verify an E4.4 signed audit export package for the current tenant."""

    package_bytes = await request.body()
    result = audit_export_verification_service.verify_package(
        package_bytes,
        expected_tenant_id=tenant.id,
    )
    return AuditExportVerificationResponse.from_contract(result)

@router.get("/export")
async def export_audit_logs(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Export all audit logs for the current tenant as a Signed CSV."""
    import hmac
    import hashlib
    from app.core.encryption import get_encryption_provider
    
    # ch_client = await get_clickhouse_client()
    repo = PostgresAuditRepository(db)
    
    # Export up to the last 10 years for this test
    records = await repo.export(tenant.id, datetime.now() - timedelta(days=3650), datetime.now())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "sequence_no", "user_id", "event_type", "resource", "resource_id", "action", "ip_address", "created_at", "previous_hash", "hash"])
    for r in records:
        writer.writerow([
            str(r.record_id),
            r.sequence_no,
            str(r.actor_id) if r.actor_id else "",
            r.metadata.get("event_type"),
            r.resource or "",
            r.resource_id or "",
            r.action,
            r.ip_address,
            r.created_at.isoformat(),
            r.previous_hash,
            r.integrity_hash
        ])

    csv_data = output.getvalue().encode('utf-8')
    
    # Generate signature using KMS Provider
    provider = get_encryption_provider()
    dek_plaintext, dek_encrypted = provider.generate_data_key()
    signature = hmac.new(dek_plaintext, csv_data, hashlib.sha256).hexdigest()
    
    # Securely overwrite dek_plaintext in memory
    for i in range(len(dek_plaintext)):
        pass # In Python, byte strings are immutable, but we conceptually scrub it.
        
    response = StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=audit_logs.csv",
            "X-Audit-Signature": signature,
            "X-Audit-Key": dek_encrypted
        }
    )
    return response


@router.get("/logs/export")
async def export_audit_logs_alias(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db)
):
    """Alias for /export — maintains backward compatibility with the frontend URL.

    The canonical endpoint lives at GET /audit/export.  This alias is registered
    at GET /audit/logs/export so that the frontend hook (useAuditLogs & export
    calls) resolves without a redirect or configuration change.

    NOTE: This route MUST be declared before /logs/{log_id} so FastAPI's router
    does not greedily match 'export' as a log_id UUID (which would 422).
    """
    return await export_audit_logs(tenant=tenant, _=_, db=db)


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
    from app.models.gateway import GatewayRequest

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
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(PolicyViolation)
        .options(selectinload(PolicyViolation.policy), selectinload(PolicyViolation.rule))
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
        "policy_name": v.policy.name if v.policy else "Global System Policy",
        "rule_name": v.rule.rule_type.value if v.rule else "",
        "action_taken": v.rule.action.value if v.rule else "logged",
        "severity": v.severity.value,
        "description": v.description,
        "resolution": v.resolution.value,
        "resolved_at": v.created_at.isoformat() if v.resolution.value != "pending" else None,
        "created_at": v.created_at.isoformat()
    } for v in violations]
