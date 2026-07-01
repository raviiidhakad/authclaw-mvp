from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, inspect as sa_inspect, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.dependencies import get_current_tenant, get_db, require_roles
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.risk import (
    AdversarialProbeCategory,
    AdversarialProbeRun,
    AdversarialProbeStatus,
    RedTeamProbeResult,
    VulnerabilityRegisterItem,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.risk import (
    AdversarialProbeRunCreate,
    AdversarialProbeRunResponse,
    RedTeamProbeResultResponse,
    RiskListResponse,
    RiskPostureResponse,
    VulnerabilityRegisterItemResponse,
    VulnerabilityUpdateRequest,
)
from app.services.api_safety import sanitize_text
from app.services.risk_red_teaming import (
    RISK_READ_ROLES,
    RISK_RUN_ROLES,
    RISK_UPDATE_ROLES,
    RISK_WRITE_ROLES,
    create_simulated_probe_run,
    latest_or_computed_posture,
    safe_model_payload,
    seed_risk_demo_data,
    set_tenant_context,
)


router = APIRouter()


def _enum_value(value: object) -> str:
    return getattr(value, "value", str(value))


def _result_response(row: RedTeamProbeResult) -> RedTeamProbeResultResponse:
    payload = safe_model_payload(
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "probe_run_id": row.probe_run_id,
            "category": _enum_value(row.category),
            "target_surface": row.target_surface,
            "status": row.status,
            "severity": _enum_value(row.severity),
            "confidence": row.confidence,
            "evidence_summary": row.evidence_summary,
            "sanitized_input_summary": row.sanitized_input_summary,
            "sanitized_output_summary": row.sanitized_output_summary,
            "linked_finding_id": row.linked_finding_id,
            "linked_remediation_plan_id": row.linked_remediation_plan_id,
            "linked_control_id": row.linked_control_id,
            "linked_report_artifact_id": row.linked_report_artifact_id,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
    )
    payload["raw_payload_stored"] = bool(row.raw_payload_stored)
    return RedTeamProbeResultResponse(**payload)


def _probe_response(row: AdversarialProbeRun) -> AdversarialProbeRunResponse:
    loaded_results = [] if "results" in sa_inspect(row).unloaded else list(row.results or [])
    result_payloads = [_result_response(result).model_dump(mode="python") for result in loaded_results]
    payload = safe_model_payload(
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "category": _enum_value(row.category),
            "status": _enum_value(row.status),
            "target_surface": row.target_surface,
            "model_target": row.model_target,
            "execution_mode": row.execution_mode,
            "owner_user_id": row.owner_user_id,
            "started_at": row.started_at,
            "completed_at": row.completed_at,
            "safe_prompt_preview": row.safe_prompt_preview,
            "result_summary": row.result_summary,
            "risk_score": row.risk_score,
            "probes_total": row.probes_total,
            "blocked_count": row.blocked_count,
            "allowed_count": row.allowed_count,
            "vulnerability_count": row.vulnerability_count,
            "evidence": row.evidence or {},
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
    )
    payload["results"] = result_payloads
    payload["raw_payload_stored"] = bool(row.raw_payload_stored)
    return AdversarialProbeRunResponse(**payload)


def _vulnerability_response(row: VulnerabilityRegisterItem) -> VulnerabilityRegisterItemResponse:
    return VulnerabilityRegisterItemResponse(
        **safe_model_payload(
            {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "probe_run_id": row.probe_run_id,
                "remediation_plan_id": row.remediation_plan_id,
                "category": _enum_value(row.category),
                "title": row.title,
                "description": row.description,
                "severity": _enum_value(row.severity),
                "status": _enum_value(row.status),
                "owner_user_id": row.owner_user_id,
                "confidence": row.confidence,
                "due_date": row.due_date,
                "linked_finding_id": row.linked_finding_id,
                "linked_control_id": row.linked_control_id,
                "linked_report_artifact_id": row.linked_report_artifact_id,
                "evidence_summary": row.evidence_summary,
                "remediation_summary": row.remediation_summary,
                "first_seen_at": row.first_seen_at,
                "last_seen_at": row.last_seen_at,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
    )


@router.get("/probes", response_model=RiskListResponse[AdversarialProbeRunResponse])
@router.get("/probe-runs", response_model=RiskListResponse[AdversarialProbeRunResponse])
async def list_probe_runs(
    skip: int = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    category: AdversarialProbeCategory | None = None,
    status: AdversarialProbeStatus | None = None,
    owner_user_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(RISK_READ_ROLES)),
):
    await set_tenant_context(db, tenant.id)
    query = select(AdversarialProbeRun).where(AdversarialProbeRun.tenant_id == tenant.id)
    if category is not None:
        query = query.where(AdversarialProbeRun.category == category)
    if status is not None:
        query = query.where(AdversarialProbeRun.status == status)
    if owner_user_id is not None:
        query = query.where(AdversarialProbeRun.owner_user_id == owner_user_id)
    rows = (await db.execute(query.order_by(desc(AdversarialProbeRun.completed_at), desc(AdversarialProbeRun.created_at)))).scalars().all()
    total = len(rows)
    return RiskListResponse(items=[_probe_response(row) for row in rows[skip : skip + limit]], total=total, skip=skip, limit=limit)


@router.post("/probes/run", response_model=AdversarialProbeRunResponse)
@router.post("/probe-runs", response_model=AdversarialProbeRunResponse)
async def create_probe_run(
    body: AdversarialProbeRunCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(RISK_RUN_ROLES)),
):
    try:
        category = AdversarialProbeCategory(body.category)
    except ValueError as exc:
        raise BadRequestException(detail="Unsupported probe category") from exc
    run = await create_simulated_probe_run(
        db,
        tenant.id,
        name=body.name,
        category=category,
        target_surface=body.target_surface,
        model_target=body.model_target,
        owner_user_id=body.owner_user_id or current_user.id,
    )
    row = (
        await db.execute(
            select(AdversarialProbeRun)
            .options(selectinload(AdversarialProbeRun.results))
            .where(AdversarialProbeRun.id == run.id, AdversarialProbeRun.tenant_id == tenant.id)
        )
    ).scalars().first()
    return _probe_response(row or run)


@router.get("/probes/{run_id}", response_model=AdversarialProbeRunResponse)
@router.get("/probe-runs/{run_id}", response_model=AdversarialProbeRunResponse)
async def get_probe_run(
    run_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(RISK_READ_ROLES)),
):
    await set_tenant_context(db, tenant.id)
    row = (
        await db.execute(
            select(AdversarialProbeRun)
            .options(selectinload(AdversarialProbeRun.results))
            .where(AdversarialProbeRun.id == run_id, AdversarialProbeRun.tenant_id == tenant.id)
        )
    ).scalars().first()
    if row is None:
        raise NotFoundException(detail="Probe run not found")
    return _probe_response(row)


@router.get("/vulnerabilities", response_model=RiskListResponse[VulnerabilityRegisterItemResponse])
async def list_vulnerabilities(
    skip: int = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    category: AdversarialProbeCategory | None = None,
    severity: VulnerabilitySeverity | None = None,
    status: VulnerabilityStatus | None = None,
    owner_user_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(RISK_READ_ROLES)),
):
    await set_tenant_context(db, tenant.id)
    query = select(VulnerabilityRegisterItem).where(VulnerabilityRegisterItem.tenant_id == tenant.id)
    if category is not None:
        query = query.where(VulnerabilityRegisterItem.category == category)
    if severity is not None:
        query = query.where(VulnerabilityRegisterItem.severity == severity)
    if status is not None:
        query = query.where(VulnerabilityRegisterItem.status == status)
    if owner_user_id is not None:
        query = query.where(VulnerabilityRegisterItem.owner_user_id == owner_user_id)
    rows = (
        await db.execute(query.order_by(desc(VulnerabilityRegisterItem.last_seen_at), desc(VulnerabilityRegisterItem.created_at)))
    ).scalars().all()
    total = len(rows)
    return RiskListResponse(items=[_vulnerability_response(row) for row in rows[skip : skip + limit]], total=total, skip=skip, limit=limit)


@router.patch("/vulnerabilities/{vulnerability_id}", response_model=VulnerabilityRegisterItemResponse)
async def update_vulnerability(
    vulnerability_id: uuid.UUID,
    body: VulnerabilityUpdateRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(RISK_UPDATE_ROLES)),
):
    await set_tenant_context(db, tenant.id)
    row = (
        await db.execute(
            select(VulnerabilityRegisterItem).where(
                VulnerabilityRegisterItem.id == vulnerability_id,
                VulnerabilityRegisterItem.tenant_id == tenant.id,
            )
        )
    ).scalars().first()
    if row is None:
        raise NotFoundException(detail="Vulnerability not found")
    if body.status is not None:
        try:
            row.status = VulnerabilityStatus(body.status)
        except ValueError as exc:
            raise BadRequestException(detail="Unsupported vulnerability status") from exc
    if body.severity is not None:
        try:
            row.severity = VulnerabilitySeverity(body.severity)
        except ValueError as exc:
            raise BadRequestException(detail="Unsupported vulnerability severity") from exc
    if body.owner_user_id is not None:
        row.owner_user_id = body.owner_user_id
    if body.remediation_plan_id is not None:
        row.remediation_plan_id = body.remediation_plan_id
    if body.remediation_summary is not None:
        row.remediation_summary = str(safe_model_payload({"value": sanitize_text(body.remediation_summary)})["value"])
    if body.confidence is not None:
        row.confidence = body.confidence
    if body.due_date is not None:
        row.due_date = body.due_date.replace(tzinfo=None)
    await db.flush()
    await db.commit()
    await set_tenant_context(db, tenant.id)
    await db.refresh(row)
    return _vulnerability_response(row)


@router.get("/posture", response_model=RiskPostureResponse)
async def get_posture(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(RISK_READ_ROLES)),
):
    snapshot = await latest_or_computed_posture(db, tenant.id)
    return RiskPostureResponse(
        **safe_model_payload(
            {
                "verdict": _enum_value(snapshot.verdict),
                "summary": snapshot.summary,
                "counts": snapshot.counts or {},
                "blockers": snapshot.blockers or [],
                "recommendations": snapshot.recommendations or [],
                "evidence_summary": snapshot.evidence_summary,
                "generated_at": snapshot.generated_at,
            }
        )
    )


@router.post("/seed-demo")
async def seed_demo(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(RISK_WRITE_ROLES)),
):
    return safe_model_payload(await seed_risk_demo_data(db, tenant.id, current_user.id))
