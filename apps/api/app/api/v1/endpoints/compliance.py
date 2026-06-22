import csv
import hashlib
import hmac
import inspect
import io
import uuid
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import or_, select, desc, text
from sqlalchemy.orm import selectinload

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.core.exceptions import NotFoundException
from app.models.tenant import Tenant
from app.models.user import User
from app.models.compliance import (
    AgentComplianceSession,
    ComplianceAssessment,
    ComplianceAssessmentStatus,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    ComplianceGapSeverity,
    ComplianceGapType,
    ComplianceScore,
    ControlAssessmentResult,
    EvidenceItem,
    EvidenceStatus,
    EvidenceSourceType,
    FindingControlMapping,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeDocumentStatus,
    MappingReviewStatus,
    MappingSource,
)
from app.schemas.compliance import (
    ComplianceAskRequest,
    ComplianceAskResponse,
    ComplianceAskSessionListResponse,
    ComplianceAskSessionResponse,
    ComplianceAssessmentListResponse,
    ComplianceAssessmentResponse,
    ComplianceAssessmentRunRequest,
    ComplianceControlListResponse,
    ComplianceControlResponse,
    ComplianceFrameworkResponse,
    ComplianceGapListResponse,
    ComplianceGapResponse,
    ComplianceRecommendationListResponse,
    ComplianceRecommendationResponse,
    FindingControlMappingListResponse,
    FindingControlMappingResponse,
    MappingReviewRequest,
    ControlRequirementResponse,
    ControlAssessmentResultResponse,
    EvidenceItemListResponse,
    EvidenceItemResponse,
    KnowledgeChunkResponse,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentResponse,
    KnowledgeIngestRequest,
    KnowledgeIngestResponse,
    RetrievalCitationResponse,
    RetrievalChunkResultResponse,
    RetrievalQueryRequest,
    RetrievalQueryResponse,
)
from app.core.events.producer import producer
from app.core.engine.compliance import ComplianceRuleChecker
from app.schemas.events import ComplianceMappingReviewedEvent
from app.services.compliance_answer import ComplianceAnswerService
from app.services.compliance_evidence import ComplianceScoringService
from app.services.compliance_knowledge import (
    ComplianceKnowledgeIngestionService,
    ComplianceRetrievalService,
)

router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _legacy_posture_status(score: float) -> str:
    if score >= 80:
        return "evidence_supported"
    if score >= 50:
        return "at_risk"
    return "high_risk"


def _requirement_response(requirement) -> ControlRequirementResponse:
    return ControlRequirementResponse(
        id=requirement.id,
        requirement_key=requirement.requirement_key,
        summary=requirement.summary,
        evidence_expectation=requirement.evidence_expectation,
        sort_order=requirement.sort_order,
    )


def _control_response(control: ComplianceControl) -> ComplianceControlResponse:
    return ComplianceControlResponse(
        id=control.id,
        framework_id=control.framework_id,
        control_code=control.control_code,
        title=control.title,
        summary=control.summary,
        domain=control.domain,
        category=control.category,
        severity_weight=control.severity_weight,
        requires_review=control.requires_review,
        sort_order=control.sort_order,
        metadata=control.metadata_,
        requirements=[_requirement_response(req) for req in control.requirements],
        created_at=control.created_at,
        updated_at=control.updated_at,
    )


def _framework_response(framework: ComplianceFramework) -> ComplianceFrameworkResponse:
    return ComplianceFrameworkResponse(
        id=framework.id,
        key=framework.key,
        version=framework.version,
        name=framework.name,
        description=framework.description,
        source_url=framework.source_url,
        license_note=framework.license_note,
        status=framework.status,
        metadata=framework.metadata_,
        control_count=len(framework.controls),
        created_at=framework.created_at,
        updated_at=framework.updated_at,
    )


def _mapping_response(mapping: FindingControlMapping) -> FindingControlMappingResponse:
    control = mapping.control
    framework = control.framework if control is not None else None
    return FindingControlMappingResponse(
        id=mapping.id,
        tenant_id=mapping.tenant_id,
        finding_id=mapping.finding_id,
        control_id=mapping.control_id,
        rule_id=mapping.rule_id,
        confidence=mapping.confidence,
        mapping_source=mapping.mapping_source.value,
        review_status=mapping.review_status.value,
        override_reason=mapping.override_reason,
        control_code=control.control_code if control is not None else None,
        control_title=control.title if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=mapping.created_at,
        updated_at=mapping.updated_at,
    )


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _evidence_response(evidence: EvidenceItem) -> EvidenceItemResponse:
    control = evidence.control
    framework = control.framework if control is not None else None
    return EvidenceItemResponse(
        id=evidence.id,
        tenant_id=evidence.tenant_id,
        control_id=evidence.control_id,
        finding_id=evidence.finding_id,
        integration_id=evidence.integration_id,
        audit_log_id=evidence.audit_log_id,
        mapping_id=evidence.mapping_id,
        source_type=_enum_value(evidence.source_type),
        status=_enum_value(evidence.status),
        safe_summary=evidence.safe_summary,
        proof_hash=evidence.proof_hash,
        freshness_expires_at=evidence.freshness_expires_at,
        metadata=evidence.metadata_,
        control_code=control.control_code if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=evidence.created_at,
        updated_at=evidence.updated_at,
    )


def _gap_response(gap: ComplianceGap) -> ComplianceGapResponse:
    control = gap.control
    framework = control.framework if control is not None else None
    return ComplianceGapResponse(
        id=gap.id,
        tenant_id=gap.tenant_id,
        assessment_id=gap.assessment_id,
        control_id=gap.control_id,
        evidence_id=gap.evidence_id,
        mapping_id=gap.mapping_id,
        finding_id=gap.finding_id,
        gap_type=_enum_value(gap.gap_type),
        severity=_enum_value(gap.severity),
        reason=gap.reason,
        evidence_status=gap.evidence_status,
        metadata=gap.metadata_,
        control_code=control.control_code if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=gap.created_at,
        updated_at=gap.updated_at,
    )


def _control_result_response(result: ControlAssessmentResult) -> ControlAssessmentResultResponse:
    control = result.control
    return ControlAssessmentResultResponse(
        id=result.id,
        tenant_id=result.tenant_id,
        assessment_id=result.assessment_id,
        control_id=result.control_id,
        score=result.score,
        score_band=_enum_value(result.score_band),
        evidence_count=result.evidence_count,
        gap_count=result.gap_count,
        explanation=result.explanation,
        metadata=result.metadata_,
        control_code=control.control_code if control is not None else None,
        control_title=control.title if control is not None else None,
        created_at=result.created_at,
        updated_at=result.updated_at,
    )


def _assessment_response(assessment: ComplianceAssessment, include_detail: bool = False) -> ComplianceAssessmentResponse:
    framework = assessment.framework
    return ComplianceAssessmentResponse(
        id=assessment.id,
        tenant_id=assessment.tenant_id,
        framework_id=assessment.framework_id,
        framework_key=framework.key if framework is not None else None,
        status=_enum_value(assessment.status),
        score=assessment.score,
        score_band=_enum_value(assessment.score_band),
        started_at=assessment.started_at,
        completed_at=assessment.completed_at,
        inputs_hash=assessment.inputs_hash,
        explanation=assessment.explanation,
        control_results=[
            _control_result_response(item)
            for item in (assessment.control_results if include_detail else [])
        ],
        gaps=[_gap_response(gap) for gap in (assessment.gaps if include_detail else [])],
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def _knowledge_chunk_response(chunk: KnowledgeChunk) -> KnowledgeChunkResponse:
    return KnowledgeChunkResponse(
        id=chunk.id,
        document_id=chunk.document_id,
        framework_id=chunk.framework_id,
        tenant_id=chunk.tenant_id,
        control_id=chunk.control_id,
        chunk_index=chunk.chunk_index,
        chunk_text=chunk.chunk_text,
        summary=chunk.summary,
        metadata=chunk.metadata_,
        source_locator=chunk.source_locator,
        created_at=chunk.created_at,
        updated_at=chunk.updated_at,
    )


def _knowledge_document_response(
    document: KnowledgeDocument,
    include_chunks: bool = False,
) -> KnowledgeDocumentResponse:
    chunks = list(document.chunks or [])
    return KnowledgeDocumentResponse(
        id=document.id,
        tenant_id=document.tenant_id,
        framework_id=document.framework_id,
        source_type=document.source_type,
        title=document.title,
        source_url=document.source_url,
        license_status=document.license_status,
        trust_level=document.trust_level,
        checksum=document.checksum,
        status=_enum_value(document.status),
        ingested_by=document.ingested_by,
        metadata=document.metadata_,
        chunk_count=len(chunks),
        chunks=[_knowledge_chunk_response(chunk) for chunk in chunks] if include_chunks else [],
        created_at=document.created_at,
        updated_at=document.updated_at,
    )


def _retrieval_response(result) -> RetrievalQueryResponse:
    return RetrievalQueryResponse(
        query_hash=result.query_hash,
        trace_id=result.trace.id,
        confidence=result.confidence,
        strategy=result.strategy,
        results=[
            RetrievalChunkResultResponse(
                chunk_id=item.chunk.id,
                document_id=item.chunk.document_id,
                chunk_text=item.chunk.chunk_text,
                summary=item.chunk.summary,
                score=item.score,
                citation=RetrievalCitationResponse(**item.citation),
                metadata=item.chunk.metadata_,
            )
            for item in result.results
        ],
        generated_answer=None,
    )


def _ask_response(result) -> ComplianceAskResponse:
    return ComplianceAskResponse(
        answer=result.answer,
        confidence=result.confidence,
        citations=result.citations,
        related_controls=result.related_controls,
        related_evidence=result.related_evidence,
        related_gaps=result.related_gaps,
        recommended_next_steps=result.recommended_next_steps,
        refusal_reason=result.refusal_reason,
        retrieval_trace_id=result.retrieval_trace_id,
        session_id=result.session.id,
    )


def _ask_session_response(session: AgentComplianceSession) -> ComplianceAskSessionResponse:
    metadata = dict(session.metadata_ or {})
    safe_metadata = {
        key: value
        for key, value in metadata.items()
        if key in {"mode", "refused", "related_controls", "related_evidence", "related_gaps", "recommended_next_steps"}
    }
    return ComplianceAskSessionResponse(
        id=session.id,
        tenant_id=session.tenant_id,
        user_id=session.user_id,
        question_hash=session.normalized_question_hash,
        answer=session.answer,
        citations=session.citations or [],
        confidence=session.confidence,
        refused=session.refusal_reason is not None,
        refusal_reason=session.refusal_reason,
        framework_id=session.framework_id,
        control_id=session.control_id,
        assessment_id=session.assessment_id,
        retrieval_trace_id=session.retrieval_trace_id,
        metadata=safe_metadata,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


def _recommendation_response(gap: ComplianceGap) -> ComplianceRecommendationResponse:
    control = gap.control
    framework = control.framework if control is not None else None
    return ComplianceRecommendationResponse(
        id=gap.id,
        tenant_id=gap.tenant_id,
        control_id=gap.control_id,
        gap_id=gap.id,
        finding_id=gap.finding_id,
        severity=_enum_value(gap.severity),
        status="review_recommended",
        title=f"Review {_enum_value(gap.gap_type).replace('_', ' ')}",
        summary=gap.reason,
        control_code=control.control_code if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=gap.created_at,
    )


async def _publish_mapping_review_event(mapping: FindingControlMapping, actor_id: uuid.UUID | None) -> None:
    event = ComplianceMappingReviewedEvent(
        tenant_id=str(mapping.tenant_id),
        finding_id=str(mapping.finding_id),
        control_id=str(mapping.control_id),
        rule_id=mapping.rule_id,
        confidence=mapping.confidence,
        review_status=_enum_value(mapping.review_status),
        actor_id=str(actor_id) if actor_id else None,
    )
    try:
        result = producer.publish("authclaw.compliance.mapping.events", event)
        if inspect.isawaitable(result):
            await result
    except Exception:
        pass


async def _set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
        {"tenant_id": str(tenant_id)},
    )


@router.get("/frameworks", response_model=list[ComplianceFrameworkResponse])
async def list_frameworks(
    framework: str | None = Query(None, description="Filter by framework key, e.g. gdpr"),
    key: str | None = None,
    status: str | None = Query("active", description="Filter by catalog status"),
    skip: int = 0,
    limit: int = 100,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    """
    List global compliance framework catalog entries.

    The catalog is global, but the endpoint still requires tenant context so
    AuthClaw RBAC and request auditing remain consistent.
    """
    query = select(ComplianceFramework).options(selectinload(ComplianceFramework.controls))
    framework_key = (key or framework or "").strip().lower()
    if framework_key:
        query = query.where(ComplianceFramework.key == framework_key)
    if status:
        query = query.where(ComplianceFramework.status == status.strip().lower())

    result = await db.execute(query.order_by(ComplianceFramework.key, ComplianceFramework.version))
    frameworks = result.scalars().all()
    return [_framework_response(item) for item in frameworks[skip : skip + limit]]


@router.get("/frameworks/{framework_id}", response_model=ComplianceFrameworkResponse)
async def get_framework(
    framework_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ComplianceFramework)
        .where(ComplianceFramework.id == framework_id)
        .options(selectinload(ComplianceFramework.controls))
    )
    framework = result.scalars().first()
    if framework is None:
        raise NotFoundException(detail="Compliance framework not found")
    return _framework_response(framework)


@router.get(
    "/frameworks/{framework_id}/controls",
    response_model=ComplianceControlListResponse,
)
async def list_framework_controls(
    framework_id: uuid.UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    domain: str | None = None,
    category: str | None = None,
    requires_review: bool | None = None,
    search: str | None = Query(None, min_length=2, max_length=100),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    framework_result = await db.execute(
        select(ComplianceFramework.id).where(ComplianceFramework.id == framework_id)
    )
    if framework_result.scalars().first() is None:
        raise NotFoundException(detail="Compliance framework not found")

    query = (
        select(ComplianceControl)
        .where(ComplianceControl.framework_id == framework_id)
        .options(selectinload(ComplianceControl.requirements))
    )
    if domain:
        query = query.where(ComplianceControl.domain == domain.strip().lower())
    if category:
        query = query.where(ComplianceControl.category == category.strip().lower())
    if requires_review is not None:
        query = query.where(ComplianceControl.requires_review == requires_review)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                ComplianceControl.control_code.ilike(term),
                ComplianceControl.title.ilike(term),
                ComplianceControl.summary.ilike(term),
            )
        )

    result = await db.execute(
        query.order_by(ComplianceControl.sort_order, ComplianceControl.control_code)
    )
    controls = result.scalars().all()
    total = len(controls)
    paged = controls[skip : skip + limit]
    return ComplianceControlListResponse(
        items=[_control_response(control) for control in paged],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/controls/{control_id}", response_model=ComplianceControlResponse)
async def get_control(
    control_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ComplianceControl)
        .where(ComplianceControl.id == control_id)
        .options(selectinload(ComplianceControl.requirements))
    )
    control = result.scalars().first()
    if control is None:
        raise NotFoundException(detail="Compliance control not found")
    return _control_response(control)


@router.get("/mappings", response_model=FindingControlMappingListResponse)
async def list_mappings(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: str | None = None,
    framework_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    control_id: uuid.UUID | None = None,
    review_status: MappingReviewStatus | None = None,
    mapping_source: MappingSource | None = None,
    min_confidence: float | None = Query(None, ge=0.0, le=1.0),
    max_confidence: float | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    if min_confidence is not None and max_confidence is not None and min_confidence > max_confidence:
        raise HTTPException(status_code=400, detail="min_confidence cannot exceed max_confidence")

    query = (
        select(FindingControlMapping)
        .join(ComplianceControl, FindingControlMapping.control_id == ComplianceControl.id)
        .join(ComplianceFramework, ComplianceControl.framework_id == ComplianceFramework.id)
        .where(FindingControlMapping.tenant_id == tenant.id)
        .options(
            selectinload(FindingControlMapping.control).selectinload(ComplianceControl.framework)
        )
    )
    if framework:
        query = query.where(ComplianceFramework.key == framework.strip().lower())
    if framework_id is not None:
        query = query.where(ComplianceControl.framework_id == framework_id)
    if finding_id is not None:
        query = query.where(FindingControlMapping.finding_id == finding_id)
    if control_id is not None:
        query = query.where(FindingControlMapping.control_id == control_id)
    if review_status is not None:
        query = query.where(FindingControlMapping.review_status == review_status)
    if mapping_source is not None:
        query = query.where(FindingControlMapping.mapping_source == mapping_source)
    if min_confidence is not None:
        query = query.where(FindingControlMapping.confidence >= min_confidence)
    if max_confidence is not None:
        query = query.where(FindingControlMapping.confidence <= max_confidence)

    result = await db.execute(
        query.order_by(FindingControlMapping.confidence.desc(), FindingControlMapping.created_at.desc())
    )
    mappings = result.scalars().all()
    total = len(mappings)
    return FindingControlMappingListResponse(
        items=[_mapping_response(mapping) for mapping in mappings[skip : skip + limit]],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/findings/{finding_id}/mappings",
    response_model=FindingControlMappingListResponse,
)
async def list_finding_mappings(
    finding_id: uuid.UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    return await list_mappings(
        skip=skip,
        limit=limit,
        framework=None,
        framework_id=None,
        finding_id=finding_id,
        control_id=None,
        review_status=None,
        mapping_source=None,
        min_confidence=None,
        max_confidence=None,
        tenant=tenant,
        _=_,
        db=db,
    )


@router.get(
    "/controls/{control_id}/mappings",
    response_model=FindingControlMappingListResponse,
)
async def list_control_mappings(
    control_id: uuid.UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    return await list_mappings(
        skip=skip,
        limit=limit,
        framework=None,
        framework_id=None,
        finding_id=None,
        control_id=control_id,
        review_status=None,
        mapping_source=None,
        min_confidence=None,
        max_confidence=None,
        tenant=tenant,
        _=_,
        db=db,
    )


@router.patch("/mappings/{mapping_id}/review", response_model=FindingControlMappingResponse)
async def review_mapping(
    mapping_id: uuid.UUID,
    request: MappingReviewRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    result = await db.execute(
        select(FindingControlMapping)
        .where(
            FindingControlMapping.tenant_id == tenant.id,
            FindingControlMapping.id == mapping_id,
        )
        .options(
            selectinload(FindingControlMapping.control).selectinload(ComplianceControl.framework)
        )
    )
    mapping = result.scalars().first()
    if mapping is None:
        raise NotFoundException(detail="Finding control mapping not found")

    if request.review_status == "overridden" and not (request.override_reason or "").strip():
        raise HTTPException(status_code=409, detail="override_reason is required for overridden mappings")

    mapping.review_status = MappingReviewStatus(request.review_status)
    mapping.mapping_source = MappingSource.manual
    mapping.override_reason = request.override_reason.strip() if request.override_reason else None
    await db.flush()
    await _publish_mapping_review_event(mapping, current_user.id)
    await db.commit()
    return _mapping_response(mapping)


@router.post("/assessments/run", response_model=ComplianceAssessmentResponse)
async def run_assessment(
    request: ComplianceAssessmentRunRequest,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    framework_id = request.framework_id
    if framework_id is None and request.framework:
        result = await db.execute(
            select(ComplianceFramework.id).where(
                ComplianceFramework.key == request.framework.strip().lower(),
                ComplianceFramework.status == "active",
            )
        )
        framework_id = result.scalars().first()
    if framework_id is None:
        raise HTTPException(status_code=422, detail="framework_id or framework is required")

    assessment = await ComplianceScoringService(db).run_assessment(tenant.id, framework_id)
    await db.commit()
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
        {"tenant_id": str(tenant.id)},
    )
    result = await db.execute(
        select(ComplianceAssessment)
        .where(
            ComplianceAssessment.tenant_id == tenant.id,
            ComplianceAssessment.id == assessment.id,
        )
        .options(
            selectinload(ComplianceAssessment.framework),
            selectinload(ComplianceAssessment.control_results).selectinload(ControlAssessmentResult.control),
            selectinload(ComplianceAssessment.gaps)
            .selectinload(ComplianceGap.control)
            .selectinload(ComplianceControl.framework),
        )
    )
    return _assessment_response(result.scalars().first(), include_detail=True)


@router.get("/assessments", response_model=ComplianceAssessmentListResponse)
async def list_assessments(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: str | None = None,
    framework_id: uuid.UUID | None = None,
    status: ComplianceAssessmentStatus | None = None,
    latest_only: bool = False,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(ComplianceAssessment)
        .join(ComplianceFramework, ComplianceAssessment.framework_id == ComplianceFramework.id)
        .where(ComplianceAssessment.tenant_id == tenant.id)
        .options(selectinload(ComplianceAssessment.framework))
    )
    if framework:
        query = query.where(ComplianceFramework.key == framework.strip().lower())
    if framework_id is not None:
        query = query.where(ComplianceAssessment.framework_id == framework_id)
    if status is not None:
        query = query.where(ComplianceAssessment.status == status)

    result = await db.execute(query.order_by(ComplianceAssessment.started_at.desc()))
    assessments = result.scalars().all()
    if latest_only:
        latest_by_framework = {}
        for assessment in assessments:
            latest_by_framework.setdefault(assessment.framework_id, assessment)
        assessments = list(latest_by_framework.values())
    return ComplianceAssessmentListResponse(
        items=[
            _assessment_response(assessment)
            for assessment in assessments[skip : skip + limit]
        ],
        total=len(assessments),
        skip=skip,
        limit=limit,
    )


@router.get("/assessments/{assessment_id}", response_model=ComplianceAssessmentResponse)
async def get_assessment(
    assessment_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ComplianceAssessment)
        .where(
            ComplianceAssessment.tenant_id == tenant.id,
            ComplianceAssessment.id == assessment_id,
        )
        .options(
            selectinload(ComplianceAssessment.framework),
            selectinload(ComplianceAssessment.control_results).selectinload(ControlAssessmentResult.control),
            selectinload(ComplianceAssessment.gaps)
            .selectinload(ComplianceGap.control)
            .selectinload(ComplianceControl.framework),
        )
    )
    assessment = result.scalars().first()
    if assessment is None:
        raise NotFoundException(detail="Compliance assessment not found")
    return _assessment_response(assessment, include_detail=True)


@router.get(
    "/assessments/{assessment_id}/controls",
    response_model=list[ControlAssessmentResultResponse],
)
async def list_assessment_controls(
    assessment_id: uuid.UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    assessment_exists = await db.scalar(
        select(ComplianceAssessment.id).where(
            ComplianceAssessment.tenant_id == tenant.id,
            ComplianceAssessment.id == assessment_id,
        )
    )
    if assessment_exists is None:
        raise NotFoundException(detail="Compliance assessment not found")

    result = await db.execute(
        select(ControlAssessmentResult)
        .where(
            ControlAssessmentResult.tenant_id == tenant.id,
            ControlAssessmentResult.assessment_id == assessment_id,
        )
        .options(selectinload(ControlAssessmentResult.control))
        .order_by(ControlAssessmentResult.created_at.desc())
    )
    controls = result.scalars().all()
    return [_control_result_response(item) for item in controls[skip : skip + limit]]


@router.get("/evidence", response_model=EvidenceItemListResponse)
async def list_evidence(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: str | None = None,
    framework_id: uuid.UUID | None = None,
    control_id: uuid.UUID | None = None,
    source_type: EvidenceSourceType | None = None,
    status: EvidenceStatus | None = None,
    finding_id: uuid.UUID | None = None,
    freshness: str | None = Query(None, description="fresh, stale, or expired"),
    stale: bool | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(EvidenceItem)
        .join(ComplianceControl, EvidenceItem.control_id == ComplianceControl.id)
        .join(ComplianceFramework, ComplianceControl.framework_id == ComplianceFramework.id)
        .where(EvidenceItem.tenant_id == tenant.id)
        .options(selectinload(EvidenceItem.control).selectinload(ComplianceControl.framework))
    )
    if framework:
        query = query.where(ComplianceFramework.key == framework.strip().lower())
    if framework_id is not None:
        query = query.where(ComplianceControl.framework_id == framework_id)
    if control_id is not None:
        query = query.where(EvidenceItem.control_id == control_id)
    if source_type is not None:
        query = query.where(EvidenceItem.source_type == source_type)
    if status is not None:
        query = query.where(EvidenceItem.status == status)
    if finding_id is not None:
        query = query.where(EvidenceItem.finding_id == finding_id)
    if stale is not None:
        now = _utcnow()
        query = query.where(
            EvidenceItem.freshness_expires_at < now
            if stale
            else (
                (EvidenceItem.freshness_expires_at.is_(None))
                | (EvidenceItem.freshness_expires_at >= now)
            )
        )
    if freshness:
        now = _utcnow()
        freshness_value = freshness.strip().lower()
        if freshness_value == "fresh":
            query = query.where(
                (EvidenceItem.freshness_expires_at.is_(None))
                | (EvidenceItem.freshness_expires_at >= now)
            )
        elif freshness_value in {"stale", "expired"}:
            query = query.where(EvidenceItem.freshness_expires_at < now)
        else:
            raise HTTPException(status_code=422, detail="freshness must be fresh, stale, or expired")

    result = await db.execute(query.order_by(EvidenceItem.updated_at.desc()))
    evidence = result.scalars().all()
    return EvidenceItemListResponse(
        items=[_evidence_response(item) for item in evidence[skip : skip + limit]],
        total=len(evidence),
        skip=skip,
        limit=limit,
    )


@router.get("/evidence/{evidence_id}", response_model=EvidenceItemResponse)
async def get_evidence(
    evidence_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    result = await db.execute(
        select(EvidenceItem)
        .where(EvidenceItem.tenant_id == tenant.id, EvidenceItem.id == evidence_id)
        .options(selectinload(EvidenceItem.control).selectinload(ComplianceControl.framework))
    )
    evidence = result.scalars().first()
    if evidence is None:
        raise NotFoundException(detail="Evidence item not found")
    return _evidence_response(evidence)


@router.get("/gaps", response_model=ComplianceGapListResponse)
async def list_gaps(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: str | None = None,
    framework_id: uuid.UUID | None = None,
    control_id: uuid.UUID | None = None,
    severity: ComplianceGapSeverity | None = None,
    gap_type: ComplianceGapType | None = None,
    evidence_status: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(ComplianceGap)
        .join(ComplianceControl, ComplianceGap.control_id == ComplianceControl.id)
        .join(ComplianceFramework, ComplianceControl.framework_id == ComplianceFramework.id)
        .where(ComplianceGap.tenant_id == tenant.id)
        .options(selectinload(ComplianceGap.control).selectinload(ComplianceControl.framework))
    )
    if framework:
        query = query.where(ComplianceFramework.key == framework.strip().lower())
    if framework_id is not None:
        query = query.where(ComplianceControl.framework_id == framework_id)
    if control_id is not None:
        query = query.where(ComplianceGap.control_id == control_id)
    if severity is not None:
        query = query.where(ComplianceGap.severity == severity)
    if gap_type is not None:
        query = query.where(ComplianceGap.gap_type == gap_type)
    if evidence_status:
        query = query.where(ComplianceGap.evidence_status == evidence_status.strip().lower())

    result = await db.execute(query.order_by(ComplianceGap.created_at.desc()))
    gaps = result.scalars().all()
    return ComplianceGapListResponse(
        items=[_gap_response(gap) for gap in gaps[skip : skip + limit]],
        total=len(gaps),
        skip=skip,
        limit=limit,
    )


@router.get("/gaps/{gap_id}", response_model=ComplianceGapResponse)
async def get_gap(
    gap_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    result = await db.execute(
        select(ComplianceGap)
        .where(ComplianceGap.tenant_id == tenant.id, ComplianceGap.id == gap_id)
        .options(selectinload(ComplianceGap.control).selectinload(ComplianceControl.framework))
    )
    gap = result.scalars().first()
    if gap is None:
        raise NotFoundException(detail="Compliance gap not found")
    return _gap_response(gap)


@router.get("/recommendations", response_model=ComplianceRecommendationListResponse)
async def list_recommendations(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: str | None = None,
    framework_id: uuid.UUID | None = None,
    control_id: uuid.UUID | None = None,
    severity: ComplianceGapSeverity | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    query = (
        select(ComplianceGap)
        .join(ComplianceControl, ComplianceGap.control_id == ComplianceControl.id)
        .join(ComplianceFramework, ComplianceControl.framework_id == ComplianceFramework.id)
        .where(ComplianceGap.tenant_id == tenant.id)
        .options(selectinload(ComplianceGap.control).selectinload(ComplianceControl.framework))
    )
    if framework:
        query = query.where(ComplianceFramework.key == framework.strip().lower())
    if framework_id is not None:
        query = query.where(ComplianceControl.framework_id == framework_id)
    if control_id is not None:
        query = query.where(ComplianceGap.control_id == control_id)
    if severity is not None:
        query = query.where(ComplianceGap.severity == severity)

    result = await db.execute(query.order_by(ComplianceGap.created_at.desc()))
    gaps = result.scalars().all()
    return ComplianceRecommendationListResponse(
        items=[_recommendation_response(gap) for gap in gaps[skip : skip + limit]],
        total=len(gaps),
        skip=skip,
        limit=limit,
    )


@router.get("/knowledge", response_model=KnowledgeDocumentListResponse)
async def list_knowledge_documents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: str | None = None,
    framework_id: uuid.UUID | None = None,
    source_type: str | None = None,
    trust_level: str | None = None,
    status: KnowledgeDocumentStatus | None = KnowledgeDocumentStatus.active,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(KnowledgeDocument)
        .outerjoin(ComplianceFramework, KnowledgeDocument.framework_id == ComplianceFramework.id)
        .where(or_(KnowledgeDocument.tenant_id.is_(None), KnowledgeDocument.tenant_id == tenant.id))
        .options(selectinload(KnowledgeDocument.chunks))
    )
    if framework:
        query = query.where(ComplianceFramework.key == framework.strip().lower())
    if framework_id is not None:
        query = query.where(KnowledgeDocument.framework_id == framework_id)
    if source_type:
        query = query.where(KnowledgeDocument.source_type == source_type.strip().lower())
    if trust_level:
        query = query.where(KnowledgeDocument.trust_level == trust_level.strip().lower())
    if status is not None:
        query = query.where(KnowledgeDocument.status == status)

    result = await db.execute(query.order_by(KnowledgeDocument.created_at.desc()))
    documents = result.scalars().all()
    return KnowledgeDocumentListResponse(
        items=[
            _knowledge_document_response(document)
            for document in documents[skip : skip + limit]
        ],
        total=len(documents),
        skip=skip,
        limit=limit,
    )


@router.post("/knowledge/ingest", response_model=KnowledgeIngestResponse)
async def ingest_knowledge_documents(
    request: KnowledgeIngestRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    result = await ComplianceKnowledgeIngestionService(db).ingest_curated_catalog(
        tenant_id=tenant.id if request.tenant_scoped else None,
        ingested_by=current_user.id,
    )
    await db.commit()
    return KnowledgeIngestResponse(
        documents_seen=result.documents_seen,
        documents_created=result.documents_created,
        documents_updated=result.documents_updated,
        chunks_created=result.chunks_created,
    )


@router.get("/knowledge/{document_id}", response_model=KnowledgeDocumentResponse)
async def get_knowledge_document(
    document_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(KnowledgeDocument)
        .where(
            KnowledgeDocument.id == document_id,
            or_(KnowledgeDocument.tenant_id.is_(None), KnowledgeDocument.tenant_id == tenant.id),
        )
        .options(selectinload(KnowledgeDocument.chunks))
    )
    document = result.scalars().first()
    if document is None:
        raise NotFoundException(detail="Knowledge document not found")
    return _knowledge_document_response(document, include_chunks=True)


@router.post("/retrieval/query", response_model=RetrievalQueryResponse)
async def query_compliance_knowledge(
    request: RetrievalQueryRequest,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    result = await ComplianceRetrievalService(db).retrieve(
        tenant_id=tenant.id,
        query=request.query,
        framework_id=request.framework_id,
        control_id=request.control_id,
        limit=request.limit,
        session_id=request.session_id,
    )
    await db.commit()
    return _retrieval_response(result)


@router.post("/ask", response_model=ComplianceAskResponse)
async def ask_compliance_question(
    request: ComplianceAskRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(require_roles(["owner", "admin", "auditor", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    result = await ComplianceAnswerService(db).answer_question(
        tenant_id=tenant.id,
        user_id=current_user.id,
        question=request.question,
        framework_id=request.framework_id,
        control_id=request.control_id,
        finding_id=request.finding_id,
        assessment_id=request.assessment_id,
    )
    await db.commit()
    return _ask_response(result)


@router.get("/ask/sessions", response_model=ComplianceAskSessionListResponse)
async def list_ask_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework_id: uuid.UUID | None = None,
    control_id: uuid.UUID | None = None,
    refused: bool | None = None,
    min_confidence: float | None = Query(None, ge=0.0, le=1.0),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    query = select(AgentComplianceSession).where(AgentComplianceSession.tenant_id == tenant.id)
    if framework_id is not None:
        query = query.where(AgentComplianceSession.framework_id == framework_id)
    if control_id is not None:
        query = query.where(AgentComplianceSession.control_id == control_id)
    if refused is True:
        query = query.where(AgentComplianceSession.refusal_reason.is_not(None))
    elif refused is False:
        query = query.where(AgentComplianceSession.refusal_reason.is_(None))
    if min_confidence is not None:
        query = query.where(AgentComplianceSession.confidence >= min_confidence)

    result = await db.execute(query.order_by(AgentComplianceSession.created_at.desc()))
    sessions = result.scalars().all()
    return ComplianceAskSessionListResponse(
        items=[_ask_session_response(session) for session in sessions[skip : skip + limit]],
        total=len(sessions),
        skip=skip,
        limit=limit,
    )


@router.get("/ask/sessions/{session_id}", response_model=ComplianceAskSessionResponse)
async def get_ask_session(
    session_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    await _set_tenant_context(db, tenant.id)
    result = await db.execute(
        select(AgentComplianceSession).where(
            AgentComplianceSession.tenant_id == tenant.id,
            AgentComplianceSession.id == session_id,
        )
    )
    session = result.scalars().first()
    if session is None:
        raise NotFoundException(detail="Compliance ask session not found")
    return _ask_session_response(session)


@router.get("/scores")
async def get_compliance_scores(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the latest compliance scores for all frameworks.
    """
    scores = {}
    for framework in ["gdpr", "hipaa", "soc2"]:
        result = await db.execute(
            select(ComplianceScore)
            .where(
                ComplianceScore.tenant_id == tenant.id,
                ComplianceScore.framework == framework,
            )
            .order_by(desc(ComplianceScore.calculated_at))
            .limit(1)
        )
        score_record = result.scalars().first()
        if score_record:
            scores[framework] = {
                "score": score_record.score,
                "critical_violations": score_record.critical_violations,
                "policy_failures": score_record.policy_failures,
                "security_findings": score_record.security_findings,
                "breakdown": score_record.breakdown,
                "calculated_at": score_record.calculated_at.isoformat(),
            }
        else:
            scores[framework] = None

    return scores



@router.post("/scores/calculate")
async def calculate_compliance_scores(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Calculate and persist compliance scores for all frameworks.
    """
    checker = ComplianceRuleChecker(db, tenant.id)
    results = await checker.calculate_all()

    persisted = {}
    for framework_name, result_data in results.items():
        score_record = ComplianceScore(
            tenant_id=tenant.id,
            framework=framework_name,
            score=result_data["score"],
            critical_violations=result_data["critical_violations_30d"],
            policy_failures=result_data["violations_30d"],
            security_findings=sum(1 for v in result_data["checks"].values() if not v),
            breakdown=result_data["checks"],
            calculated_at=_utcnow(),
        )
        db.add(score_record)
        persisted[framework_name] = {
            "score": result_data["score"],
            "checks": result_data["checks"],
            "violations_30d": result_data["violations_30d"],
            "critical_violations_30d": result_data["critical_violations_30d"],
        }

    await db.commit()
    return persisted


@router.get("/scores/history")
async def get_compliance_history(
    framework: str = Query("gdpr"),
    limit: int = Query(30, ge=1, le=365),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical compliance scores for a framework.
    """
    result = await db.execute(
        select(ComplianceScore)
        .where(
            ComplianceScore.tenant_id == tenant.id,
            ComplianceScore.framework == framework,
        )
        .order_by(desc(ComplianceScore.calculated_at))
        .limit(limit)
    )
    scores = result.scalars().all()

    return [{
        "score": s.score,
        "critical_violations": s.critical_violations,
        "policy_failures": s.policy_failures,
        "security_findings": s.security_findings,
        "breakdown": s.breakdown,
        "calculated_at": s.calculated_at.isoformat(),
    } for s in scores]


@router.get("/scores/{framework}")
async def get_compliance_score_by_framework(
    framework: str,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the latest compliance score for a specific framework.
    """
    result = await db.execute(
        select(ComplianceScore)
        .where(
            ComplianceScore.tenant_id == tenant.id,
            ComplianceScore.framework == framework,
        )
        .order_by(desc(ComplianceScore.calculated_at))
        .limit(1)
    )
    score_record = result.scalars().first()
    if score_record:
        return {
            "framework": framework,
            "score": score_record.score,
            "critical_violations": score_record.critical_violations,
            "policy_failures": score_record.policy_failures,
            "security_findings": score_record.security_findings,
            "breakdown": score_record.breakdown,
            "calculated_at": score_record.calculated_at.isoformat(),
        }
    return {"framework": framework, "score": None, "message": "No score calculated yet."}


@router.get("/dashboard")
async def get_compliance_dashboard(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a combined compliance dashboard view with latest scores for all frameworks.
    """
    dashboard = {}
    for framework in ["gdpr", "hipaa", "soc2"]:
        result = await db.execute(
            select(ComplianceScore)
            .where(
                ComplianceScore.tenant_id == tenant.id,
                ComplianceScore.framework == framework,
            )
            .order_by(desc(ComplianceScore.calculated_at))
            .limit(1)
        )
        latest = result.scalars().first()
        if latest:
            dashboard[framework] = {
                "score": latest.score,
                "status": _legacy_posture_status(latest.score),
                "critical_violations": latest.critical_violations,
                "last_calculated": latest.calculated_at.isoformat(),
            }
        else:
            dashboard[framework] = {
                "score": None,
                "status": "not_calculated",
                "critical_violations": 0,
                "last_calculated": None,
            }

    return dashboard


@router.get("/export")
async def export_compliance_report(
    framework: str = Query("all", description="Framework to export: gdpr, hipaa, soc2, or all"),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Export the compliance posture report as a signed CSV.

    Includes the latest score for each requested framework along with a
    breakdown of passing/failing controls.

    The response includes an ``X-Report-Signature`` HMAC-SHA256 header so
    downstream consumers can verify the file has not been tampered with.

    Args:
        framework: One of ``gdpr``, ``hipaa``, ``soc2``, or ``all`` (default).
    """
    from app.core.config import settings

    frameworks_to_export = (
        ["gdpr", "hipaa", "soc2"] if framework == "all" else [framework]
    )

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "framework",
        "score",
        "status",
        "critical_violations",
        "policy_failures",
        "security_findings",
        "calculated_at",
    ])

    for fw in frameworks_to_export:
        result = await db.execute(
            select(ComplianceScore)
            .where(
                ComplianceScore.tenant_id == tenant.id,
                ComplianceScore.framework == fw,
            )
            .order_by(desc(ComplianceScore.calculated_at))
            .limit(1)
        )
        score = result.scalars().first()
        if score:
            status = (
                _legacy_posture_status(score.score)
            )
            writer.writerow([
                fw,
                score.score,
                status,
                score.critical_violations,
                score.policy_failures,
                score.security_findings,
                score.calculated_at.isoformat(),
            ])
        else:
            writer.writerow([fw, "N/A", "not_calculated", 0, 0, 0, ""])

    csv_bytes = output.getvalue().encode("utf-8")

    # HMAC-SHA256 signature so consumers can verify file integrity.
    # Only the first 32 bytes of ENCRYPTION_KEY are used to stay within
    # the HMAC key-size best-practice for SHA-256.
    sig = hmac.new(
        settings.ENCRYPTION_KEY.encode("utf-8")[:32],
        csv_bytes,
        hashlib.sha256,
    ).hexdigest()

    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=authclaw_compliance_{framework}.csv"
            ),
            "X-Report-Signature": sig,
        },
    )
