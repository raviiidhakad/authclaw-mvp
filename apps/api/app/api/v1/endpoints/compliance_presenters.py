from app.models.compliance import (
    AgentComplianceSession,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    ControlAssessmentResult,
    EvidenceItem,
    FindingControlMapping,
    KnowledgeChunk,
    KnowledgeDocument,
)
from app.schemas.compliance import (
    ComplianceAskResponse,
    ComplianceAskSessionResponse,
    ComplianceAssessmentResponse,
    ComplianceControlResponse,
    ComplianceFrameworkResponse,
    ComplianceGapResponse,
    ComplianceRecommendationResponse,
    ControlAssessmentResultResponse,
    ControlRequirementResponse,
    EvidenceItemResponse,
    FindingControlMappingResponse,
    KnowledgeChunkResponse,
    KnowledgeDocumentResponse,
    RetrievalCitationResponse,
    RetrievalChunkResultResponse,
    RetrievalQueryResponse,
)


def enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def legacy_posture_status(score: float) -> str:
    if score >= 80:
        return "evidence_supported"
    if score >= 50:
        return "at_risk"
    return "high_risk"


def requirement_response(requirement) -> ControlRequirementResponse:
    return ControlRequirementResponse(
        id=requirement.id,
        requirement_key=requirement.requirement_key,
        summary=requirement.summary,
        evidence_expectation=requirement.evidence_expectation,
        sort_order=requirement.sort_order,
    )


def control_response(control: ComplianceControl) -> ComplianceControlResponse:
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
        requirements=[requirement_response(req) for req in control.requirements],
        created_at=control.created_at,
        updated_at=control.updated_at,
    )


def framework_response(framework: ComplianceFramework) -> ComplianceFrameworkResponse:
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


def mapping_response(mapping: FindingControlMapping) -> FindingControlMappingResponse:
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


def evidence_response(evidence: EvidenceItem) -> EvidenceItemResponse:
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
        source_type=enum_value(evidence.source_type),
        status=enum_value(evidence.status),
        safe_summary=evidence.safe_summary,
        proof_hash=evidence.proof_hash,
        freshness_expires_at=evidence.freshness_expires_at,
        metadata=evidence.metadata_,
        control_code=control.control_code if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=evidence.created_at,
        updated_at=evidence.updated_at,
    )


def gap_response(gap: ComplianceGap) -> ComplianceGapResponse:
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
        gap_type=enum_value(gap.gap_type),
        severity=enum_value(gap.severity),
        reason=gap.reason,
        evidence_status=gap.evidence_status,
        metadata=gap.metadata_,
        control_code=control.control_code if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=gap.created_at,
        updated_at=gap.updated_at,
    )


def control_result_response(result: ControlAssessmentResult) -> ControlAssessmentResultResponse:
    control = result.control
    return ControlAssessmentResultResponse(
        id=result.id,
        tenant_id=result.tenant_id,
        assessment_id=result.assessment_id,
        control_id=result.control_id,
        score=result.score,
        score_band=enum_value(result.score_band),
        evidence_count=result.evidence_count,
        gap_count=result.gap_count,
        explanation=result.explanation,
        metadata=result.metadata_,
        control_code=control.control_code if control is not None else None,
        control_title=control.title if control is not None else None,
        created_at=result.created_at,
        updated_at=result.updated_at,
    )


def assessment_response(
    assessment: ComplianceAssessment,
    include_detail: bool = False,
) -> ComplianceAssessmentResponse:
    framework = assessment.framework
    return ComplianceAssessmentResponse(
        id=assessment.id,
        tenant_id=assessment.tenant_id,
        framework_id=assessment.framework_id,
        framework_key=framework.key if framework is not None else None,
        status=enum_value(assessment.status),
        score=assessment.score,
        score_band=enum_value(assessment.score_band),
        started_at=assessment.started_at,
        completed_at=assessment.completed_at,
        inputs_hash=assessment.inputs_hash,
        explanation=assessment.explanation,
        control_results=[
            control_result_response(item)
            for item in (assessment.control_results if include_detail else [])
        ],
        gaps=[gap_response(gap) for gap in (assessment.gaps if include_detail else [])],
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def knowledge_chunk_response(chunk: KnowledgeChunk) -> KnowledgeChunkResponse:
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


def knowledge_document_response(
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
        status=enum_value(document.status),
        ingested_by=document.ingested_by,
        metadata=document.metadata_,
        chunk_count=len(chunks),
        chunks=[knowledge_chunk_response(chunk) for chunk in chunks] if include_chunks else [],
        created_at=document.created_at,
        updated_at=document.updated_at,
    )


def retrieval_response(result) -> RetrievalQueryResponse:
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


def ask_response(result) -> ComplianceAskResponse:
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


def ask_session_response(session: AgentComplianceSession) -> ComplianceAskSessionResponse:
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


def recommendation_response(gap: ComplianceGap) -> ComplianceRecommendationResponse:
    control = gap.control
    framework = control.framework if control is not None else None
    return ComplianceRecommendationResponse(
        id=gap.id,
        tenant_id=gap.tenant_id,
        control_id=gap.control_id,
        gap_id=gap.id,
        finding_id=gap.finding_id,
        severity=enum_value(gap.severity),
        status="review_recommended",
        title=f"Review {enum_value(gap.gap_type).replace('_', ' ')}",
        summary=gap.reason,
        control_code=control.control_code if control is not None else None,
        framework_key=framework.key if framework is not None else None,
        created_at=gap.created_at,
    )
