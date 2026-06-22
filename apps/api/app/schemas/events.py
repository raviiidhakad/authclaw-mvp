"""
AuthClaw Kafka Event Schemas
-----------------------------
Defines all Pydantic models for events published to Kafka topics across the
AuthClaw platform.  Each class maps 1-to-1 to a Kafka topic namespace:

  authclaw.gateway.events   →  GatewayEvent
  authclaw.audit.events     →  AuditEvent
  authclaw.security.events  →  SecurityEvent
  authclaw.user.events      →  UserEvent
  authclaw.agent.events     →  AgentEvent

Legacy thin wrappers (GatewayRequestEvent) are kept for backward compatibility.
"""
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


# ---------------------------------------------------------------------------
# Base event — all schema-versioned events inherit from this
# ---------------------------------------------------------------------------

class BaseEvent(BaseModel):
    """Base schema for all AuthClaw Kafka events.

    Attributes:
        version:    Schema version integer for consumer-side deserialization.
        event_id:   UUID v4 unique identifier for this event instance.
        event_type: Dot-notation event type string, e.g. "gateway.request.completed".
        tenant_id:  UUID of the tenant this event belongs to.
        timestamp:  ISO-8601 UTC timestamp of when the event was created.
        actor_id:   UUID of the user or service account that triggered the event.
        payload:    Arbitrary additional data; schema is event-type-specific.
    """
    version: int = Field(1, description="Schema version")
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_type: str
    tenant_id: Optional[uuid.UUID] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: Optional[uuid.UUID] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Gateway events — published to authclaw.gateway.events
# ---------------------------------------------------------------------------

class GatewayRequestEvent(BaseEvent):
    """Legacy gateway event — kept for backward compatibility.

    New consumers should subscribe to GatewayEvent which carries richer
    analytics fields (latency, token counts, model, provider name).
    """
    event_type: str = "gateway.request"


class GatewayEvent(BaseModel):
    """Rich analytics event for every AI request processed by the gateway.

    Published to the ``authclaw.gateway.events`` Kafka topic after each
    synchronous (non-streaming) request completes or errors.

    Event types:
        gateway.request.completed  — provider responded successfully (2xx)
        gateway.request.error      — provider returned a non-2xx status
        gateway.blocked            — request blocked by a policy rule
        gateway.error              — internal gateway failure

    Attributes:
        event_id:           UUID v4 unique identifier for deduplication.
        event_type:         Dot-notation classification of the gateway outcome.
        tenant_id:          Tenant that issued the request.
        request_id:         Correlation ID (api_key_id used as surrogate).
        provider:           Human-readable provider name (e.g. "openai-prod").
        model:              Model identifier forwarded to the provider.
        status:             Raw HTTP status code returned by the provider.
        latency_ms:         Wall-clock milliseconds for the provider round-trip.
        tokens_prompt:      Prompt token count from provider usage response.
        tokens_completion:  Completion token count from provider usage response.
        timestamp:          ISO-8601 UTC string of event creation time.
        payload:            Extra context (e.g. error_type for failed requests).
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str  # gateway.request.completed | gateway.request.error | gateway.blocked
    tenant_id: str
    request_id: str
    provider: Optional[str] = None
    model: Optional[str] = None
    status: int
    latency_ms: int = 0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    timestamp: str
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Audit events — published to authclaw.audit.events
# ---------------------------------------------------------------------------

class AuditEvent(BaseEvent):
    """Thin wrapper for audit-trail events written to the audit ledger.

    Extends BaseEvent so that all base fields (event_id, tenant_id, actor_id,
    timestamp, payload) are inherited.  The default event_type is overridable
    for sub-categories such as "audit.chain.verified" or "audit.export".
    """
    event_type: str = "audit.record"


# ---------------------------------------------------------------------------
# Security events — published to authclaw.security.events
# ---------------------------------------------------------------------------

class SecurityEvent(BaseEvent):
    """Event raised when a security-relevant anomaly or threat is detected.

    Examples: audit chain tampering detected, brute-force login attempt,
    unknown API key used, rate-limit breach on a sensitive endpoint.
    """
    event_type: str = "security.event"


# ---------------------------------------------------------------------------
# User lifecycle events — published to authclaw.user.events
# ---------------------------------------------------------------------------

class UserEvent(BaseEvent):
    """Event raised for user lifecycle transitions.

    Examples: user.created, user.deactivated, user.role_changed,
    user.mfa_enabled, user.password_reset.
    """
    event_type: str = "user.lifecycle"


# ---------------------------------------------------------------------------
# Agent events — published to authclaw.agent.events
# ---------------------------------------------------------------------------

class AgentEvent(BaseModel):
    """Event raised by the AuthClaw autonomous remediation agent.

    Published to the ``authclaw.agent.events`` Kafka topic after scan or
    remediation tasks complete, stall, or require human-in-the-loop approval.

    Event types:
        agent.scan.started        — a scan task was dispatched
        agent.scan.completed      — scan finished with findings list
        agent.scan.failed         — scan encountered an unrecoverable error
        agent.remediation.proposed — agent proposed an action, awaiting approval
        agent.remediation.applied  — approved action was successfully applied
        agent.remediation.rejected — HITL operator rejected the proposed action

    Attributes:
        event_id:       UUID v4 unique identifier.
        event_type:     Dot-notation classification of the agent action.
        tenant_id:      Tenant the agent is operating on behalf of.
        task_id:        Unique identifier for the scan / remediation task.
        target:         Resource or scope the agent is examining (e.g. policy id).
        actor_id:       Service account or user that triggered the task.
        findings:       List of finding dicts (empty for non-scan events).
        timestamp:      ISO-8601 UTC string of event creation time.
        payload:        Arbitrary extra data (error messages, diff snippets, etc.).
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str  # agent.scan.started | agent.scan.completed | agent.remediation.*
    tenant_id: str
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: Optional[str] = None
    actor_id: Optional[str] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Connector sync events — published to authclaw.connector.events
# ---------------------------------------------------------------------------

class AgentContextBuiltEvent(AgentEvent):
    event_type: str = "agent.context.built"
    target: Optional[str] = "security_findings"
    finding_count: int = 0
    max_severity: Optional[str] = None
    provider_types: List[str] = Field(default_factory=list)
    integration_ids: List[str] = Field(default_factory=list)
    duration_ms: int = 0


class IntegrationLifecycleEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    tenant_id: str
    integration_id: str
    provider_type: str
    target_identifier: Optional[str] = None
    status: Optional[str] = None
    actor_id: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload: Dict[str, Any] = Field(default_factory=dict)


class IntegrationCreatedEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.created"


class IntegrationUpdatedEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.updated"


class IntegrationDeletedEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.deleted"


class IntegrationDisabledEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.disabled"


class IntegrationValidationRequestedEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.validation.requested"


class IntegrationValidationCompletedEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.validation.completed"
    valid: bool = False
    error_code: Optional[str] = None
    missing_permissions: List[str] = Field(default_factory=list)


class IntegrationSyncRequestedEvent(IntegrationLifecycleEvent):
    event_type: str = "integration.sync.requested"
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class FindingStatusChangedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "finding.status.changed"
    tenant_id: str
    finding_id: str
    integration_id: str
    provider_type: str
    old_status: str
    new_status: str
    actor_id: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload: Dict[str, Any] = Field(default_factory=dict)


class RemediationEvent(BaseEvent):
    event_type: str
    plan_id: Optional[uuid.UUID] = None
    status: Optional[str] = None
    risk_level: Optional[str] = None
    reason: Optional[str] = None


class RemediationPlanCreatedEvent(RemediationEvent):
    event_type: str = "remediation.plan.created"
    plan_id: uuid.UUID
    status: str
    risk_level: str


class RemediationPlanStatusChangedEvent(RemediationEvent):
    event_type: str = "remediation.plan.status_changed"
    plan_id: uuid.UUID
    previous_status: str
    status: str
    risk_level: str


class RemediationArtifactCreatedEvent(RemediationEvent):
    event_type: str = "remediation.artifact.created"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    artifact_type: str
    artifact_hash: str
    status: str


class RemediationPlanGeneratedEvent(RemediationEvent):
    event_type: str = "remediation.plan.generated"
    plan_id: uuid.UUID
    source_type: str
    source_id: uuid.UUID
    risk_level: str
    artifact_count: int = 0


class RemediationArtifactDraftedEvent(RemediationEvent):
    event_type: str = "remediation.artifact.drafted"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    source_type: str
    source_id: uuid.UUID
    artifact_type: str
    artifact_hash: str
    risk_level: str


class RemediationRollbackPlanCreatedEvent(RemediationEvent):
    event_type: str = "remediation.rollback_plan.created"
    plan_id: uuid.UUID
    source_type: str
    source_id: uuid.UUID
    risk_level: str
    rollback_uncertain: bool = False


class RemediationPlanValidatedEvent(RemediationEvent):
    event_type: str = "remediation.plan.validated"
    plan_id: uuid.UUID
    policy_check_id: uuid.UUID
    passed: bool
    warning_count: int
    blocking_reason_count: int
    required_approval_level: str
    policy_check_hash: str


class RemediationPolicyCheckFailedEvent(RemediationEvent):
    event_type: str = "remediation.policy_check.failed"
    plan_id: uuid.UUID
    policy_check_id: uuid.UUID
    passed: bool
    warning_count: int
    blocking_reason_count: int
    required_approval_level: str
    policy_check_hash: str


class RemediationPolicyWarningEvent(RemediationEvent):
    event_type: str = "remediation.policy_check.warning"
    plan_id: uuid.UUID
    policy_check_id: uuid.UUID
    passed: bool
    warning_count: int
    blocking_reason_count: int
    required_approval_level: str
    policy_check_hash: str


class RemediationApprovalRequestedEvent(RemediationEvent):
    event_type: str = "remediation.approval.requested"
    plan_id: uuid.UUID
    approval_id: Optional[uuid.UUID] = None
    artifact_hash: str
    policy_check_hash: str
    status: str
    required_approval_level: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason_category: Optional[str] = None


class RemediationApprovedEvent(RemediationEvent):
    event_type: str = "remediation.approved"
    plan_id: uuid.UUID
    approval_id: uuid.UUID
    artifact_hash: str
    policy_check_hash: str
    status: str
    required_approval_level: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason_category: Optional[str] = None


class RemediationRejectedEvent(RemediationEvent):
    event_type: str = "remediation.rejected"
    plan_id: uuid.UUID
    approval_id: Optional[uuid.UUID] = None
    status: str
    required_approval_level: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason_category: Optional[str] = None


class RemediationApprovalExpiredEvent(RemediationEvent):
    event_type: str = "remediation.approval.expired"
    plan_id: uuid.UUID
    approval_id: uuid.UUID
    status: str
    required_approval_level: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason_category: Optional[str] = None


class RemediationApprovalRevokedEvent(RemediationEvent):
    event_type: str = "remediation.approval.revoked"
    plan_id: uuid.UUID
    approval_id: uuid.UUID
    status: str
    required_approval_level: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason_category: Optional[str] = None


class RemediationApprovalReplayBlockedEvent(RemediationEvent):
    event_type: str = "remediation.approval.replay_blocked"
    plan_id: uuid.UUID
    approval_id: uuid.UUID
    status: str
    required_approval_level: Optional[str] = None
    reason_category: Optional[str] = None


class RemediationExecutionBlockedEvent(RemediationEvent):
    event_type: str = "remediation.execution.blocked"
    plan_id: uuid.UUID
    attempted_status: str | None = None
    disabled_reason: str | None = None
    artifact_id: Optional[uuid.UUID] = None
    job_id: Optional[uuid.UUID] = None
    status: Optional[str] = None
    adapter_type: Optional[str] = None
    simulated: bool = False
    reason_category: Optional[str] = None


class RemediationExecutionQueuedEvent(RemediationEvent):
    event_type: str = "remediation.execution.queued"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    status: str
    adapter_type: str
    simulated: bool = False


class RemediationExecutionStartedEvent(RemediationEvent):
    event_type: str = "remediation.execution.started"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    status: str
    adapter_type: str
    simulated: bool = False


class RemediationExecutionSucceededEvent(RemediationEvent):
    event_type: str = "remediation.execution.succeeded"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    status: str
    adapter_type: str
    simulated: bool = False


class RemediationExecutionFailedEvent(RemediationEvent):
    event_type: str = "remediation.execution.failed"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    status: str
    adapter_type: str
    simulated: bool = False
    reason_category: Optional[str] = None


class RemediationVerifiedEvent(RemediationEvent):
    event_type: str = "remediation.verified"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    verification_result_id: uuid.UUID
    status: str
    adapter_type: str
    simulated: bool = False


class RemediationRollbackRequiredEvent(RemediationEvent):
    event_type: str = "remediation.rollback.required"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    status: str
    adapter_type: str
    simulated: bool = False
    reason_category: Optional[str] = None


class RemediationDryRunQueuedEvent(RemediationEvent):
    event_type: str = "remediation.dry_run.queued"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    result_id: Optional[uuid.UUID] = None
    status: str
    warning_count: int = 0
    blocking_reason_count: int = 0


class RemediationDryRunStartedEvent(RemediationEvent):
    event_type: str = "remediation.dry_run.started"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    result_id: Optional[uuid.UUID] = None
    status: str
    warning_count: int = 0
    blocking_reason_count: int = 0


class RemediationDryRunCompletedEvent(RemediationEvent):
    event_type: str = "remediation.dry_run.completed"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    result_id: uuid.UUID
    status: str
    warning_count: int
    blocking_reason_count: int


class RemediationDryRunFailedEvent(RemediationEvent):
    event_type: str = "remediation.dry_run.failed"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: uuid.UUID
    result_id: Optional[uuid.UUID] = None
    status: str
    warning_count: int = 0
    blocking_reason_count: int = 0


class RemediationSandboxRejectedArtifactEvent(RemediationEvent):
    event_type: str = "remediation.sandbox.rejected_artifact"
    plan_id: uuid.UUID
    artifact_id: uuid.UUID
    job_id: Optional[uuid.UUID] = None
    result_id: Optional[uuid.UUID] = None
    status: str
    warning_count: int = 0
    blocking_reason_count: int


class TrustReportEvent(BaseEvent):
    event_type: str
    artifact_id: Optional[uuid.UUID] = None
    report_run_id: Optional[uuid.UUID] = None
    share_link_id: Optional[uuid.UUID] = None
    notification_id: Optional[uuid.UUID] = None
    status: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


class ReportRunStartedEvent(TrustReportEvent):
    event_type: str = "trust.report_run.started"
    report_run_id: uuid.UUID
    status: str = "running"


class ReportRunCompletedEvent(TrustReportEvent):
    event_type: str = "trust.report_run.completed"
    report_run_id: uuid.UUID
    artifact_id: Optional[uuid.UUID] = None
    status: str = "completed"


class ReportRunFailedEvent(TrustReportEvent):
    event_type: str = "trust.report_run.failed"
    report_run_id: uuid.UUID
    status: str = "failed"
    reason_category: Optional[str] = None


class EvidencePackageCreatedEvent(TrustReportEvent):
    event_type: str = "trust.evidence_package.created"
    report_run_id: uuid.UUID
    artifact_id: uuid.UUID
    manifest_hash: str


class ReportDownloadedEvent(TrustReportEvent):
    event_type: str = "trust.report.downloaded"
    artifact_id: uuid.UUID
    access_log_id: Optional[uuid.UUID] = None


class ShareLinkCreatedEvent(TrustReportEvent):
    event_type: str = "trust.share_link.created"
    artifact_id: uuid.UUID
    share_link_id: uuid.UUID
    expires_at: datetime


class ShareLinkRevokedEvent(TrustReportEvent):
    event_type: str = "trust.share_link.revoked"
    artifact_id: uuid.UUID
    share_link_id: uuid.UUID


class TrustCenterViewedEvent(TrustReportEvent):
    event_type: str = "trust.center.viewed"


class NotificationCreatedEvent(TrustReportEvent):
    event_type: str = "trust.notification.created"
    notification_id: uuid.UUID


class FindingControlMappingEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    tenant_id: str
    finding_id: str
    control_id: str
    rule_id: str
    confidence: float
    review_status: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload: Dict[str, Any] = Field(default_factory=dict)


class FindingMappedToControlEvent(FindingControlMappingEvent):
    event_type: str = "compliance.finding.mapped"


class FindingMappingNeedsReviewEvent(FindingControlMappingEvent):
    event_type: str = "compliance.finding_mapping.needs_review"


class FindingMappingOverriddenEvent(FindingControlMappingEvent):
    event_type: str = "compliance.finding_mapping.overridden"


class ComplianceMappingReviewedEvent(FindingControlMappingEvent):
    event_type: str = "compliance.finding_mapping.reviewed"
    actor_id: str | None = None


class EvidenceEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    evidence_id: str
    control_id: str
    finding_id: str | None = None
    mapping_id: str | None = None
    status: str


class EvidenceCreatedEvent(EvidenceEvent):
    event_type: str = "compliance.evidence.created"


class EvidenceExpiredEvent(EvidenceEvent):
    event_type: str = "compliance.evidence.expired"


class ComplianceAssessmentEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    assessment_id: str
    framework_id: str
    status: str
    score: float | None = None
    score_band: str | None = None


class ComplianceAssessmentStartedEvent(ComplianceAssessmentEvent):
    event_type: str = "compliance.assessment.started"


class ComplianceAssessmentCompletedEvent(ComplianceAssessmentEvent):
    event_type: str = "compliance.assessment.completed"


class ComplianceGapDetectedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "compliance.gap.detected"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    assessment_id: str
    control_id: str
    gap_type: str
    severity: str
    evidence_status: str
    evidence_id: str | None = None
    finding_id: str | None = None
    mapping_id: str | None = None


class ControlStatusChangedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "compliance.control_status.changed"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    assessment_id: str
    control_id: str
    score: float
    score_band: str


class KnowledgeDocumentEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str | None = None
    document_id: str
    framework_id: str | None = None
    source_type: str
    status: str
    chunk_count: int = 0
    checksum: str | None = None


class KnowledgeDocumentIngestedEvent(KnowledgeDocumentEvent):
    event_type: str = "compliance.knowledge.document.ingested"


class KnowledgeDocumentUpdatedEvent(KnowledgeDocumentEvent):
    event_type: str = "compliance.knowledge.document.updated"


class KnowledgeChunkCreatedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "compliance.knowledge.chunks.created"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str | None = None
    document_id: str
    framework_id: str | None = None
    chunk_count: int


class ComplianceKnowledgeRetrievedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "compliance.knowledge.retrieved"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    trace_id: str
    framework_id: str | None = None
    result_count: int
    strategy: str
    max_score: float = 0


class ComplianceQuestionAskedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "compliance.question.asked"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    session_id: str
    query_hash: str
    framework_id: str | None = None
    control_id: str | None = None
    confidence: float
    refused: bool
    refusal_reason: str | None = None
    retrieval_trace_id: str | None = None
    citation_count: int = 0


class ConnectorEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    tenant_id: str
    integration_id: str
    provider_type: str
    scan_id: str
    status: str
    finding_count: Optional[int] = None
    max_severity: Optional[str] = None
    duration_ms: int = 0
    error_code: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload: Dict[str, Any] = Field(default_factory=dict)


class IntegrationSyncStartedEvent(ConnectorEvent):
    event_type: str = "integration.sync.started"
    status: str = "started"


class IntegrationSyncSkippedEvent(ConnectorEvent):
    event_type: str = "integration.sync.skipped"
    status: str = "skipped"


class FindingsDiscoveredEvent(ConnectorEvent):
    event_type: str = "integration.findings.discovered"
    status: str = "findings_discovered"


class IntegrationSyncCompletedEvent(ConnectorEvent):
    event_type: str = "integration.sync.completed"
    status: str = "completed"


class IntegrationSyncFailedEvent(ConnectorEvent):
    event_type: str = "integration.sync.failed"
    status: str = "failed"
