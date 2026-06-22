from __future__ import annotations

import hashlib
import inspect
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.core.database import AsyncSessionLocal
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceAssessmentStatus,
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    ComplianceGapSeverity,
    ComplianceGapType,
    ComplianceScoreBand,
    ControlAssessmentResult,
    EvidenceItem,
    EvidenceSourceType,
    EvidenceStatus,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationArtifactStatus,
    RemediationArtifactType,
    RemediationDryRunResult,
    RemediationDryRunStatus,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationRiskLevel,
    RemediationVerificationResult,
    RemediationVerificationStatus,
)
from app.models.tenant import Tenant
from app.models.trust import ExportManifest, ReportArtifact, ReportRun, ReportRunStatus, ReportTemplate
from app.services import trust_reporting as trust_module
from app.services.trust_reporting import (
    ExportSanitizer,
    EvidencePackageBuilder,
    EvidencePackageRequest,
    LocalReportArtifactStore,
    ReportGenerationRequest,
    ReportGenerationService,
    SANITIZATION_VERSION,
    build_manifest_hash,
    canonical_json,
)

UNSAFE_TERMS = (
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_supersecretsecretsecretsecret",
    "raw_provider_payload",
    "super-secret",
    "vault://",
    "secret/authclaw",
    "authorization",
    "private key",
    "audit-ready",
    "certified",
    "fully compliant",
)


class FakeProducer:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


class FailingStore(LocalReportArtifactStore):
    async def write_json(self, *, tenant_id, run_id, payload):
        raise RuntimeError("failed with token=ghp_supersecretsecretsecretsecret and vault://tenant/raw")


async def _set_tenant(db, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint5-phase2-{suffix}",
        slug=f"sprint5-phase2-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    await _set_tenant(db, tenant.id)
    return tenant


async def _framework_and_control(db, suffix: str):
    framework = ComplianceFramework(
        id=uuid.uuid4(),
        key=f"sprint5_{suffix}",
        version="2026.1",
        name=f"Sprint 5 Framework {suffix}",
        description="Internal summarized framework for evidence-supported posture review.",
        source_url=None,
        license_note="Internal summary only.",
        metadata_={},
    )
    control = ComplianceControl(
        id=uuid.uuid4(),
        framework_id=framework.id,
        control_code=f"AC-{suffix.upper()}",
        title="Access review",
        summary="Access review evidence should be collected.",
        domain="access_control",
        category="identity",
        severity_weight=2,
        requires_review=True,
        metadata_={},
    )
    db.add_all([framework, control])
    await db.flush()
    return framework, control


async def _dataset(db, tenant: Tenant, suffix: str):
    await _set_tenant(db, tenant.id)
    framework, control = await _framework_and_control(db, f"{suffix}_{tenant.id.hex[:8]}")
    integration = CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        provider_type=CloudProvider.aws,
        target_identifier=f"1234567890{suffix[-1:]}",
        display_name=f"aws-{suffix}",
        status=IntegrationStatus.active,
        vault_reference_id=f"secret/authclaw/tenants/{tenant.id}/integrations/{uuid.uuid4()}",
        last_sync_finding_count=1,
    )
    db.add(integration)
    await db.flush()
    finding = SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration.id,
        dedup_hash=hashlib.sha256(f"{tenant.id}:{suffix}".encode()).hexdigest(),
        external_id=f"provider-alert-{suffix}",
        resource_id=f"arn:aws:s3:::safe-summary-{suffix}",
        title=f"S3 bucket public access posture {suffix}",
        description="Provider finding description with raw_provider_payload should not be exported.",
        remediation_instructions="Rotate token ghp_supersecretsecretsecretsecret",
        severity=FindingSeverity.high,
        status=FindingStatus.active,
    )
    db.add(finding)
    await db.flush()
    evidence = EvidenceItem(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        control_id=control.id,
        finding_id=finding.id,
        integration_id=integration.id,
        source_type=EvidenceSourceType.finding_mapping,
        status=EvidenceStatus.active,
        safe_summary=f"Evidence-supported access review posture {suffix}.",
        proof_hash=hashlib.sha256(f"proof-{suffix}".encode()).hexdigest(),
        freshness_expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=20),
        metadata_={"raw_provider_payload": {"authorization": "Bearer super-secret"}},
    )
    db.add(evidence)
    await db.flush()
    assessment = ComplianceAssessment(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        framework_id=framework.id,
        status=ComplianceAssessmentStatus.completed,
        score=72,
        score_band=ComplianceScoreBand.mostly_supported,
        inputs_hash=hashlib.sha256(f"assessment-{suffix}".encode()).hexdigest(),
        explanation="Evidence-supported posture needs review. Not certified.",
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(assessment)
    await db.flush()
    result = ControlAssessmentResult(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        control_id=control.id,
        score=70,
        score_band=ComplianceScoreBand.mostly_supported,
        evidence_count=1,
        gap_count=1,
        explanation="Mapped controls indicate evidence-supported posture.",
        metadata_={"api_key": "AKIAIOSFODNN7EXAMPLE"},
    )
    gap = ComplianceGap(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        control_id=control.id,
        evidence_id=evidence.id,
        finding_id=finding.id,
        gap_type=ComplianceGapType.unresolved_finding,
        severity=ComplianceGapSeverity.high,
        reason="Gap detected; needs review.",
        evidence_status="active",
        metadata_={"private_key": "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----"},
    )
    db.add_all([result, gap])
    await db.flush()
    plan = RemediationPlan(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        finding_id=finding.id,
        gap_id=gap.id,
        integration_id=integration.id,
        provider="aws",
        resource_ref=finding.resource_id,
        risk_level=RemediationRiskLevel.high,
        status=RemediationPlanStatus.verified,
        summary="Documentation-only remediation posture update.",
        expected_impact="No external mutation.",
    )
    db.add(plan)
    await db.flush()
    artifact = RemediationArtifact(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        plan_id=plan.id,
        artifact_type=RemediationArtifactType.documentation_only,
        content_redacted="Documentation-only artifact summary.",
        artifact_hash="c" * 64,
        risk_flags={},
        status=RemediationArtifactStatus.active,
    )
    db.add(artifact)
    await db.flush()
    approval = RemediationApproval(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        plan_id=plan.id,
        artifact_hash="a" * 64,
        policy_check_hash="b" * 64,
        status=RemediationApprovalStatus.approved,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1),
        mfa_verified=True,
        nonce=f"phase2-{uuid.uuid4()}",
    )
    job = RemediationExecutionJob(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        plan_id=plan.id,
        approval_id=approval.id,
        status=RemediationExecutionStatus.succeeded,
        disabled_reason="Controlled simulated execution only.",
    )
    db.add_all([approval, job])
    await db.flush()
    dry_run = RemediationDryRunResult(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        job_id=job.id,
        plan_id=plan.id,
        artifact_id=artifact.id,
        approval_id=approval.id,
        sandbox_id=f"sandbox-{suffix}",
        dry_run_type=RemediationArtifactType.documentation_only.value,
        status=RemediationDryRunStatus.succeeded,
        output_summary="Static dry-run passed. No external mutation.",
        warnings=[],
        blocking_reasons=[],
    )
    verification = RemediationVerificationResult(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        plan_id=plan.id,
        job_id=job.id,
        evidence_id=evidence.id,
        verified=True,
        status=RemediationVerificationStatus.verified,
        verification_summary="Verified through controlled AuthClaw records only.",
    )
    db.add_all([dry_run, verification])
    await db.flush()
    return {
        "framework": framework,
        "control": control,
        "integration": integration,
        "finding": finding,
        "evidence": evidence,
        "assessment": assessment,
        "gap": gap,
        "plan": plan,
        "verification": verification,
    }


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await _set_tenant(db, tenant_id)
        for table in (
            "export_manifests",
            "report_artifacts",
            "report_runs",
            "report_templates",
            "trust_notifications",
            "report_access_logs",
            "external_share_links",
            "remediation_verification_results",
            "remediation_dry_run_results",
            "remediation_execution_jobs",
            "remediation_approvals",
            "remediation_policy_checks",
            "remediation_rollback_plans",
            "remediation_artifacts",
            "remediation_plans",
            "compliance_gaps",
            "control_assessment_results",
            "compliance_assessments",
            "evidence_items",
            "finding_control_mappings",
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(
            text("DELETE FROM security_findings WHERE integration_id IN (SELECT id FROM cloud_integrations WHERE tenant_id = :tenant_id)"),
            {"tenant_id": tenant_id},
        )
        await db.execute(text("DELETE FROM cloud_integrations WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


def _assert_safe_export(value) -> None:
    serialized = json.dumps(value, sort_keys=True, default=str)
    for term in UNSAFE_TERMS:
        assert term.lower() not in serialized.lower()


def test_export_sanitizer_removes_nested_sensitive_data_and_legal_overclaims():
    sanitizer = ExportSanitizer()
    sanitized = sanitizer.sanitize_payload(
        {
            "summary": "This system is fully compliant, certified, guaranteed audit-ready.",
            "authorization": "Bearer super-secret",
            "ip": "127.0.0.1",
            "user_agent": "raw browser",
            "nested": {
                "raw_provider_payload": {"api_key": "AKIAIOSFODNN7EXAMPLE"},
                "private_key": "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----",
                "safe": "mapped controls need review",
            },
            "items": [{"vault_reference_id": "vault://tenant/secret"}, {"title": "safe posture"}],
        }
    )
    _assert_safe_export(sanitized)
    assert sanitized["summary"].count("evidence-supported posture; needs review") >= 1
    assert sanitized["nested"]["safe"] == "mapped controls need review"
    assert sanitized["sanitization_version"] == SANITIZATION_VERSION


@pytest.mark.asyncio
async def test_report_generation_is_tenant_scoped_sanitized_and_persists_metadata_only(tmp_path: Path):
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(3))
        try:
            data_a = await _dataset(db, tenant_a, "a")
            data_b = await _dataset(db, tenant_b, "b")
            producer = FakeProducer()
            store = LocalReportArtifactStore(tmp_path)
            service = ReportGenerationService(db, artifact_store=store, event_producer=producer)

            result = await service.generate_report(
                tenant_a.id,
                ReportGenerationRequest(report_type="trust_overview", filters={"scope": "executive"}),
            )
            assert result.report_run.status == ReportRunStatus.completed
            assert result.artifact is not None
            assert result.manifest is not None
            assert result.payload is not None
            _assert_safe_export(result.payload)
            serialized = json.dumps(result.payload, sort_keys=True, default=str)
            assert str(data_a["finding"].id) in serialized
            assert str(data_b["finding"].id) not in serialized
            assert "vault_reference_id" not in serialized

            stored = store.read_json(result.artifact.storage_key)
            assert build_manifest_hash(result.manifest.manifest_json) == result.manifest.manifest_hash
            assert hashlib.sha256(canonical_json(stored).encode("utf-8")).hexdigest() == result.artifact.content_hash
            assert result.artifact.sanitization_version == SANITIZATION_VERSION
            assert result.artifact.expires_at is not None

            db_artifact = (await db.execute(select(ReportArtifact).where(ReportArtifact.id == result.artifact.id))).scalars().one()
            db_manifest = (await db.execute(select(ExportManifest).where(ExportManifest.artifact_id == db_artifact.id))).scalars().one()
            assert not hasattr(db_artifact, "body")
            assert not hasattr(db_artifact, "raw_content")
            assert db_manifest.manifest_json["content_hash"] == result.artifact.content_hash
            events = [event for _, event in producer.events]
            assert {event["event_type"] for event in events} >= {"trust.report_run.started", "trust.report_run.completed"}
            _assert_safe_export(events)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_evidence_package_builder_filters_and_includes_expected_summaries(tmp_path: Path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "pkg-" + secrets.token_hex(3))
        try:
            data = await _dataset(db, tenant, "pkg")
            producer = FakeProducer()
            builder = EvidencePackageBuilder(db, artifact_store=LocalReportArtifactStore(tmp_path), event_producer=producer)
            result = await builder.create_evidence_package(
                tenant.id,
                EvidencePackageRequest(
                    framework_id=data["framework"].id,
                    control_ids=[data["control"].id],
                    include_findings=True,
                    include_remediation=True,
                    retention_days=14,
                ),
            )
            assert result.report_run.status == ReportRunStatus.completed
            assert result.payload is not None
            _assert_safe_export(result.payload)
            assert len(result.payload["evidence_summaries"]) == 1
            assert result.payload["linked_findings"][0]["id"] == str(data["finding"].id)
            assert result.payload["remediation_status"]["plans"][0]["id"] == str(data["plan"].id)
            assert result.payload["verification_summaries"][0]["id"] == str(data["verification"].id)
            assert result.artifact is not None
            assert result.artifact.expires_at is not None
            assert (result.artifact.expires_at - datetime.now(timezone.utc).replace(tzinfo=None)).days <= 14
            assert any(event[1]["event_type"] == "trust.evidence_package.created" for event in producer.events)
            _assert_safe_export([event for _, event in producer.events])
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_report_generation_failure_records_sanitized_failed_reason_and_event(tmp_path: Path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "fail-" + secrets.token_hex(3))
        try:
            await _dataset(db, tenant, "fail")
            producer = FakeProducer()
            service = ReportGenerationService(db, artifact_store=FailingStore(tmp_path), event_producer=producer)
            result = await service.generate_report(tenant.id, ReportGenerationRequest(report_type="trust_overview"))
            assert result.report_run.status == ReportRunStatus.failed
            assert result.report_run.failed_reason is not None
            _assert_safe_export({"failed_reason": result.report_run.failed_reason})
            assert result.artifact is None
            assert any(event[1]["event_type"] == "trust.report_run.failed" for event in producer.events)
            _assert_safe_export([event for _, event in producer.events])
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_running_duplicate_guard_returns_existing_run_without_artifact(tmp_path: Path):
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "dupe-" + secrets.token_hex(3))
        try:
            service = ReportGenerationService(db, artifact_store=LocalReportArtifactStore(tmp_path), event_producer=FakeProducer())
            request = ReportGenerationRequest(report_type="trust_overview", filters={"scope": "executive"})
            filters = service.sanitizer.sanitize_payload(
                {
                    "report_type": request.report_type,
                    "filters": dict(request.filters),
                    "template_id": None,
                    "output_format": "json",
                }
            )
            filter_hash = build_manifest_hash(filters)
            run = ReportRun(
                tenant_id=tenant.id,
                status=ReportRunStatus.running,
                filters={**filters, "filter_hash": filter_hash},
            )
            db.add(run)
            await db.flush()

            result = await service.generate_report(tenant.id, request)
            assert result.report_run.id == run.id
            assert result.artifact is None
            assert result.manifest is None
        finally:
            await _cleanup(db, tenant.id)


def test_phase2_service_source_does_not_import_real_execution_clients():
    source = inspect.getsource(trust_module)
    forbidden = (
        "boto3",
        "google.cloud",
        "Github(",
        "subprocess",
        "terraform apply",
        "terraform destroy",
        "os.system",
    )
    for term in forbidden:
        assert term not in source
