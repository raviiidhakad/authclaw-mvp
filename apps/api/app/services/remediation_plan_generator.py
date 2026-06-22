from __future__ import annotations

import inspect
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.compliance import ComplianceGap, ComplianceGapSeverity, ComplianceGapType
from app.models.finding import FindingSeverity, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider
from app.models.remediation import (
    RemediationArtifact,
    RemediationArtifactType,
    RemediationPlan,
    RemediationRiskLevel,
    RemediationRollbackPlan,
)
from app.schemas.events import (
    RemediationArtifactDraftedEvent,
    RemediationPlanGeneratedEvent,
    RemediationRollbackPlanCreatedEvent,
)
from app.services.api_safety import collect_secret_values, sanitize_text
from app.services.remediation_state_machine import REMEDIATION_EVENTS_TOPIC, RemediationPlanService

logger = logging.getLogger(__name__)

NON_EXECUTING_NOTICE = (
    "NON-EXECUTING DRAFT ONLY. This artifact is for human review, future policy "
    "validation, and future approval. AuthClaw Sprint 4 Phase 2 does not execute, "
    "dry-run, apply, mutate cloud resources, or create pull requests."
)


@dataclass(frozen=True)
class SourceContext:
    source_type: str
    source_id: uuid.UUID
    finding: SecurityFinding | None = None
    gap: ComplianceGap | None = None
    integration: CloudIntegration | None = None


@dataclass(frozen=True)
class TemplateSpec:
    template_key: str
    risk_level: RemediationRiskLevel
    artifact_type: RemediationArtifactType
    summary: str
    expected_impact: str
    artifact_content: str
    diff_summary: str
    rollback_steps: str
    rollback_uncertain: bool
    risk_flags: dict[str, Any]


@dataclass(frozen=True)
class GeneratedRemediationPlan:
    plan: RemediationPlan
    artifacts: list[RemediationArtifact]
    rollback_plan: RemediationRollbackPlan
    source_type: str
    source_id: uuid.UUID


class RemediationPlanGenerator:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer
        self.plan_service = RemediationPlanService(db, event_producer=event_producer)

    async def preview_plan_inputs(
        self,
        tenant_id: uuid.UUID | str,
        source_type: str,
        source_id: uuid.UUID | str,
    ) -> dict[str, Any]:
        source = await self._source_context(tenant_id, source_type, source_id)
        spec = self._template_for(source)
        return {
            "source_type": source.source_type,
            "source_id": str(source.source_id),
            "template_key": spec.template_key,
            "risk_level": spec.risk_level.value,
            "artifact_type": spec.artifact_type.value,
            "summary": sanitize_text(spec.summary),
            "rollback_uncertain": spec.rollback_uncertain,
        }

    async def generate_from_finding(
        self,
        tenant_id: uuid.UUID | str,
        finding_id: uuid.UUID | str,
        actor_id: uuid.UUID | str | None = None,
    ) -> GeneratedRemediationPlan:
        source = await self._source_context(tenant_id, "finding", finding_id)
        return await self._generate(source, actor_id=actor_id)

    async def generate_from_gap(
        self,
        tenant_id: uuid.UUID | str,
        gap_id: uuid.UUID | str,
        actor_id: uuid.UUID | str | None = None,
    ) -> GeneratedRemediationPlan:
        source = await self._source_context(tenant_id, "gap", gap_id)
        return await self._generate(source, actor_id=actor_id)

    async def generate_from_recommendation(
        self,
        tenant_id: uuid.UUID | str,
        recommendation_id: uuid.UUID | str,
        actor_id: uuid.UUID | str | None = None,
    ) -> GeneratedRemediationPlan:
        # Sprint 3 recommendations are derived views over ComplianceGap rows;
        # their response id is the gap id. Persist the id as recommendation_id
        # while preserving the gap relationship for tenant isolation.
        source = await self._source_context(tenant_id, "recommendation", recommendation_id)
        result = await self._generate(source, actor_id=actor_id)
        result.plan.recommendation_id = source.source_id
        await self.db.flush()
        return result

    async def _generate(
        self,
        source: SourceContext,
        actor_id: uuid.UUID | str | None = None,
    ) -> GeneratedRemediationPlan:
        spec = self._template_for(source)
        plan = await self.plan_service.create_draft_plan_shell(
            tenant_id=source_tenant_id(source),
            finding_id=source.finding.id if source.finding else None,
            gap_id=source.gap.id if source.gap else None,
            actor_id=actor_id,
            summary=spec.summary,
            expected_impact=spec.expected_impact,
            risk_level=spec.risk_level,
        )
        artifact = await self.plan_service.attach_artifact_placeholder(
            tenant_id=plan.tenant_id,
            plan_id=plan.id,
            artifact_type=spec.artifact_type,
            content=spec.artifact_content,
            diff_summary=spec.diff_summary,
            risk_flags=spec.risk_flags,
        )
        rollback = await self.plan_service.attach_rollback_placeholder(
            tenant_id=plan.tenant_id,
            plan_id=plan.id,
            rollback_steps=spec.rollback_steps,
            risk_level=spec.risk_level,
        )
        await self._emit_generation_events(source, plan, artifact, rollback, spec)
        return GeneratedRemediationPlan(
            plan=plan,
            artifacts=[artifact],
            rollback_plan=rollback,
            source_type=source.source_type,
            source_id=source.source_id,
        )

    async def _source_context(
        self,
        tenant_id: uuid.UUID | str,
        source_type: str,
        source_id: uuid.UUID | str,
    ) -> SourceContext:
        tenant_uuid = self._uuid(tenant_id)
        source_uuid = self._uuid(source_id)
        await self._set_tenant_context(tenant_uuid)
        normalized = source_type.strip().lower()
        if normalized == "finding":
            result = await self.db.execute(
                select(SecurityFinding, CloudIntegration)
                .join(CloudIntegration, SecurityFinding.integration_id == CloudIntegration.id)
                .where(SecurityFinding.id == source_uuid, CloudIntegration.tenant_id == tenant_uuid)
            )
            row = result.first()
            if row is None:
                raise NotFoundException(detail="Security finding not found for tenant")
            return SourceContext("finding", source_uuid, finding=row[0], integration=row[1])
        if normalized in {"gap", "recommendation"}:
            gap = (
                await self.db.execute(
                    select(ComplianceGap).where(ComplianceGap.id == source_uuid, ComplianceGap.tenant_id == tenant_uuid)
                )
            ).scalars().first()
            if gap is None:
                raise NotFoundException(detail="Compliance gap/recommendation not found for tenant")
            return SourceContext(normalized, source_uuid, gap=gap)
        raise BadRequestException(detail="source_type must be finding, gap, or recommendation")

    def _template_for(self, source: SourceContext) -> TemplateSpec:
        if source.finding is not None:
            return self._finding_template(source)
        if source.gap is not None:
            return self._gap_template(source)
        return self._manual_template(source, "unknown_source")

    def _finding_template(self, source: SourceContext) -> TemplateSpec:
        finding = source.finding
        assert finding is not None
        integration = source.integration
        provider = integration.provider_type if integration is not None else None
        text_blob = " ".join(
            [
                str(finding.title or ""),
                str(finding.description or ""),
                str(finding.remediation_instructions or ""),
                str(finding.resource_id or ""),
            ]
        ).lower()
        resource_ref = sanitize_text(finding.resource_id)

        if provider == CloudProvider.aws and self._has_any(text_blob, ["s3", "bucket"]) and "public" in text_blob:
            return self._spec(
                source,
                "aws_s3_public_access_block",
                RemediationRiskLevel.high,
                RemediationArtifactType.terraform_plan_draft,
                f"Draft S3 public-access remediation plan for {resource_ref}.",
                "Expected impact: block public access after future validation and approval. Verification should refresh AWS findings, confirm bucket public-access posture, and update mapped compliance evidence.",
                [
                    "# Terraform draft only; do not apply from AuthClaw Phase 2.",
                    f"# Resource: {resource_ref}",
                    'resource "aws_s3_bucket_public_access_block" "reviewed_bucket" {',
                    "  bucket = \"<review-safe-bucket-name>\"",
                    "  block_public_acls       = true",
                    "  block_public_policy     = true",
                    "  ignore_public_acls      = true",
                    "  restrict_public_buckets = true",
                    "}",
                ],
                "Draft would add or update S3 public access block settings after future validation.",
                "Restore previous S3 public access block configuration if known. If prior settings are unknown, require manual AWS console/API review before rollback.",
                rollback_uncertain=True,
            )
        if provider == CloudProvider.aws and "cloudtrail" in text_blob and self._has_any(
            text_blob,
            ["disabled", "missing", "logging", "trail"],
        ):
            return self._spec(
                source,
                "aws_cloudtrail_enable_logging",
                RemediationRiskLevel.high if self._severity(finding) in {"high", "critical"} else RemediationRiskLevel.medium,
                RemediationArtifactType.terraform_plan_draft,
                f"Draft CloudTrail logging remediation plan for {resource_ref}.",
                "Expected impact: improve audit logging coverage after future validation and approval. Verification should check connector scan results, CloudTrail posture evidence, and related compliance gaps.",
                [
                    "# Terraform draft only; do not apply from AuthClaw Phase 2.",
                    "# Create or enable a reviewed multi-region trail with encrypted log delivery.",
                    'resource "aws_cloudtrail" "reviewed_trail" {',
                    "  name                          = \"<review-safe-trail-name>\"",
                    "  s3_bucket_name                = \"<review-safe-log-bucket>\"",
                    "  include_global_service_events = true",
                    "  is_multi_region_trail         = true",
                    "  enable_logging                = true",
                    "}",
                ],
                "Draft would enable reviewed CloudTrail coverage after validation.",
                "Rollback may reduce audit coverage. Manual security review is required before disabling or deleting any trail.",
                rollback_uncertain=True,
            )
        if provider == CloudProvider.aws and self._has_any(text_blob, ["kms", "encryption", "unencrypted", "rotation"]):
            return self._spec(
                source,
                "aws_kms_encryption_review",
                RemediationRiskLevel.medium,
                RemediationArtifactType.documentation_only,
                f"Draft KMS/encryption remediation review for {resource_ref}.",
                "Expected impact: improve encryption posture after future validation. Verification should confirm encryption settings and refreshed evidence.",
                [
                    "Documentation-only draft.",
                    "Review resource encryption settings, key ownership, rotation requirements, and service compatibility before proposing infrastructure changes.",
                ],
                "Documents encryption review steps; no resource mutation.",
                "Rollback depends on the future approved encryption change and must be documented during validation.",
                rollback_uncertain=True,
            )
        if provider == CloudProvider.aws and self._has_any(
            text_blob,
            ["iam", "admin", "permission", "policy", "privilege", "overpermission", "mfa"],
        ):
            return self._iam_review_spec(source, "aws_iam_least_privilege_review")

        if provider == CloudProvider.github and (
            ("branch" in text_blob and "protection" in text_blob)
            or self._has_any(text_blob, ["required review", "status check"])
        ):
            return self._spec(
                source,
                "github_branch_protection_draft",
                RemediationRiskLevel.medium,
                RemediationArtifactType.github_pr_patch_draft,
                f"Draft GitHub branch protection remediation plan for {resource_ref}.",
                "Expected impact: strengthen repository change controls after future validation. Verification should confirm branch protection settings and refreshed GitHub findings.",
                [
                    "Settings draft only; no GitHub API mutation or pull request creation.",
                    "Target branch: <review-required-branch>",
                    "Require pull request reviews: true",
                    "Require status checks: true",
                    "Restrict force pushes: true",
                    "Restrict deletions: true",
                ],
                "Draft settings change for branch protection review.",
                "Restore previous branch protection settings if known; otherwise require repository admin review.",
                rollback_uncertain=True,
            )
        if provider == CloudProvider.github and self._has_any(text_blob, ["actions", "workflow"]) and self._has_any(
            text_blob,
            ["permission", "write-all"],
        ):
            return self._spec(
                source,
                "github_actions_permissions_patch",
                RemediationRiskLevel.high if self._severity(finding) in {"high", "critical"} else RemediationRiskLevel.medium,
                RemediationArtifactType.github_pr_patch_draft,
                f"Draft GitHub Actions permissions hardening plan for {resource_ref}.",
                "Expected impact: reduce default workflow token permissions after future validation. Verification should inspect workflow permissions and refreshed GitHub findings.",
                [
                    "YAML patch draft only; no PR creation.",
                    "--- before",
                    "permissions: write-all",
                    "+++ after",
                    "permissions:",
                    "  contents: read",
                    "  pull-requests: read",
                ],
                "Draft YAML permissions patch for future review.",
                "Restore prior workflow permissions only after repository owner review.",
                rollback_uncertain=True,
            )
        if provider == CloudProvider.github and self._has_any(text_blob, ["secret", "token", "credential", "leak"]):
            return self._spec(
                source,
                "github_secret_rotation_recommendation",
                RemediationRiskLevel.high,
                RemediationArtifactType.documentation_only,
                f"Draft GitHub secret exposure response plan for {resource_ref}.",
                "Expected impact: reduce leaked credential risk after human-led rotation/revocation. Verification should confirm alert state, rotation evidence, and no secret value exposure.",
                [
                    "Documentation-only draft.",
                    "Rotate the affected credential in its owning system.",
                    "Revoke the exposed token or key.",
                    "Audit recent usage and update dependent systems through approved secret management.",
                    "Confirm GitHub alert state after rotation.",
                ],
                "Documents credential rotation and revocation workflow without exposing the secret.",
                "Rollback for secret rotation is manual and should not restore a compromised credential. Use a newly issued credential if rollback is required.",
                rollback_uncertain=True,
            )

        if provider == CloudProvider.gcp and self._has_any(text_blob, ["storage", "bucket"]) and self._has_any(
            text_blob,
            ["public", "allusers", "allauthenticatedusers"],
        ):
            return self._spec(
                source,
                "gcp_storage_public_access_review",
                RemediationRiskLevel.high,
                RemediationArtifactType.terraform_plan_draft,
                f"Draft GCP storage public-access remediation plan for {resource_ref}.",
                "Expected impact: restrict public bucket access after future validation. Verification should refresh GCP findings and mapped compliance evidence.",
                [
                    "# Terraform/gcloud-equivalent draft only; do not execute from AuthClaw Phase 2.",
                    f"# Resource: {resource_ref}",
                    'resource "google_storage_bucket_iam_binding" "reviewed_public_binding" {',
                    "  bucket = \"<review-safe-bucket-name>\"",
                    "  role   = \"roles/storage.objectViewer\"",
                    "  members = []",
                    "}",
                ],
                "Draft would remove reviewed public storage bucket members after validation.",
                "Restore previous IAM binding only if it was intentionally public and approved by the data owner.",
                rollback_uncertain=True,
            )
        if provider == CloudProvider.gcp and self._has_any(
            text_blob,
            ["iam", "owner", "allusers", "binding", "privilege"],
        ):
            return self._iam_review_spec(source, "gcp_iam_binding_reduction_review")

        return self._manual_template(source, "unknown_finding_manual_review")

    def _gap_template(self, source: SourceContext) -> TemplateSpec:
        gap = source.gap
        assert gap is not None
        gap_type = gap.gap_type.value if hasattr(gap.gap_type, "value") else str(gap.gap_type)
        severity = gap.severity.value if hasattr(gap.severity, "value") else str(gap.severity)
        risk = {
            ComplianceGapSeverity.critical.value: RemediationRiskLevel.critical,
            ComplianceGapSeverity.high.value: RemediationRiskLevel.high,
            ComplianceGapSeverity.medium.value: RemediationRiskLevel.medium,
            ComplianceGapSeverity.low.value: RemediationRiskLevel.low,
        }.get(severity, RemediationRiskLevel.medium)
        if gap.gap_type == ComplianceGapType.critical_open_risk:
            risk = RemediationRiskLevel.critical
        elif gap.gap_type in {ComplianceGapType.needs_review, ComplianceGapType.low_confidence_mapping}:
            risk = max_risk(risk, RemediationRiskLevel.medium)

        return self._spec(
            source,
            f"compliance_gap_{gap_type}",
            risk,
            RemediationArtifactType.documentation_only,
            f"Draft remediation review for compliance gap {gap_type}.",
            "Expected impact: improve evidence-supported posture after reviewed remediation. Verification should refresh evidence, rerun assessment, and confirm gap state.",
            [
                "Documentation-only compliance gap remediation draft.",
                f"Gap type: {sanitize_text(gap_type)}",
                f"Gap reason: {sanitize_text(gap.reason)}",
                "Review mapped finding, evidence freshness, and control ownership before proposing provider-specific changes.",
            ],
            "Documents compliance gap review steps; no provider mutation.",
            "Rollback depends on the future provider-specific remediation and must be documented during validation.",
            rollback_uncertain=True,
        )

    def _iam_review_spec(self, source: SourceContext, template_key: str) -> TemplateSpec:
        resource_ref = self._resource_ref(source)
        return self._spec(
            source,
            template_key,
            RemediationRiskLevel.critical,
            RemediationArtifactType.iam_policy_diff,
            f"Draft IAM least-privilege review plan for {resource_ref}.",
            "Expected impact: reduce privilege exposure only after careful validation and approval. Verification should confirm effective permissions, application impact, and refreshed findings.",
            [
                "IAM diff draft only; no automatic permission removal.",
                "--- current policy",
                "<review current effective permissions>",
                "+++ proposed direction",
                "<remove only explicitly validated excessive permissions>",
                "Manual owner review is required before any IAM change.",
            ],
            "Draft least-privilege review diff; no permission removal is executed.",
            "Rollback requires restoring the prior IAM policy or binding from reviewed change history. Manual review required.",
            rollback_uncertain=True,
        )

    def _manual_template(self, source: SourceContext, template_key: str) -> TemplateSpec:
        resource_ref = self._resource_ref(source)
        return self._spec(
            source,
            template_key,
            self._fallback_risk(source),
            RemediationArtifactType.documentation_only,
            f"Draft manual remediation review for {resource_ref}.",
            "Expected impact: create a safe review path. Verification should refresh the source finding/gap after any future approved action.",
            [
                "Documentation-only manual review draft.",
                "No deterministic provider remediation template matched this source.",
                "A human must review the source, expected impact, rollback path, and verification steps before future validation.",
            ],
            "Manual review draft; no executable artifact.",
            "Manual rollback plan required once a concrete remediation is selected.",
            rollback_uncertain=True,
        )

    def _spec(
        self,
        source: SourceContext,
        template_key: str,
        risk_level: RemediationRiskLevel,
        artifact_type: RemediationArtifactType,
        summary: str,
        expected_impact: str,
        artifact_lines: list[str],
        diff_summary: str,
        rollback_steps: str,
        *,
        rollback_uncertain: bool,
    ) -> TemplateSpec:
        source_text = self._source_text(source)
        secrets_found = collect_secret_values(source_text)
        suspicious = sanitize_text(source_text, secrets_found) != " ".join(str(source_text).split())
        flags = {
            "template_key": template_key,
            "source_type": source.source_type,
            "non_executing": True,
            "requires_future_policy_validation": True,
            "requires_future_human_approval": True,
            "rollback_uncertain": rollback_uncertain,
            "suspicious_source_text_redacted": suspicious,
        }
        content = "\n".join([NON_EXECUTING_NOTICE, "", *artifact_lines])
        return TemplateSpec(
            template_key=template_key,
            risk_level=risk_level,
            artifact_type=artifact_type,
            summary=sanitize_text(summary, secrets_found),
            expected_impact=sanitize_text(expected_impact, secrets_found),
            artifact_content=sanitize_text(content, secrets_found),
            diff_summary=sanitize_text(diff_summary, secrets_found),
            rollback_steps=sanitize_text(rollback_steps, secrets_found),
            rollback_uncertain=rollback_uncertain,
            risk_flags=sanitize_json(flags),
        )

    async def _emit_generation_events(
        self,
        source: SourceContext,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        rollback: RemediationRollbackPlan,
        spec: TemplateSpec,
    ) -> None:
        await self._emit(
            RemediationPlanGeneratedEvent(
                tenant_id=plan.tenant_id,
                plan_id=plan.id,
                source_type=source.source_type,
                source_id=source.source_id,
                risk_level=plan.risk_level.value,
                artifact_count=1,
            )
        )
        await self._emit(
            RemediationArtifactDraftedEvent(
                tenant_id=plan.tenant_id,
                plan_id=plan.id,
                artifact_id=artifact.id,
                source_type=source.source_type,
                source_id=source.source_id,
                artifact_type=artifact.artifact_type.value,
                artifact_hash=artifact.artifact_hash,
                risk_level=plan.risk_level.value,
            )
        )
        await self._emit(
            RemediationRollbackPlanCreatedEvent(
                tenant_id=plan.tenant_id,
                plan_id=plan.id,
                source_type=source.source_type,
                source_id=source.source_id,
                risk_level=rollback.risk_level.value,
                rollback_uncertain=spec.rollback_uncertain,
            )
        )

    async def _emit(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish remediation generation event %s: %s", event.event_type, exc)

    def _has_any(self, text: str, terms: list[str]) -> bool:
        return any(term.lower() in text for term in terms)

    def _severity(self, finding: SecurityFinding) -> str:
        return finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

    def _fallback_risk(self, source: SourceContext) -> RemediationRiskLevel:
        if source.finding is not None:
            severity = self._severity(source.finding)
            return {
                FindingSeverity.critical.value: RemediationRiskLevel.critical,
                FindingSeverity.high.value: RemediationRiskLevel.high,
                FindingSeverity.medium.value: RemediationRiskLevel.medium,
                FindingSeverity.low.value: RemediationRiskLevel.low,
            }.get(severity, RemediationRiskLevel.medium)
        if source.gap is not None:
            severity = source.gap.severity.value if hasattr(source.gap.severity, "value") else str(source.gap.severity)
            return {
                ComplianceGapSeverity.critical.value: RemediationRiskLevel.critical,
                ComplianceGapSeverity.high.value: RemediationRiskLevel.high,
                ComplianceGapSeverity.medium.value: RemediationRiskLevel.medium,
                ComplianceGapSeverity.low.value: RemediationRiskLevel.low,
            }.get(severity, RemediationRiskLevel.medium)
        return RemediationRiskLevel.medium

    def _resource_ref(self, source: SourceContext) -> str:
        if source.finding is not None:
            return sanitize_text(source.finding.resource_id)
        if source.gap is not None:
            return f"gap:{source.gap.id}"
        return f"{source.source_type}:{source.source_id}"

    def _source_text(self, source: SourceContext) -> str:
        if source.finding is not None:
            return " ".join(
                [
                    str(source.finding.title or ""),
                    str(source.finding.description or ""),
                    str(source.finding.remediation_instructions or ""),
                    str(source.finding.resource_id or ""),
                ]
            )
        if source.gap is not None:
            return " ".join([str(source.gap.gap_type), str(source.gap.severity), str(source.gap.reason)])
        return ""

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


def source_tenant_id(source: SourceContext) -> uuid.UUID:
    if source.integration is not None:
        return source.integration.tenant_id
    if source.gap is not None:
        return source.gap.tenant_id
    raise BadRequestException(detail="Source has no tenant binding")


def sanitize_json(value: Any) -> Any:
    secret_values = collect_secret_values(value)
    if isinstance(value, dict):
        return {sanitize_text(key, secret_values): sanitize_json(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value, secret_values)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return sanitize_text(value, secret_values)


def max_risk(left: RemediationRiskLevel, right: RemediationRiskLevel) -> RemediationRiskLevel:
    order = {
        RemediationRiskLevel.low: 1,
        RemediationRiskLevel.medium: 2,
        RemediationRiskLevel.high: 3,
        RemediationRiskLevel.critical: 4,
    }
    return left if order[left] >= order[right] else right
