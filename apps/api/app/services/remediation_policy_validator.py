from __future__ import annotations

import hashlib
import inspect
import json
import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import NotFoundException
from app.models.remediation import (
    RemediationApprovalLevel,
    RemediationArtifact,
    RemediationArtifactType,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRollbackPlan,
)
from app.schemas.events import (
    RemediationPlanValidatedEvent,
    RemediationPolicyCheckFailedEvent,
    RemediationPolicyWarningEvent,
)
from app.services.api_safety import sanitize_text
from app.services.remediation_state_machine import (
    REMEDIATION_EVENTS_TOPIC,
    RemediationStateMachine,
    artifact_hash,
)

logger = logging.getLogger(__name__)

VALIDATOR_VERSION = "sprint4-phase3-v1"

APPROVAL_ORDER = {
    RemediationApprovalLevel.operator: 1,
    RemediationApprovalLevel.admin: 2,
    RemediationApprovalLevel.owner: 3,
    RemediationApprovalLevel.security_admin: 4,
}

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(r"\bA(?:KI|SI)A[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"\b(?:aws_secret_access_key|aws_session_token|github_token|private_key|"
        r"client_secret|access_token|refresh_token|id_token|password|api[_-]?key|token)\s*"
        r"[:=]\s*['\"]?[^'\"\s,;]+",
        re.I,
    ),
    re.compile(r"\b(?:raw_provider_payload|raw_payload|raw_finding_data)\b", re.I),
]

BLOCKING_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("terraform_apply", re.compile(r"\bterraform\s+apply\b", re.I), "Artifact includes terraform apply."),
    ("terraform_destroy", re.compile(r"\bterraform\s+destroy\b", re.I), "Artifact includes terraform destroy."),
    ("force_destroy", re.compile(r"\bforce_destroy\s*=\s*true\b", re.I), "Artifact enables force_destroy."),
    ("shell_wrapper", re.compile(r"(^|\n)\s*#!.*\b(?:bash|sh|pwsh|powershell)\b|\b(?:bash|sh|pwsh|powershell|cmd\.exe)\s+-c\b", re.I), "Artifact includes shell execution wrapper."),
    ("subprocess_execution", re.compile(r"\bsubprocess\b|\bos\.system\s*\(", re.I), "Artifact includes process execution code."),
    ("pipe_to_shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b", re.I), "Artifact pipes downloaded content to shell."),
    ("aws_configure", re.compile(r"\baws\s+configure\b", re.I), "Artifact includes aws configure."),
    ("credential_export", re.compile(r"\b(?:export|set)\s+AWS_[A-Z0-9_]+|\$env:AWS_[A-Z0-9_]+", re.I), "Artifact exports cloud credentials."),
    ("delete_bucket", re.compile(r"\bdelete[-_\s]bucket\b|\bdelete\s+(?:s3\s+)?bucket\b", re.I), "Artifact requests bucket deletion."),
    ("delete_repository", re.compile(r"\bdelete\s+(?:github\s+)?(?:repository|repo)\b", re.I), "Artifact requests repository deletion."),
    ("privilege_escalation", re.compile(r"\b(?:administratoraccess|grant\s+admin|add\s+admin|iam:passrole|iam:createpolicyversion|sts:assumerole)\b", re.I), "Artifact includes privilege escalation pattern."),
    ("public_access_enablement", re.compile(r"\b(?:public-read|allusers|allauthenticatedusers)\b|block_public_[a-z_]+\s*=\s*false|restrict_public_buckets\s*=\s*false", re.I), "Artifact appears to enable public access."),
]


@dataclass(frozen=True)
class PolicyValidationResult:
    plan: RemediationPlan
    artifact: RemediationArtifact
    policy_check: RemediationPolicyCheck
    warnings: list[dict[str, str]]
    blocking_reasons: list[dict[str, str]]
    required_approval_level: RemediationApprovalLevel


class RemediationPolicyValidator:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer
        self.state_machine = RemediationStateMachine(db, event_producer=event_producer)

    async def validate_plan(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        actor_id: uuid.UUID | str | None = None,
    ) -> PolicyValidationResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, self._uuid(plan_id))
        artifact = await self._latest_artifact(plan)
        if artifact is None:
            raise NotFoundException(detail="Remediation artifact not found for plan")
        return await self._validate(plan, artifact, actor_id=actor_id)

    async def validate_artifact(
        self,
        tenant_id: uuid.UUID | str,
        artifact_id: uuid.UUID | str,
        actor_id: uuid.UUID | str | None = None,
    ) -> PolicyValidationResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        artifact = await self._artifact(tenant_uuid, self._uuid(artifact_id))
        plan = await self._plan(tenant_uuid, artifact.plan_id)
        return await self._validate(plan, artifact, actor_id=actor_id)

    def classify_action_risk(
        self,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
    ) -> RemediationApprovalLevel:
        content = self._normalized_content(artifact)
        template_key = str((artifact.risk_flags or {}).get("template_key", "")).lower()
        level = RemediationApprovalLevel.operator

        if artifact.artifact_type == RemediationArtifactType.documentation_only:
            level = self._max_approval(level, RemediationApprovalLevel.operator)
            if "manual" in template_key or "unknown" in template_key:
                level = self._max_approval(level, RemediationApprovalLevel.admin)
            if "secret" in template_key or "rotation" in template_key:
                level = self._max_approval(level, RemediationApprovalLevel.owner)
        elif artifact.artifact_type in {
            RemediationArtifactType.terraform_plan_draft,
            RemediationArtifactType.github_pr_patch_draft,
        }:
            level = self._max_approval(level, RemediationApprovalLevel.owner)
        elif artifact.artifact_type == RemediationArtifactType.iam_policy_diff:
            level = self._max_approval(level, RemediationApprovalLevel.security_admin)
        elif artifact.artifact_type == RemediationArtifactType.aws_cli_command_draft:
            level = self._max_approval(level, RemediationApprovalLevel.security_admin)

        if plan.risk_level and plan.risk_level.value in {"high", "critical"}:
            level = self._max_approval(level, RemediationApprovalLevel.owner)
        if self._contains_iam(content, template_key):
            level = self._max_approval(level, RemediationApprovalLevel.security_admin)
        if self._contains_public_access_change(content, template_key):
            level = self._max_approval(level, RemediationApprovalLevel.owner)
        if self._contains_destructive_or_escalating(content):
            level = self._max_approval(level, RemediationApprovalLevel.security_admin)
        return level

    def compute_policy_check_hash(
        self,
        *,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        artifact_hash_value: str,
        warnings: list[dict[str, str]],
        blocking_reasons: list[dict[str, str]],
        required_approval_level: RemediationApprovalLevel | str,
    ) -> str:
        payload = {
            "tenant_id": str(tenant_id),
            "plan_id": str(plan_id),
            "artifact_hash": str(artifact_hash_value),
            "warnings": self._normalized_findings(warnings),
            "blocking_reasons": self._normalized_findings(blocking_reasons),
            "required_approval_level": self._approval_level(required_approval_level).value,
            "validator_version": VALIDATOR_VERSION,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    async def get_latest_policy_check(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
    ) -> RemediationPolicyCheck | None:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        return (
            await self.db.execute(
                select(RemediationPolicyCheck)
                .where(RemediationPolicyCheck.tenant_id == tenant_uuid, RemediationPolicyCheck.plan_id == self._uuid(plan_id))
                .order_by(desc(RemediationPolicyCheck.created_at))
                .limit(1)
            )
        ).scalars().first()

    async def _validate(
        self,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        actor_id: uuid.UUID | str | None = None,
    ) -> PolicyValidationResult:
        warnings: list[dict[str, str]] = []
        blocking_reasons: list[dict[str, str]] = []
        await self._collect_validation_findings(plan, artifact, warnings, blocking_reasons)
        approval_level = self.classify_action_risk(plan, artifact)
        if blocking_reasons:
            approval_level = self._max_approval(approval_level, RemediationApprovalLevel.security_admin)

        check_hash = self.compute_policy_check_hash(
            tenant_id=plan.tenant_id,
            plan_id=plan.id,
            artifact_hash_value=artifact.artifact_hash,
            warnings=warnings,
            blocking_reasons=blocking_reasons,
            required_approval_level=approval_level,
        )
        existing = await self._policy_check_by_hash(plan, check_hash)
        if existing is None:
            existing = RemediationPolicyCheck(
                tenant_id=plan.tenant_id,
                plan_id=plan.id,
                artifact_id=artifact.id,
                passed=not blocking_reasons,
                warnings=self._safe_findings(warnings),
                blocking_reasons=self._safe_findings(blocking_reasons),
                required_approval_level=approval_level,
                policy_check_hash=check_hash,
            )
            self.db.add(existing)
            await self.db.flush()

        if existing.passed and plan.status == RemediationPlanStatus.plan_drafted:
            await self.state_machine.transition_plan(
                plan.tenant_id,
                plan.id,
                RemediationPlanStatus.plan_validated,
                actor_id=actor_id,
                reason="Remediation policy validation passed.",
            )
        await self._emit_validation_events(plan, existing)
        return PolicyValidationResult(
            plan=plan,
            artifact=artifact,
            policy_check=existing,
            warnings=list(existing.warnings),
            blocking_reasons=list(existing.blocking_reasons),
            required_approval_level=existing.required_approval_level,
        )

    async def _collect_validation_findings(
        self,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        warnings: list[dict[str, str]],
        blocking_reasons: list[dict[str, str]],
    ) -> None:
        content = self._normalized_content(artifact)
        template_key = str((artifact.risk_flags or {}).get("template_key", "")).lower()

        rollback = await self._rollback(plan)
        if rollback is None:
            blocking_reasons.append(self._finding("missing_rollback_plan", "Validation requires a rollback plan."))

        expected_hash = artifact_hash(artifact.artifact_type, artifact.content_redacted)
        if artifact.artifact_hash != expected_hash:
            blocking_reasons.append(self._finding("artifact_hash_mismatch", "Artifact hash does not match redacted content."))

        if plan.provider and str(plan.provider).lower() not in {"aws", "github", "gcp"}:
            blocking_reasons.append(self._finding("unsupported_provider", "Provider is not supported by Phase 3 validation."))
        if artifact.artifact_type == RemediationArtifactType.aws_cli_command_draft:
            blocking_reasons.append(self._finding("unsupported_action_type", "AWS CLI command drafts are not supported by Phase 3 validation."))

        if any(pattern.search(artifact.content_redacted) for pattern in SECRET_PATTERNS):
            blocking_reasons.append(self._finding("secret_like_content", "Artifact contains secret-like or raw-payload content."))

        for code, pattern, message in BLOCKING_RULES:
            if pattern.search(content):
                blocking_reasons.append(self._finding(code, message))

        if self._contains_iam_wildcard(content):
            blocking_reasons.append(self._finding("iam_wildcard", "IAM wildcard action/resource requires a future explicit critical approval path."))

        if self._contains_iam(content, template_key):
            warnings.append(self._finding("iam_review_required", "IAM permission changes require least-privilege review."))
        if "remove" in content and self._contains_iam(content, template_key):
            warnings.append(self._finding("iam_permission_reduction", "IAM permission reduction may affect workloads."))
        if self._contains_public_access_change(content, template_key):
            warnings.append(self._finding("public_access_change", "Public access control changes require owner review."))
        if "cloudtrail" in content or "enable_logging" in content or "audit logging" in content:
            warnings.append(self._finding("logging_configuration_change", "Logging configuration changes require verification."))
        if "kms" in content or "encryption" in content or "rotation" in content:
            warnings.append(self._finding("encryption_configuration_change", "Encryption configuration changes require compatibility review."))
        if "branch protection" in content or "required review" in content or "status checks" in content:
            warnings.append(self._finding("github_branch_protection_change", "GitHub branch protection changes require repository owner review."))
        if "google_storage_bucket_iam" in content or "gcp_iam" in template_key or "gcp iam" in content:
            warnings.append(self._finding("gcp_iam_binding_change", "GCP IAM binding changes require owner review."))
        if bool((artifact.risk_flags or {}).get("rollback_uncertain")):
            warnings.append(self._finding("rollback_uncertain", "Rollback path is uncertain and needs human review."))
        if "manual" in template_key or "unknown" in template_key or "human must review" in content:
            warnings.append(self._finding("manual_review_required", "Manual remediation review is required."))
        if "low_confidence" in template_key or "low confidence" in content:
            warnings.append(self._finding("low_confidence_source_mapping", "Source mapping is low confidence."))
        if artifact.artifact_type == RemediationArtifactType.documentation_only and "documentation-only" not in content:
            warnings.append(self._finding("unknown_artifact_syntax", "Documentation artifact syntax is not recognized."))

    async def _emit_validation_events(self, plan: RemediationPlan, check: RemediationPolicyCheck) -> None:
        event_cls = RemediationPlanValidatedEvent if check.passed else RemediationPolicyCheckFailedEvent
        await self._emit(
            event_cls(
                tenant_id=plan.tenant_id,
                plan_id=plan.id,
                policy_check_id=check.id,
                passed=check.passed,
                warning_count=len(check.warnings or []),
                blocking_reason_count=len(check.blocking_reasons or []),
                required_approval_level=check.required_approval_level.value,
                policy_check_hash=check.policy_check_hash,
                status=plan.status.value,
            )
        )
        if check.warnings:
            await self._emit(
                RemediationPolicyWarningEvent(
                    tenant_id=plan.tenant_id,
                    plan_id=plan.id,
                    policy_check_id=check.id,
                    passed=check.passed,
                    warning_count=len(check.warnings or []),
                    blocking_reason_count=len(check.blocking_reasons or []),
                    required_approval_level=check.required_approval_level.value,
                    policy_check_hash=check.policy_check_hash,
                    status=plan.status.value,
                )
            )

    async def _plan(self, tenant_id: uuid.UUID, plan_id: uuid.UUID) -> RemediationPlan:
        plan = (
            await self.db.execute(
                select(RemediationPlan).where(RemediationPlan.tenant_id == tenant_id, RemediationPlan.id == plan_id)
            )
        ).scalars().first()
        if plan is None:
            raise NotFoundException(detail="Remediation plan not found")
        return plan

    async def _latest_artifact(self, plan: RemediationPlan) -> RemediationArtifact | None:
        return (
            await self.db.execute(
                select(RemediationArtifact)
                .where(RemediationArtifact.tenant_id == plan.tenant_id, RemediationArtifact.plan_id == plan.id)
                .order_by(desc(RemediationArtifact.created_at))
                .limit(1)
            )
        ).scalars().first()

    async def _artifact(self, tenant_id: uuid.UUID, artifact_id: uuid.UUID) -> RemediationArtifact:
        artifact = (
            await self.db.execute(
                select(RemediationArtifact).where(
                    RemediationArtifact.tenant_id == tenant_id,
                    RemediationArtifact.id == artifact_id,
                )
            )
        ).scalars().first()
        if artifact is None:
            raise NotFoundException(detail="Remediation artifact not found")
        return artifact

    async def _rollback(self, plan: RemediationPlan) -> RemediationRollbackPlan | None:
        return (
            await self.db.execute(
                select(RemediationRollbackPlan).where(
                    RemediationRollbackPlan.tenant_id == plan.tenant_id,
                    RemediationRollbackPlan.plan_id == plan.id,
                )
            )
        ).scalars().first()

    async def _policy_check_by_hash(self, plan: RemediationPlan, check_hash: str) -> RemediationPolicyCheck | None:
        return (
            await self.db.execute(
                select(RemediationPolicyCheck).where(
                    RemediationPolicyCheck.tenant_id == plan.tenant_id,
                    RemediationPolicyCheck.plan_id == plan.id,
                    RemediationPolicyCheck.policy_check_hash == check_hash,
                )
            )
        ).scalars().first()

    async def _emit(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish remediation validation event %s: %s", event.event_type, exc)

    def _finding(self, code: str, message: str) -> dict[str, str]:
        return {"code": sanitize_text(code), "message": sanitize_text(message)}

    def _safe_findings(self, findings: list[dict[str, str]]) -> list[dict[str, str]]:
        return [self._finding(str(item.get("code", "")), str(item.get("message", ""))) for item in findings]

    def _normalized_findings(self, findings: list[dict[str, str]]) -> list[dict[str, str]]:
        safe = self._safe_findings(findings)
        return sorted(safe, key=lambda item: json.dumps(item, sort_keys=True))

    def _normalized_content(self, artifact: RemediationArtifact) -> str:
        return " ".join(str(artifact.content_redacted or "").split()).lower()

    def _contains_iam(self, content: str, template_key: str) -> bool:
        return "iam" in content or "least-privilege" in content or "policy" in content or "iam" in template_key

    def _contains_iam_wildcard(self, content: str) -> bool:
        return bool(
            re.search(r'["\'](?:action|resource)["\']\s*:\s*["\']\*["\']', content, re.I)
            or re.search(r"\b(?:action|resource)\s*=\s*\[\s*['\"]\*['\"]\s*\]", content, re.I)
            or re.search(r"\b(?:action|resource)\s*=\s*['\"]\*['\"]", content, re.I)
        )

    def _contains_public_access_change(self, content: str, template_key: str) -> bool:
        return (
            "public access" in content
            or "public_access" in content
            or "restrict_public" in content
            or "allusers" in content
            or "public" in template_key
        )

    def _contains_destructive_or_escalating(self, content: str) -> bool:
        return any(pattern.search(content) for code, pattern, _ in BLOCKING_RULES if code in {
            "terraform_destroy",
            "force_destroy",
            "delete_bucket",
            "delete_repository",
            "privilege_escalation",
        })

    def _max_approval(
        self,
        left: RemediationApprovalLevel,
        right: RemediationApprovalLevel,
    ) -> RemediationApprovalLevel:
        return left if APPROVAL_ORDER[left] >= APPROVAL_ORDER[right] else right

    def _approval_level(self, value: RemediationApprovalLevel | str) -> RemediationApprovalLevel:
        if isinstance(value, RemediationApprovalLevel):
            return value
        return RemediationApprovalLevel(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))
