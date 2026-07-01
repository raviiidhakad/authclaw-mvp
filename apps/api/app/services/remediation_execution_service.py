from __future__ import annotations

import inspect
import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException, NotFoundException
from app.core.rate_limit.tenant_limiter import TenantPlanLimiter, rate_limit_exception, tenant_plan_limiter
from app.models.remediation import (
    RemediationApproval,
    RemediationArtifact,
    RemediationArtifactType,
    RemediationDryRunResult,
    RemediationDryRunStatus,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
    RemediationRollbackPlan,
    RemediationVerificationResult,
    RemediationVerificationStatus,
)
from app.schemas.events import (
    RemediationExecutionBlockedEvent,
    RemediationExecutionFailedEvent,
    RemediationExecutionQueuedEvent,
    RemediationExecutionStartedEvent,
    RemediationExecutionSucceededEvent,
    RemediationRollbackRequiredEvent,
    RemediationVerifiedEvent,
)
from app.services.api_safety import sanitize_text
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_sandbox_service import RemediationSandboxService
from app.services.remediation_state_machine import REMEDIATION_EVENTS_TOPIC, RemediationStateMachine, utcnow
from app.services.worker_token_service import WorkerTokenScope, WorkerTokenService

logger = logging.getLogger(__name__)

EXECUTION_ENABLED_CONTEXT = {"execution_enabled": True}
SIMULATED_RISK_ALLOWED = {RemediationRiskLevel.low, RemediationRiskLevel.medium, RemediationRiskLevel.high, RemediationRiskLevel.critical}
LOW_RISK_ALLOWED = {RemediationRiskLevel.low, RemediationRiskLevel.medium}

MUTATION_OR_PROCESS_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("terraform_apply", re.compile(r"\bterraform\s+apply\b|\bapply\s+-auto-approve\b", re.I), "Terraform apply is blocked."),
    ("terraform_destroy", re.compile(r"\bterraform\s+destroy\b|\bdestroy\b", re.I), "Terraform destroy is blocked."),
    ("aws_mutation", re.compile(r"\baws\s+\w+\s+(?:create|delete|put|update|modify|attach|detach|authorize|revoke|terminate|run)-", re.I), "AWS CLI mutation is blocked."),
    ("github_mutation", re.compile(r"\bgh\s+pr\s+create\b|\bgit\s+push\b|\bapi\.github\.com\b", re.I), "GitHub mutation is blocked."),
    ("gcp_mutation", re.compile(r"\bgcloud\s+.*\b(?:create|delete|update|set-iam-policy)\b", re.I), "GCP mutation is blocked."),
    ("shell_wrapper", re.compile(r"(^|\n)\s*#!.*\b(?:bash|sh|pwsh|powershell)\b|\b(?:bash|sh|pwsh|powershell|cmd\.exe)\s+-c\b", re.I), "Shell wrappers are blocked."),
    ("process_execution", re.compile(r"\b" + "sub" + r"process\b|\bos\.system\s*\(|\bexec\s*\(|\beval\s*\(", re.I), "Process execution code is blocked."),
    ("pipe_to_shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b", re.I), "Pipe-to-shell patterns are blocked."),
)


@dataclass(frozen=True)
class ExecutionEligibility:
    adapter_type: str
    simulated: bool
    dry_run: RemediationDryRunResult


@dataclass(frozen=True)
class ExecutionOutcome:
    success: bool
    adapter_type: str
    simulated: bool
    verification_summary: str
    rollback_required: bool = False
    reason_category: str | None = None


class ExecutionAdapter:
    adapter_type = "base"
    simulated = False

    def execute(
        self,
        *,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        dry_run: RemediationDryRunResult,
    ) -> ExecutionOutcome:
        raise NotImplementedError


class DocumentationOnlyExecutionAdapter(ExecutionAdapter):
    adapter_type = "documentation_only"

    def execute(
        self,
        *,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        dry_run: RemediationDryRunResult,
    ) -> ExecutionOutcome:
        return ExecutionOutcome(
            success=True,
            adapter_type=self.adapter_type,
            simulated=False,
            verification_summary="Documentation-only remediation acknowledged. No external mutation was attempted.",
        )


class StaticValidationExecutionAdapter(ExecutionAdapter):
    adapter_type = "static_validation"

    def execute(
        self,
        *,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        dry_run: RemediationDryRunResult,
    ) -> ExecutionOutcome:
        return ExecutionOutcome(
            success=True,
            adapter_type=self.adapter_type,
            simulated=False,
            verification_summary="Passed static dry-run validation was recorded as controlled MVP completion. No external mutation was attempted.",
        )


class LocalNoopExecutionAdapter(ExecutionAdapter):
    adapter_type = "local_noop"

    def execute(
        self,
        *,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        dry_run: RemediationDryRunResult,
    ) -> ExecutionOutcome:
        return ExecutionOutcome(
            success=True,
            adapter_type=self.adapter_type,
            simulated=False,
            verification_summary="Local no-op execution completed. Only AuthClaw job and verification rows were updated.",
        )


class SimulatedProviderExecutionAdapter(ExecutionAdapter):
    adapter_type = "simulated_provider"
    simulated = True

    def execute(
        self,
        *,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        dry_run: RemediationDryRunResult,
    ) -> ExecutionOutcome:
        risk_flags = artifact.risk_flags or {}
        should_fail = bool(risk_flags.get("simulate_execution_failure") or risk_flags.get("simulated_failure"))
        if should_fail:
            return ExecutionOutcome(
                success=False,
                adapter_type=self.adapter_type,
                simulated=True,
                verification_summary="Simulated provider execution failed by configured test input. No external provider was called.",
                rollback_required=True,
                reason_category="simulated_failure",
            )
        return ExecutionOutcome(
            success=True,
            adapter_type=self.adapter_type,
            simulated=True,
            verification_summary="Simulated provider execution succeeded. No external provider was called and no resources were mutated.",
        )


ADAPTERS = {
    DocumentationOnlyExecutionAdapter.adapter_type: DocumentationOnlyExecutionAdapter(),
    StaticValidationExecutionAdapter.adapter_type: StaticValidationExecutionAdapter(),
    LocalNoopExecutionAdapter.adapter_type: LocalNoopExecutionAdapter(),
    SimulatedProviderExecutionAdapter.adapter_type: SimulatedProviderExecutionAdapter(),
}


class RemediationExecutionService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        event_producer=default_event_producer,
        sandbox_service: RemediationSandboxService | None = None,
        worker_token_service: WorkerTokenService | None = None,
        rate_limiter: TenantPlanLimiter | None = None,
    ) -> None:
        self.db = db
        self.event_producer = event_producer
        self.sandbox_service = sandbox_service or RemediationSandboxService()
        self.approval_service = RemediationApprovalService(db, event_producer=event_producer)
        self.state_machine = RemediationStateMachine(db, event_producer=event_producer)
        self.worker_token_service = worker_token_service or WorkerTokenService(event_producer=event_producer)
        self.rate_limiter = rate_limiter or tenant_plan_limiter

    async def create_execution_job(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        artifact_id: uuid.UUID | str,
        approval_id: uuid.UUID | str,
        actor_id: uuid.UUID | str | None = None,
    ) -> RemediationExecutionJob:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, self._uuid(plan_id))
        artifact = await self._artifact(tenant_uuid, plan.id, self._uuid(artifact_id))
        approval = await self._approval(tenant_uuid, plan.id, self._uuid(approval_id))
        eligibility = await self._eligibility(tenant_uuid, plan, artifact, approval, consume_approval=False)
        await self.approval_service.verify_approval_for_dry_run(
            tenant_uuid,
            plan.id,
            approval.id,
            actor_id=actor_id,
            execution_action="create_execution_job",
        )

        job = RemediationExecutionJob(
            tenant_id=tenant_uuid,
            plan_id=plan.id,
            approval_id=approval.id,
            dry_run_result_id=eligibility.dry_run.id,
            sandbox_id=eligibility.dry_run.sandbox_id,
            status=RemediationExecutionStatus.queued,
            disabled_reason=f"Controlled Phase 8 execution queued with {eligibility.adapter_type} adapter.",
        )
        self.db.add(job)
        await self.db.flush()
        await self._emit(
            RemediationExecutionQueuedEvent(
                tenant_id=tenant_uuid,
                actor_id=self._uuid(actor_id) if actor_id else None,
                plan_id=plan.id,
                artifact_id=artifact.id,
                job_id=job.id,
                status=job.status.value,
                adapter_type=eligibility.adapter_type,
                simulated=eligibility.simulated,
            )
        )
        return job

    async def execute_job(
        self,
        tenant_id: uuid.UUID | str,
        job_id: uuid.UUID | str,
        *,
        actor_id: uuid.UUID | str | None = None,
    ) -> RemediationVerificationResult | None:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        job = await self._job(tenant_uuid, self._uuid(job_id))
        dry_run = await self._dry_run_by_id(tenant_uuid, job.dry_run_result_id)
        plan = await self._plan(tenant_uuid, job.plan_id)
        artifact = await self._artifact(tenant_uuid, plan.id, dry_run.artifact_id)
        approval = await self._approval(tenant_uuid, plan.id, job.approval_id)
        eligibility = await self._eligibility(tenant_uuid, plan, artifact, approval, consume_approval=False)
        adapter = ADAPTERS[eligibility.adapter_type]

        verification = await self.approval_service.verify_approval_for_controlled_execution_start(
            tenant_uuid,
            plan.id,
            approval.id,
            actor_id=actor_id,
            execution_action="execute_job",
        )
        if verification.artifact_hash != artifact.artifact_hash:
            raise BadRequestException(detail="Approval artifact hash does not match selected artifact")
        if plan.status != RemediationPlanStatus.approved:
            raise BadRequestException(detail="Plan must be approved when controlled execution starts")
        token_scope = self._worker_token_scope(
            tenant_uuid,
            job.id,
            adapter.adapter_type,
            plan=plan,
            actor_id=actor_id,
        )
        issued_worker_token = await self.worker_token_service.issue_token(token_scope)
        await self.worker_token_service.validate_token(issued_worker_token.token, token_scope)

        limit_decision = await self.rate_limiter.acquire_remediation_job(self.db, tenant_uuid)
        if not limit_decision.allowed:
            raise rate_limit_exception(limit_decision)
        try:
            await self.state_machine.transition_plan(
                tenant_uuid,
                plan.id,
                RemediationPlanStatus.queued_for_execution,
                reason="Controlled Phase 8 execution queued.",
                context=EXECUTION_ENABLED_CONTEXT,
            )
            started_at = utcnow()
            job.status = RemediationExecutionStatus.executing
            job.started_at = started_at
            await self.db.flush()
            await self.state_machine.transition_plan(
                tenant_uuid,
                plan.id,
                RemediationPlanStatus.executing,
                reason="Controlled Phase 8 execution started.",
                context=EXECUTION_ENABLED_CONTEXT,
            )
            await self._emit(
                RemediationExecutionStartedEvent(
                    tenant_id=tenant_uuid,
                    plan_id=plan.id,
                    artifact_id=artifact.id,
                    job_id=job.id,
                    status=job.status.value,
                    adapter_type=eligibility.adapter_type,
                    simulated=eligibility.simulated,
                )
            )

            outcome = adapter.execute(plan=plan, artifact=artifact, dry_run=eligibility.dry_run)
            completed_at = utcnow()
            job.completed_at = completed_at
            if outcome.success:
                job.status = RemediationExecutionStatus.succeeded
                await self.db.flush()
                await self.state_machine.transition_plan(
                    tenant_uuid,
                    plan.id,
                    RemediationPlanStatus.succeeded,
                    reason="Controlled Phase 8 execution succeeded.",
                    context=EXECUTION_ENABLED_CONTEXT,
                )
                await self._emit(
                    RemediationExecutionSucceededEvent(
                        tenant_id=tenant_uuid,
                        plan_id=plan.id,
                        artifact_id=artifact.id,
                        job_id=job.id,
                        status=job.status.value,
                        adapter_type=outcome.adapter_type,
                        simulated=outcome.simulated,
                    )
                )
                return await self.verify_execution(tenant_uuid, job.id, outcome=outcome, artifact_id=artifact.id)

            job.status = RemediationExecutionStatus.failed
            await self.db.flush()
            await self.state_machine.transition_plan(
                tenant_uuid,
                plan.id,
                RemediationPlanStatus.failed,
                reason="Controlled Phase 8 execution failed.",
                context=EXECUTION_ENABLED_CONTEXT,
            )
            await self._emit(
                RemediationExecutionFailedEvent(
                    tenant_id=tenant_uuid,
                    plan_id=plan.id,
                    artifact_id=artifact.id,
                    job_id=job.id,
                    status=job.status.value,
                    adapter_type=outcome.adapter_type,
                    simulated=outcome.simulated,
                    reason_category=outcome.reason_category,
                )
            )
            verification_result = await self.verify_execution(tenant_uuid, job.id, outcome=outcome, artifact_id=artifact.id)
            if outcome.rollback_required and await self._rollback_plan_exists(plan):
                job.status = RemediationExecutionStatus.rollback_required
                await self.db.flush()
                await self.state_machine.transition_plan(
                    tenant_uuid,
                    plan.id,
                    RemediationPlanStatus.rollback_required,
                    reason="Rollback required after simulated controlled execution failure.",
                    context=EXECUTION_ENABLED_CONTEXT,
                )
                await self._emit(
                    RemediationRollbackRequiredEvent(
                        tenant_id=tenant_uuid,
                        plan_id=plan.id,
                        artifact_id=artifact.id,
                        job_id=job.id,
                        status=job.status.value,
                        adapter_type=outcome.adapter_type,
                        simulated=outcome.simulated,
                        reason_category=outcome.reason_category,
                    )
                )
            return verification_result
        finally:
            await self.rate_limiter.release_remediation_job(tenant_uuid)

    async def verify_execution(
        self,
        tenant_id: uuid.UUID | str,
        job_id: uuid.UUID | str,
        *,
        outcome: ExecutionOutcome | None = None,
        artifact_id: uuid.UUID | None = None,
    ) -> RemediationVerificationResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        job = await self._job(tenant_uuid, self._uuid(job_id))
        plan = await self._plan(tenant_uuid, job.plan_id)
        dry_run = await self._dry_run_by_id(tenant_uuid, job.dry_run_result_id)
        artifact_uuid = artifact_id or dry_run.artifact_id
        existing = await self._verification_for_job(tenant_uuid, job.id)
        if existing is not None:
            return existing
        success = job.status == RemediationExecutionStatus.succeeded if outcome is None else outcome.success
        summary = (
            outcome.verification_summary
            if outcome is not None
            else "Controlled execution verification recorded from current job state. No external mutation was attempted."
        )
        verification = RemediationVerificationResult(
            tenant_id=tenant_uuid,
            plan_id=plan.id,
            job_id=job.id,
            finding_status_before=None,
            finding_status_after="verified" if success else "unchanged",
            evidence_id=None,
            verified=success,
            verification_summary=sanitize_text(summary),
            status=RemediationVerificationStatus.verified if success else RemediationVerificationStatus.failed,
        )
        self.db.add(verification)
        await self.db.flush()
        if success and plan.status == RemediationPlanStatus.succeeded:
            await self.state_machine.transition_plan(
                tenant_uuid,
                plan.id,
                RemediationPlanStatus.verified,
                reason="Controlled Phase 8 verification completed.",
                context=EXECUTION_ENABLED_CONTEXT,
            )
            await self._emit(
                RemediationVerifiedEvent(
                    tenant_id=tenant_uuid,
                    plan_id=plan.id,
                    artifact_id=artifact_uuid,
                    job_id=job.id,
                    verification_result_id=verification.id,
                    status=verification.status.value,
                    adapter_type=outcome.adapter_type if outcome else "unknown",
                    simulated=outcome.simulated if outcome else False,
                )
            )
        return verification

    async def block_execution(self, tenant_id: uuid.UUID | str, plan_id: uuid.UUID | str, reason: str) -> RemediationExecutionJob:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, self._uuid(plan_id))
        job = RemediationExecutionJob(
            tenant_id=tenant_uuid,
            plan_id=plan.id,
            status=RemediationExecutionStatus.disabled,
            disabled_reason=sanitize_text(reason),
        )
        self.db.add(job)
        await self.db.flush()
        await self._emit(
            RemediationExecutionBlockedEvent(
                tenant_id=tenant_uuid,
                plan_id=plan.id,
                job_id=job.id,
                status=job.status.value,
                disabled_reason=job.disabled_reason,
                reason_category="eligibility_blocked",
            )
        )
        return job

    async def get_execution_job(self, tenant_id: uuid.UUID | str, job_id: uuid.UUID | str) -> RemediationExecutionJob:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        return await self._job(tenant_uuid, self._uuid(job_id))

    async def list_execution_jobs(self, tenant_id: uuid.UUID | str, filters: dict[str, Any] | None = None) -> list[RemediationExecutionJob]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        filters = filters or {}
        query = select(RemediationExecutionJob).where(RemediationExecutionJob.tenant_id == tenant_uuid)
        if filters.get("plan_id"):
            query = query.where(RemediationExecutionJob.plan_id == self._uuid(filters["plan_id"]))
        if filters.get("approval_id"):
            query = query.where(RemediationExecutionJob.approval_id == self._uuid(filters["approval_id"]))
        if filters.get("status"):
            query = query.where(RemediationExecutionJob.status == filters["status"])
        return list((await self.db.execute(query.order_by(desc(RemediationExecutionJob.created_at)))).scalars().all())

    async def get_verification_result(self, tenant_id: uuid.UUID | str, result_id: uuid.UUID | str) -> RemediationVerificationResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        result = (
            await self.db.execute(
                select(RemediationVerificationResult).where(
                    RemediationVerificationResult.tenant_id == tenant_uuid,
                    RemediationVerificationResult.id == self._uuid(result_id),
                )
            )
        ).scalars().first()
        if result is None:
            raise NotFoundException(detail="Remediation verification result not found")
        return result

    async def list_verification_results(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str | None = None,
    ) -> list[RemediationVerificationResult]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        query = select(RemediationVerificationResult).where(RemediationVerificationResult.tenant_id == tenant_uuid)
        if plan_id is not None:
            query = query.where(RemediationVerificationResult.plan_id == self._uuid(plan_id))
        return list((await self.db.execute(query.order_by(desc(RemediationVerificationResult.created_at)))).scalars().all())

    async def _eligibility(
        self,
        tenant_id: uuid.UUID,
        plan: RemediationPlan,
        artifact: RemediationArtifact,
        approval: RemediationApproval,
        *,
        consume_approval: bool,
    ) -> ExecutionEligibility:
        if plan.tenant_id != tenant_id or artifact.tenant_id != tenant_id or approval.tenant_id != tenant_id:
            raise BadRequestException(detail="Tenant mismatch in execution objects")
        if artifact.plan_id != plan.id or approval.plan_id != plan.id:
            raise BadRequestException(detail="Execution objects do not belong to the same plan")
        if plan.status not in {RemediationPlanStatus.approved, RemediationPlanStatus.queued_for_execution}:
            raise BadRequestException(detail="Plan is not approved for controlled execution")
        verification = await self.approval_service.verify_approval_for_dry_run(
            tenant_id,
            plan.id,
            approval.id,
            execution_action="execution_eligibility",
        )
        if verification.artifact_hash != artifact.artifact_hash:
            raise BadRequestException(detail="Approval artifact hash does not match selected artifact")
        check = await self._policy_check_by_hash(tenant_id, plan.id, verification.policy_check_hash)
        if check is None or check.artifact_id != artifact.id or not check.passed:
            raise BadRequestException(detail="Approval policy check hash does not match selected artifact")
        dry_run = await self._latest_passed_dry_run(tenant_id, plan.id, artifact.id, approval.id)
        if dry_run is None:
            raise BadRequestException(detail="Passed dry-run is required before controlled execution")
        if dry_run.blocking_reasons:
            raise BadRequestException(detail="Dry-run has blocking reasons and cannot be executed")

        adapter_type = self._adapter_type(artifact)
        simulated = adapter_type == SimulatedProviderExecutionAdapter.adapter_type
        if plan.risk_level not in (SIMULATED_RISK_ALLOWED if simulated else LOW_RISK_ALLOWED):
            raise BadRequestException(detail="Only low/medium risk or simulated-only execution is allowed in Phase 8")
        self._block_secret_or_mutation_content(artifact)
        sandbox_outcome = self.sandbox_service.validate_artifact(artifact)
        if sandbox_outcome.status != RemediationDryRunStatus.succeeded:
            raise BadRequestException(detail="Static sandbox validation blocks controlled execution")
        return ExecutionEligibility(adapter_type=adapter_type, simulated=simulated, dry_run=dry_run)

    def _adapter_type(self, artifact: RemediationArtifact) -> str:
        risk_flags = artifact.risk_flags or {}
        requested = str(risk_flags.get("execution_adapter") or risk_flags.get("execution_mode") or "").strip().lower()
        aliases = {
            "simulated": SimulatedProviderExecutionAdapter.adapter_type,
            "simulate": SimulatedProviderExecutionAdapter.adapter_type,
            "simulated_provider": SimulatedProviderExecutionAdapter.adapter_type,
            "static": StaticValidationExecutionAdapter.adapter_type,
            "static_validation": StaticValidationExecutionAdapter.adapter_type,
            "noop": LocalNoopExecutionAdapter.adapter_type,
            "local_noop": LocalNoopExecutionAdapter.adapter_type,
            "documentation_only": DocumentationOnlyExecutionAdapter.adapter_type,
        }
        if requested:
            adapter_type = aliases.get(requested)
            if adapter_type is None:
                raise BadRequestException(detail="Requested execution adapter is not allowed in Phase 8")
            return adapter_type
        if artifact.artifact_type == RemediationArtifactType.documentation_only:
            return DocumentationOnlyExecutionAdapter.adapter_type
        raise BadRequestException(detail="Artifact type is not eligible for Phase 8 controlled execution without an explicit safe adapter")

    def _block_secret_or_mutation_content(self, artifact: RemediationArtifact) -> None:
        raw = str(artifact.content_redacted or "")
        normalized = " ".join(raw.replace("\x00", " ").split())
        if sanitize_text(raw) != normalized:
            raise BadRequestException(detail="Artifact contains secret-like content and cannot be executed")
        for code, pattern, message in MUTATION_OR_PROCESS_PATTERNS:
            if pattern.search(raw):
                raise BadRequestException(detail=message)

    def _worker_token_scope(
        self,
        tenant_id: uuid.UUID,
        job_id: uuid.UUID,
        adapter_type: str,
        *,
        plan: RemediationPlan,
        actor_id: uuid.UUID | str | None,
    ) -> WorkerTokenScope:
        return WorkerTokenScope(
            tenant_id=tenant_id,
            worker_type="remediation_execution",
            job_id=job_id,
            action_type=adapter_type,
            provider_scope=sanitize_text(plan.provider or "") or None,
            resource_scope=sanitize_text(plan.resource_ref or "") or None,
            created_by=actor_id or "system",
            one_time=True,
        )

    async def _latest_passed_dry_run(
        self,
        tenant_id: uuid.UUID,
        plan_id: uuid.UUID,
        artifact_id: uuid.UUID,
        approval_id: uuid.UUID,
    ) -> RemediationDryRunResult | None:
        return (
            await self.db.execute(
                select(RemediationDryRunResult)
                .where(
                    RemediationDryRunResult.tenant_id == tenant_id,
                    RemediationDryRunResult.plan_id == plan_id,
                    RemediationDryRunResult.artifact_id == artifact_id,
                    RemediationDryRunResult.approval_id == approval_id,
                    RemediationDryRunResult.status == RemediationDryRunStatus.succeeded,
                )
                .order_by(desc(RemediationDryRunResult.completed_at), desc(RemediationDryRunResult.created_at))
                .limit(1)
            )
        ).scalars().first()

    async def _dry_run_by_id(self, tenant_id: uuid.UUID, dry_run_id: uuid.UUID | None) -> RemediationDryRunResult:
        if dry_run_id is None:
            raise BadRequestException(detail="Execution job is missing a dry-run result")
        dry_run = (
            await self.db.execute(
                select(RemediationDryRunResult).where(
                    RemediationDryRunResult.tenant_id == tenant_id,
                    RemediationDryRunResult.id == dry_run_id,
                )
            )
        ).scalars().first()
        if dry_run is None:
            raise NotFoundException(detail="Remediation dry-run result not found")
        return dry_run

    async def _plan(self, tenant_id: uuid.UUID, plan_id: uuid.UUID) -> RemediationPlan:
        plan = (
            await self.db.execute(select(RemediationPlan).where(RemediationPlan.tenant_id == tenant_id, RemediationPlan.id == plan_id))
        ).scalars().first()
        if plan is None:
            raise NotFoundException(detail="Remediation plan not found")
        return plan

    async def _artifact(self, tenant_id: uuid.UUID, plan_id: uuid.UUID, artifact_id: uuid.UUID) -> RemediationArtifact:
        artifact = (
            await self.db.execute(
                select(RemediationArtifact).where(
                    RemediationArtifact.tenant_id == tenant_id,
                    RemediationArtifact.plan_id == plan_id,
                    RemediationArtifact.id == artifact_id,
                )
            )
        ).scalars().first()
        if artifact is None:
            raise NotFoundException(detail="Remediation artifact not found")
        return artifact

    async def _approval(self, tenant_id: uuid.UUID, plan_id: uuid.UUID, approval_id: uuid.UUID | None) -> RemediationApproval:
        if approval_id is None:
            raise BadRequestException(detail="Approval is required for controlled execution")
        approval = (
            await self.db.execute(
                select(RemediationApproval).where(
                    RemediationApproval.tenant_id == tenant_id,
                    RemediationApproval.plan_id == plan_id,
                    RemediationApproval.id == approval_id,
                )
            )
        ).scalars().first()
        if approval is None:
            raise NotFoundException(detail="Remediation approval not found")
        return approval

    async def _job(self, tenant_id: uuid.UUID, job_id: uuid.UUID) -> RemediationExecutionJob:
        job = (
            await self.db.execute(
                select(RemediationExecutionJob).where(
                    RemediationExecutionJob.tenant_id == tenant_id,
                    RemediationExecutionJob.id == job_id,
                )
            )
        ).scalars().first()
        if job is None:
            raise NotFoundException(detail="Remediation execution job not found")
        return job

    async def _policy_check_by_hash(self, tenant_id: uuid.UUID, plan_id: uuid.UUID, check_hash: str) -> RemediationPolicyCheck | None:
        return (
            await self.db.execute(
                select(RemediationPolicyCheck).where(
                    RemediationPolicyCheck.tenant_id == tenant_id,
                    RemediationPolicyCheck.plan_id == plan_id,
                    RemediationPolicyCheck.policy_check_hash == check_hash,
                )
            )
        ).scalars().first()

    async def _rollback_plan_exists(self, plan: RemediationPlan) -> bool:
        rollback_id = await self.db.scalar(
            select(RemediationRollbackPlan.id).where(
                RemediationRollbackPlan.tenant_id == plan.tenant_id,
                RemediationRollbackPlan.plan_id == plan.id,
            )
        )
        return rollback_id is not None

    async def _verification_for_job(self, tenant_id: uuid.UUID, job_id: uuid.UUID) -> RemediationVerificationResult | None:
        return (
            await self.db.execute(
                select(RemediationVerificationResult).where(
                    RemediationVerificationResult.tenant_id == tenant_id,
                    RemediationVerificationResult.job_id == job_id,
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
            logger.warning("Failed to publish remediation execution event %s: %s", event.event_type, exc)

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
