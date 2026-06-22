from __future__ import annotations

import inspect
import logging
import uuid
from typing import Any

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.remediation import (
    RemediationArtifact,
    RemediationApprovalLevel,
    RemediationDryRunResult,
    RemediationDryRunStatus,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationPolicyCheck,
    RemediationRiskLevel,
)
from app.schemas.events import (
    RemediationDryRunCompletedEvent,
    RemediationDryRunFailedEvent,
    RemediationDryRunQueuedEvent,
    RemediationDryRunStartedEvent,
    RemediationSandboxRejectedArtifactEvent,
)
from app.services.api_safety import collect_secret_values, sanitize_text
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_sandbox_service import RemediationSandboxService
from app.services.remediation_state_machine import REMEDIATION_EVENTS_TOPIC, utcnow

logger = logging.getLogger(__name__)


HIGH_RISK_LEVELS = {RemediationRiskLevel.high, RemediationRiskLevel.critical}
HIGH_APPROVAL_LEVELS = {
    RemediationApprovalLevel.owner,
    RemediationApprovalLevel.security_admin,
}


def _safe_json(value: Any) -> Any:
    secrets_found = collect_secret_values(value)
    if isinstance(value, dict):
        return {sanitize_text(key, secrets_found): _safe_json(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value, secrets_found)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return sanitize_text(value, secrets_found)


class RemediationDryRunService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        event_producer=default_event_producer,
        sandbox_service: RemediationSandboxService | None = None,
    ) -> None:
        self.db = db
        self.event_producer = event_producer
        self.sandbox_service = sandbox_service or RemediationSandboxService()
        self.approval_service = RemediationApprovalService(db, event_producer=event_producer)

    async def create_dry_run_job(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str,
        artifact_id: uuid.UUID | str,
        approval_id: uuid.UUID | str | None = None,
        actor_id: uuid.UUID | str | None = None,
    ) -> RemediationExecutionJob:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        plan = await self._plan(tenant_uuid, self._uuid(plan_id))
        artifact = await self._artifact(tenant_uuid, plan.id, self._uuid(artifact_id))
        required_approval_level = await self._required_approval_level(plan, artifact)
        requires_approval = plan.risk_level in HIGH_RISK_LEVELS or required_approval_level in HIGH_APPROVAL_LEVELS

        if requires_approval and approval_id is None:
            raise BadRequestException(detail="Approved remediation approval is required before dry-run for high-risk artifacts")
        if approval_id is not None:
            verification = await self.approval_service.verify_approval_for_dry_run(tenant_uuid, plan.id, approval_id)
            if verification.artifact_hash != artifact.artifact_hash:
                raise BadRequestException(detail="Approval artifact hash does not match selected artifact")
            check = await self._policy_check_by_hash(tenant_uuid, plan.id, verification.policy_check_hash)
            if check is None or check.artifact_id != artifact.id:
                raise BadRequestException(detail="Approval policy check hash does not match selected artifact")

        sandbox_id = f"queued-{uuid.uuid4().hex}"
        job = RemediationExecutionJob(
            tenant_id=tenant_uuid,
            plan_id=plan.id,
            approval_id=self._uuid(approval_id) if approval_id else None,
            sandbox_id=sandbox_id,
            status=RemediationExecutionStatus.dry_run_requested,
            disabled_reason="Dry-run static validation only; real remediation execution remains disabled.",
        )
        self.db.add(job)
        await self.db.flush()

        result = RemediationDryRunResult(
            tenant_id=tenant_uuid,
            job_id=job.id,
            plan_id=plan.id,
            artifact_id=artifact.id,
            approval_id=job.approval_id,
            sandbox_id=sandbox_id,
            dry_run_type=self._artifact_type_value(artifact),
            status=RemediationDryRunStatus.queued,
            output_summary="Dry-run queued for static sandbox validation.",
            warnings=[],
            blocking_reasons=[],
        )
        self.db.add(result)
        await self.db.flush()
        job.dry_run_result_id = result.id
        await self.db.flush()
        await self._emit(
            RemediationDryRunQueuedEvent(
                tenant_id=tenant_uuid,
                actor_id=self._uuid(actor_id) if actor_id else None,
                plan_id=plan.id,
                artifact_id=artifact.id,
                job_id=job.id,
                result_id=result.id,
                status=result.status.value,
            )
        )
        return job

    async def run_dry_run(self, tenant_id: uuid.UUID | str, job_id: uuid.UUID | str) -> RemediationDryRunResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        job = await self._job(tenant_uuid, self._uuid(job_id))
        result = await self._result_for_job(tenant_uuid, job)
        artifact = await self._artifact(tenant_uuid, result.plan_id, result.artifact_id)
        started_at = utcnow()
        result.status = RemediationDryRunStatus.running
        result.started_at = started_at
        job.started_at = started_at
        await self.db.flush()
        await self._emit(
            RemediationDryRunStartedEvent(
                tenant_id=tenant_uuid,
                plan_id=result.plan_id,
                artifact_id=result.artifact_id,
                job_id=job.id,
                result_id=result.id,
                status=result.status.value,
            )
        )

        try:
            outcome = self.sandbox_service.validate_artifact(artifact)
            completed_at = utcnow()
            result.sandbox_id = outcome.sandbox_id
            result.dry_run_type = outcome.dry_run_type
            result.status = outcome.status
            result.output_summary = sanitize_text(outcome.output_summary)
            result.warnings = _safe_json(outcome.warnings)
            result.blocking_reasons = _safe_json(outcome.blocking_reasons)
            result.completed_at = completed_at
            job.sandbox_id = outcome.sandbox_id
            job.completed_at = completed_at
            job.status = (
                RemediationExecutionStatus.dry_run_succeeded
                if outcome.status == RemediationDryRunStatus.succeeded
                else RemediationExecutionStatus.dry_run_failed
            )
            await self.db.flush()

            if outcome.status == RemediationDryRunStatus.rejected:
                await self._emit(
                    RemediationSandboxRejectedArtifactEvent(
                        tenant_id=tenant_uuid,
                        plan_id=result.plan_id,
                        artifact_id=result.artifact_id,
                        job_id=job.id,
                        result_id=result.id,
                        status=result.status.value,
                        warning_count=len(result.warnings or []),
                        blocking_reason_count=len(result.blocking_reasons or []),
                    )
                )
            await self._emit(
                RemediationDryRunCompletedEvent(
                    tenant_id=tenant_uuid,
                    plan_id=result.plan_id,
                    artifact_id=result.artifact_id,
                    job_id=job.id,
                    result_id=result.id,
                    status=result.status.value,
                    warning_count=len(result.warnings or []),
                    blocking_reason_count=len(result.blocking_reasons or []),
                )
            )
            return result
        except Exception:
            completed_at = utcnow()
            result.status = RemediationDryRunStatus.failed
            result.output_summary = "Dry-run failed during static sandbox validation."
            result.blocking_reasons = [_safe_json({"code": "dry_run_failed", "message": "Sandbox validation failed safely."})]
            result.completed_at = completed_at
            job.status = RemediationExecutionStatus.dry_run_failed
            job.completed_at = completed_at
            await self.db.flush()
            await self._emit(
                RemediationDryRunFailedEvent(
                    tenant_id=tenant_uuid,
                    plan_id=result.plan_id,
                    artifact_id=result.artifact_id,
                    job_id=job.id,
                    result_id=result.id,
                    status=result.status.value,
                    warning_count=len(result.warnings or []),
                    blocking_reason_count=len(result.blocking_reasons or []),
                )
            )
            logger.exception("Remediation dry-run sandbox validation failed")
            return result

    async def get_dry_run_result(self, tenant_id: uuid.UUID | str, result_id: uuid.UUID | str) -> RemediationDryRunResult:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        result = (
            await self.db.execute(
                select(RemediationDryRunResult).where(
                    RemediationDryRunResult.tenant_id == tenant_uuid,
                    RemediationDryRunResult.id == self._uuid(result_id),
                )
            )
        ).scalars().first()
        if result is None:
            raise NotFoundException(detail="Remediation dry-run result not found")
        return result

    async def list_dry_run_results(
        self,
        tenant_id: uuid.UUID | str,
        plan_id: uuid.UUID | str | None = None,
    ) -> list[RemediationDryRunResult]:
        tenant_uuid = self._uuid(tenant_id)
        await self._set_tenant_context(tenant_uuid)
        query = select(RemediationDryRunResult).where(RemediationDryRunResult.tenant_id == tenant_uuid)
        if plan_id is not None:
            query = query.where(RemediationDryRunResult.plan_id == self._uuid(plan_id))
        query = query.order_by(desc(RemediationDryRunResult.created_at))
        return list((await self.db.execute(query)).scalars().all())

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

    async def _result_for_job(self, tenant_id: uuid.UUID, job: RemediationExecutionJob) -> RemediationDryRunResult:
        if job.dry_run_result_id is None:
            raise BadRequestException(detail="Execution job is not associated with a dry-run result")
        result = (
            await self.db.execute(
                select(RemediationDryRunResult).where(
                    RemediationDryRunResult.tenant_id == tenant_id,
                    RemediationDryRunResult.job_id == job.id,
                    RemediationDryRunResult.id == job.dry_run_result_id,
                )
            )
        ).scalars().first()
        if result is None:
            raise NotFoundException(detail="Remediation dry-run result not found")
        return result

    async def _required_approval_level(self, plan: RemediationPlan, artifact: RemediationArtifact) -> RemediationApprovalLevel | None:
        check = (
            await self.db.execute(
                select(RemediationPolicyCheck)
                .where(
                    RemediationPolicyCheck.tenant_id == plan.tenant_id,
                    RemediationPolicyCheck.plan_id == plan.id,
                    RemediationPolicyCheck.artifact_id == artifact.id,
                    RemediationPolicyCheck.passed.is_(True),
                )
                .order_by(desc(RemediationPolicyCheck.created_at))
                .limit(1)
            )
        ).scalars().first()
        return check.required_approval_level if check else None

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

    async def _emit(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(REMEDIATION_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish remediation dry-run event %s: %s", event.event_type, exc)

    def _artifact_type_value(self, artifact: RemediationArtifact) -> str:
        artifact_type = artifact.artifact_type
        return artifact_type.value if hasattr(artifact_type, "value") else str(artifact_type)

    def _uuid(self, value: uuid.UUID | str | None) -> uuid.UUID | None:
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
