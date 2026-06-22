from __future__ import annotations

import inspect
import json
import uuid

import pytest
from sqlalchemy import delete, select, text

from app.api.v1.endpoints import remediation as remediation_api
from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, NotFoundException
from app.models.integration import CloudIntegration
from app.models.remediation import (
    RemediationApproval,
    RemediationArtifact,
    RemediationApprovalStatus,
    RemediationExecutionJob,
    RemediationExecutionStatus,
    RemediationPlan,
    RemediationVerificationResult,
)
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.remediation import CreateExecutionRequest
from app.services.remediation_execution_service import RemediationExecutionService
from scripts.seed_sprint4_demo import (
    DEMO_TENANT_SLUG,
    assert_safe_summary,
    seed_demo_dataset,
)
from tests.test_sprint4_phase4_approval_workflow import _cleanup, _tenant


UNSAFE_RESPONSE_TERMS = (
    "akia",
    "begin private key",
    "ghp_",
    "raw_provider_payload",
    "super-secret",
    "aws_secret_access_key",
    "you are compliant",
    "legally compliant",
)


def _serialized(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, default=str).lower()


async def _demo_tenant_and_user(db):
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().one()
    user = (await db.execute(select(User).where(User.tenant_id == tenant.id).order_by(User.email))).scalars().first()
    assert user is not None
    return tenant, user


async def _delete_demo_tenant(db) -> None:
    tenant = (await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))).scalars().first()
    if tenant is not None:
        await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
        await db.execute(delete(Tenant).where(Tenant.id == tenant.id))
        await db.commit()


@pytest.mark.asyncio
async def test_sprint4_demo_seed_is_idempotent_and_creates_required_lifecycle():
    async with AsyncSessionLocal() as db:
        try:
            first = await seed_demo_dataset(db)
            second = await seed_demo_dataset(db)

            first_shape = {key: value for key, value in first.as_safe_dict().items() if key != "blocked_plan_id"}
            second_shape = {key: value for key, value in second.as_safe_dict().items() if key != "blocked_plan_id"}
            assert first_shape == second_shape
            assert second.plans >= 3
            assert second.artifacts >= 3
            assert second.rollback_plans >= 3
            assert second.policy_checks >= 3
            assert second.approvals >= 2
            assert second.dry_run_results >= 2
            assert second.execution_jobs >= 3
            assert second.succeeded_jobs == 2
            assert second.verified_results == 2
            assert second.blocked_jobs >= 1
            assert_safe_summary(second, [])
        finally:
            await _delete_demo_tenant(db)


@pytest.mark.asyncio
async def test_sprint4_demo_api_visibility_is_sanitized_and_complete():
    async with AsyncSessionLocal() as db:
        try:
            summary = await seed_demo_dataset(db)
            tenant, user = await _demo_tenant_and_user(db)

            plans = await remediation_api.list_plans(limit=50, tenant=tenant, db=db, _user=user)
            jobs = await remediation_api.list_jobs(limit=50, tenant=tenant, db=db, _user=user)
            dry_runs = await remediation_api.list_dry_runs(limit=50, tenant=tenant, db=db, _user=user)
            verifications = await remediation_api.list_verification_results(limit=50, tenant=tenant, db=db, _user=user)
            blocked_detail = await remediation_api.get_plan(summary.blocked_plan_id, tenant=tenant, db=db, _user=user)

            assert plans.total >= 3
            assert dry_runs.total >= 2
            assert verifications.total == 2
            assert any(item.status == "succeeded" for item in jobs.items)
            assert any(item.status == "disabled" and "blocked mutation" in str(item.disabled_reason).lower() for item in jobs.items)
            assert any(item.passed is False and item.blocking_reasons for item in blocked_detail.policy_checks)

            payload = _serialized([plans, jobs, dry_runs, verifications, blocked_detail])
            for term in UNSAFE_RESPONSE_TERMS:
                assert term not in payload
        finally:
            await _delete_demo_tenant(db)


@pytest.mark.asyncio
async def test_sprint4_demo_approval_dry_run_and_blocking_invariants_hold():
    async with AsyncSessionLocal() as db:
        try:
            summary = await seed_demo_dataset(db)
            tenant, _ = await _demo_tenant_and_user(db)

            blocked_jobs = (
                await db.execute(
                    select(RemediationExecutionJob).where(
                        RemediationExecutionJob.tenant_id == tenant.id,
                        RemediationExecutionJob.plan_id == summary.blocked_plan_id,
                    )
                )
            ).scalars().all()
            assert blocked_jobs
            assert all(job.status != RemediationExecutionStatus.succeeded for job in blocked_jobs)

            successful_jobs = (
                await db.execute(
                    select(RemediationExecutionJob).where(
                        RemediationExecutionJob.tenant_id == tenant.id,
                        RemediationExecutionJob.status == RemediationExecutionStatus.succeeded,
                    )
                )
            ).scalars().all()
            assert len(successful_jobs) == 2
            assert all(job.approval_id is not None and job.dry_run_result_id is not None for job in successful_jobs)

            approvals = (
                await db.execute(
                    select(RemediationApproval).where(
                        RemediationApproval.tenant_id == tenant.id,
                        RemediationApproval.id.in_([job.approval_id for job in successful_jobs if job.approval_id is not None]),
                    )
                )
            ).scalars().all()
            assert len(approvals) == 2
            assert all(approval.status == RemediationApprovalStatus.used for approval in approvals)

            verifications = (
                await db.execute(
                    select(RemediationVerificationResult).where(
                        RemediationVerificationResult.tenant_id == tenant.id,
                        RemediationVerificationResult.verified.is_(True),
                    )
                )
            ).scalars().all()
            assert len(verifications) == 2
            assert any("documentation-only" in item.verification_summary.lower() for item in verifications)
            assert any("no external provider" in item.verification_summary.lower() for item in verifications)
        finally:
            await _delete_demo_tenant(db)


@pytest.mark.asyncio
async def test_sprint4_demo_tenant_isolation_and_unsafe_execute_endpoint_blocks():
    async with AsyncSessionLocal() as db:
        other_tenant = None
        try:
            summary = await seed_demo_dataset(db)
            tenant, user = await _demo_tenant_and_user(db)
            other_tenant = await _tenant(db, "phase9-isolation")

            service = RemediationExecutionService(db, event_producer=None)
            verifications = await service.list_verification_results(other_tenant.id)
            assert verifications == []
            await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
            first_job_id = (
                await db.scalar(
                    select(RemediationExecutionJob.id).where(
                        RemediationExecutionJob.tenant_id == tenant.id,
                        RemediationExecutionJob.status == RemediationExecutionStatus.succeeded,
                    )
                )
            )
            assert first_job_id is not None
            with pytest.raises(NotFoundException):
                await service.get_execution_job(other_tenant.id, first_job_id)

            await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
            blocked_artifact_id = await db.scalar(
                select(RemediationArtifact.id).where(
                    RemediationArtifact.tenant_id == tenant.id,
                    RemediationArtifact.plan_id == summary.blocked_plan_id,
                )
            )
            assert blocked_artifact_id is not None
            with pytest.raises((BadRequestException, NotFoundException)):
                await remediation_api.create_plan_artifact_execution(
                    summary.blocked_plan_id,
                    blocked_artifact_id,
                    CreateExecutionRequest(approval_id=uuid.uuid4()),
                    tenant=tenant,
                    db=db,
                    current_user=user,
                )
        finally:
            await _delete_demo_tenant(db)
            if other_tenant is not None:
                await _cleanup(db, other_tenant.id)


def test_sprint4_phase9_execution_source_has_no_real_provider_or_process_clients():
    source = inspect.getsource(RemediationExecutionService).lower()
    forbidden = [
        "import subprocess",
        "subprocess.run",
        "boto3",
        "botocore",
        "google.cloud",
        "github import",
        "requests.",
        "httpx.",
        "git push origin",
        "vault_credentials",
    ]
    for term in forbidden:
        assert term not in source

    seed_source = inspect.getsource(seed_demo_dataset).lower()
    assert "llm" not in seed_source
    assert "provider.call" not in seed_source
