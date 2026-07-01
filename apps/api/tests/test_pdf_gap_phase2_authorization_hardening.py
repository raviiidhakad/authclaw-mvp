from __future__ import annotations

import json
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.core.database import AsyncSessionLocal
from app.core.exceptions import BadRequestException, ForbiddenException
from app.models.remediation import RemediationApprovalStatus
from app.services.remediation_approval_service import RemediationApprovalService
from app.services.remediation_execution_service import ADAPTERS, RemediationExecutionService
from app.services.remediation_sandbox_service import RemediationSandboxService
from app.services.remediation_state_machine import utcnow
from app.services.worker_token_service import InMemoryWorkerTokenStore, WorkerTokenScope, WorkerTokenService
from tests.test_sprint4_phase8_execution import _approved_dry_run_fixture
from tests.test_sprint4_phase4_approval_workflow import (
    FakeProducer,
    _cleanup,
    _critical_validated_plan,
    _tenant,
    _user,
)


def _serialized(value) -> str:
    return json.dumps(value, sort_keys=True, default=str).lower()


@pytest.mark.asyncio
async def test_action_bound_mfa_envelope_requires_exact_approver_and_fresh_artifacts():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "pdf-gap-mfa")
        try:
            requester = await _user(db, tenant.id, "operator", "phase2-requester")
            owner = await _user(db, tenant.id, "owner", "phase2-owner")
            other_owner = await _user(db, tenant.id, "owner", "phase2-other-owner")
            plan, artifact, _ = await _critical_validated_plan(db, tenant.id)
            producer = FakeProducer()
            service = RemediationApprovalService(db, event_producer=producer)

            approval = await service.request_approval(tenant.id, plan.id, requested_by=requester.id)
            approved = await service.approve(tenant.id, approval.id, owner.id, "Approved after fresh MFA.", mfa_verified=True)

            verification = await service.verify_approval_for_dry_run(
                tenant.id,
                plan.id,
                approved.id,
                actor_id=owner.id,
                execution_action="phase2_test_execution",
            )
            assert verification.action_envelope_hash
            assert len(verification.action_envelope_hash) == 64
            with pytest.raises(BadRequestException) as wrong_user:
                await service.verify_approval_for_dry_run(
                    tenant.id,
                    plan.id,
                    approved.id,
                    actor_id=other_owner.id,
                    execution_action="phase2_test_execution",
                )
            assert "different approver" in wrong_user.value.detail.lower()

            artifact.artifact_hash = uuid.uuid4().hex
            await db.flush()
            with pytest.raises(BadRequestException) as changed_artifact:
                await service.verify_approval_for_dry_run(
                    tenant.id,
                    plan.id,
                    approved.id,
                    actor_id=owner.id,
                    execution_action="phase2_test_execution",
                )
            assert "artifact hash" in changed_artifact.value.detail.lower()

            events = _serialized([event for _, event in producer.events])
            assert "remediation.mfa.challenge" in events
            assert "ghp_" not in events
            assert "vault://" not in events
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_action_bound_mfa_rejects_expired_missing_mfa_and_cross_tenant():
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "pdf-gap-mfa-a")
        tenant_b = await _tenant(db, "pdf-gap-mfa-b")
        try:
            requester = await _user(db, tenant_a.id, "operator", "phase2-requester-a")
            owner = await _user(db, tenant_a.id, "owner", "phase2-owner-a")
            plan, _, _ = await _critical_validated_plan(db, tenant_a.id)
            service = RemediationApprovalService(db, event_producer=None)

            approval = await service.request_approval(tenant_a.id, plan.id, requested_by=requester.id)
            with pytest.raises(ForbiddenException) as missing_mfa:
                await service.approve(tenant_a.id, approval.id, owner.id, "Missing fresh MFA.", mfa_verified=False)
            assert "mfa" in missing_mfa.value.detail.lower()

            approved = await service.approve(tenant_a.id, approval.id, owner.id, "Fresh MFA verified.", mfa_verified=True)
            approved.expires_at = utcnow() - timedelta(minutes=1)
            await db.flush()
            with pytest.raises(BadRequestException) as expired:
                await service.verify_approval_for_future_execution(tenant_a.id, plan.id, approved.id, actor_id=owner.id)
            assert "expired" in expired.value.detail.lower()
            assert approved.status == RemediationApprovalStatus.expired

            with pytest.raises(Exception):
                await service.verify_approval_for_future_execution(tenant_b.id, plan.id, approved.id, actor_id=owner.id)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_worker_execution_tokens_are_scoped_hashed_one_time_revocable_and_audited():
    tenant_id = uuid.uuid4()
    job_id = uuid.uuid4()
    producer = FakeProducer()
    store = InMemoryWorkerTokenStore()
    service = WorkerTokenService(store=store, event_producer=producer, ttl_seconds=30)
    scope = WorkerTokenScope(
        tenant_id=tenant_id,
        worker_type="remediation_execution",
        job_id=job_id,
        action_type="simulated_provider",
        provider_scope="aws",
        resource_scope="arn:aws:iam::123456789012:role/demo",
        created_by="system",
    )

    issued = await service.issue_token(scope)
    record = next(iter(store.records.values()))
    assert issued.token.startswith("awt_")
    assert issued.token not in store.records
    assert record.token_hash != issued.token
    assert len(record.token_hash) == 64

    await service.validate_token(issued.token, scope)
    with pytest.raises(ForbiddenException) as replay:
        await service.validate_token(issued.token, scope)
    assert "already been used" in replay.value.detail

    other = await service.issue_token(scope)
    wrong_scope = WorkerTokenScope(
        tenant_id=uuid.uuid4(),
        worker_type=scope.worker_type,
        job_id=scope.job_id,
        action_type=scope.action_type,
        provider_scope=scope.provider_scope,
        resource_scope=scope.resource_scope,
    )
    with pytest.raises(ForbiddenException) as wrong_tenant:
        await service.validate_token(other.token, wrong_scope)
    assert "scope mismatch" in wrong_tenant.value.detail.lower()

    revoked = await service.issue_token(scope)
    await service.revoke_token(revoked.token)
    with pytest.raises(ForbiddenException) as revoked_error:
        await service.validate_token(revoked.token, scope)
    assert "revoked" in revoked_error.value.detail.lower()

    expired_service = WorkerTokenService(store=InMemoryWorkerTokenStore(), event_producer=producer, ttl_seconds=1)
    expired = await expired_service.issue_token(scope)
    expired_record = next(iter(expired_service.store.records.values()))
    expired_record.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(ForbiddenException) as expired_error:
        await expired_service.validate_token(expired.token, scope)
    assert "expired" in expired_error.value.detail.lower()

    serialized_events = _serialized([event for _, event in producer.events])
    assert issued.token not in serialized_events
    assert "awt_" not in serialized_events
    assert "vault://" not in serialized_events
    assert "remediation.worker_token" in serialized_events


@pytest.mark.asyncio
async def test_remediation_execution_fails_closed_when_worker_token_validation_fails(monkeypatch, tmp_path):
    class RejectingWorkerTokenService:
        async def issue_token(self, scope):
            return SimpleNamespace(token="awt_test_not_logged")

        async def validate_token(self, raw_token, expected_scope):
            raise ForbiddenException(detail="Worker execution token validation failed")

    class SpyAdapter:
        adapter_type = "documentation_only"
        simulated = False
        called = False

        def execute(self, *, plan, artifact, dry_run):
            self.called = True
            raise AssertionError("Adapter must not execute when worker token validation fails")

    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "pdf-gap-worker-failclosed")
        try:
            plan, artifact, approval, _ = await _approved_dry_run_fixture(db, tenant.id, sandbox_root=tmp_path)
            spy_adapter = SpyAdapter()
            monkeypatch.setitem(ADAPTERS, "documentation_only", spy_adapter)
            service = RemediationExecutionService(
                db,
                event_producer=None,
                sandbox_service=RemediationSandboxService(root_dir=tmp_path),
                worker_token_service=RejectingWorkerTokenService(),
            )
            job = await service.create_execution_job(tenant.id, plan.id, artifact.id, approval.id)

            with pytest.raises(ForbiddenException) as blocked:
                await service.execute_job(tenant.id, job.id)
            assert "worker execution token" in blocked.value.detail.lower()
            assert spy_adapter.called is False
        finally:
            await _cleanup(db, tenant.id)
