from __future__ import annotations

import json
import os
import secrets
import uuid
from datetime import timedelta

import asyncpg
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import AsyncSessionLocal
from app.models import Base
from app.models.remediation import (
    RemediationApproval,
    RemediationApprovalStatus,
    RemediationArtifact,
    RemediationArtifactType,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPolicyCheck,
    RemediationRiskLevel,
)
from app.models.approval import Approval
from app.models.tenant import Tenant
from app.services.remediation_state_machine import (
    RemediationExecutionDisabled,
    RemediationPlanService,
    RemediationStateError,
    RemediationStateMachine,
    artifact_hash,
    policy_check_hash,
    utcnow,
)

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "5434"))
DB_NAME = os.environ.get("DB_NAME", "authclaw")
SUPERUSER_DSN = f"postgresql://postgres:password@{DB_HOST}:{DB_PORT}/{DB_NAME}"
APP_USER_DSN = f"postgresql://authclaw_app:authclaw_app_password@{DB_HOST}:{DB_PORT}/{DB_NAME}"

UNSAFE_TERMS = (
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_supersecretsecretsecretsecret",
    "raw_provider_payload",
    "super-secret",
)


class FakeProducer:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint4-phase1-{suffix}",
        slug=f"sprint4-phase1-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        for table in (
            "remediation_audit_links",
            "remediation_verification_results",
            "remediation_execution_jobs",
            "remediation_approvals",
            "remediation_policy_checks",
            "remediation_rollback_plans",
            "remediation_artifacts",
            "remediation_plans",
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


async def _draft_with_artifact_and_check(db, tenant_id: uuid.UUID, producer=None):
    plan_service = RemediationPlanService(db, event_producer=producer)
    state = RemediationStateMachine(db, event_producer=producer)
    plan = await plan_service.create_draft_plan_shell(
        tenant_id=tenant_id,
        summary="Review public access remediation shell.",
        expected_impact="Review-only impact. No execution.",
        risk_level=RemediationRiskLevel.high,
    )
    artifact = await plan_service.attach_artifact_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_type=RemediationArtifactType.documentation_only,
        content="Documentation-only remediation placeholder.",
    )
    rollback = await plan_service.attach_rollback_placeholder(
        tenant_id=tenant_id,
        plan_id=plan.id,
        rollback_steps="Return to prior reviewed configuration if a future phase executes.",
        risk_level=RemediationRiskLevel.high,
    )
    check_hash = policy_check_hash(plan.id, artifact.artifact_hash, True, [])
    check = RemediationPolicyCheck(
        tenant_id=tenant_id,
        plan_id=plan.id,
        artifact_id=artifact.id,
        passed=True,
        warnings=[],
        blocking_reasons=[],
        required_approval_level="admin",
        policy_check_hash=check_hash,
    )
    db.add(check)
    await db.flush()
    await state.transition_plan(tenant_id, plan.id, RemediationPlanStatus.plan_validated)
    return plan, artifact, rollback, check


def test_phase1_models_are_registered_in_metadata():
    # Sprint 4 Phase 1 intentionally uses remediation-specific approvals.
    # The legacy generic Approval table lacks artifact_hash, policy_check_hash,
    # and nonce fields needed for replay protection and artifact binding.
    expected = {
        "remediation_plans",
        "remediation_artifacts",
        "remediation_rollback_plans",
        "remediation_policy_checks",
        "remediation_approvals",
        "remediation_execution_jobs",
        "remediation_verification_results",
        "remediation_audit_links",
    }
    assert expected <= set(Base.metadata.tables)
    assert Approval.__tablename__ == "approvals"
    assert RemediationApproval.__tablename__ == "remediation_approvals"


@pytest.mark.asyncio
async def test_state_machine_allows_valid_approval_foundation_and_blocks_execution():
    async with AsyncSessionLocal() as db:
        producer = FakeProducer()
        tenant = await _tenant(db)
        try:
            plan, artifact, _, check = await _draft_with_artifact_and_check(db, tenant.id, producer)
            state = RemediationStateMachine(db, event_producer=producer)
            await state.transition_plan(
                tenant.id,
                plan.id,
                RemediationPlanStatus.approval_requested,
                context={"artifact_hash": artifact.artifact_hash, "policy_check_hash": check.policy_check_hash},
            )
            approval = RemediationApproval(
                tenant_id=tenant.id,
                plan_id=plan.id,
                artifact_hash=artifact.artifact_hash,
                policy_check_hash=check.policy_check_hash,
                status=RemediationApprovalStatus.approved,
                expires_at=utcnow() + timedelta(minutes=30),
                mfa_verified=True,
                nonce="nonce-" + uuid.uuid4().hex,
            )
            db.add(approval)
            await db.flush()
            approved = await state.transition_plan(
                tenant.id,
                plan.id,
                RemediationPlanStatus.approved,
                context={"approval_id": approval.id, "nonce": approval.nonce},
            )
            assert approved.status == RemediationPlanStatus.approved

            with pytest.raises(RemediationExecutionDisabled):
                await state.transition_plan(tenant.id, plan.id, RemediationPlanStatus.queued_for_execution)
            assert any(event[1]["event_type"] == "remediation.execution.blocked" for event in producer.events)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_invalid_transition_requires_rollback_artifact_and_policy_check():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            service = RemediationPlanService(db, event_producer=None)
            state = RemediationStateMachine(db, event_producer=None)
            plan = await service.create_draft_plan_shell(tenant_id=tenant.id, summary="Missing gates", expected_impact="None")

            with pytest.raises(RemediationStateError):
                await state.transition_plan(tenant.id, plan.id, RemediationPlanStatus.approval_requested)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_approval_expiry_hash_mismatch_and_replay_prevention():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            plan, artifact, _, check = await _draft_with_artifact_and_check(db, tenant.id, None)
            state = RemediationStateMachine(db, event_producer=None)
            await state.transition_plan(
                tenant.id,
                plan.id,
                RemediationPlanStatus.approval_requested,
                context={"artifact_hash": artifact.artifact_hash, "policy_check_hash": check.policy_check_hash},
            )

            wrong_hash = "0" * 64
            bad_approval = RemediationApproval(
                tenant_id=tenant.id,
                plan_id=plan.id,
                artifact_hash=wrong_hash,
                policy_check_hash=check.policy_check_hash,
                status=RemediationApprovalStatus.approved,
                expires_at=utcnow() + timedelta(minutes=30),
                nonce="nonce-" + uuid.uuid4().hex,
            )
            db.add(bad_approval)
            await db.flush()
            with pytest.raises(RemediationStateError):
                await state.transition_plan(
                    tenant.id,
                    plan.id,
                    RemediationPlanStatus.approved,
                    context={"approval_id": bad_approval.id, "nonce": bad_approval.nonce},
                )

            expired_approval = RemediationApproval(
                tenant_id=tenant.id,
                plan_id=plan.id,
                artifact_hash=artifact.artifact_hash,
                policy_check_hash=check.policy_check_hash,
                status=RemediationApprovalStatus.pending,
                expires_at=utcnow() - timedelta(minutes=1),
                nonce="nonce-" + uuid.uuid4().hex,
            )
            db.add(expired_approval)
            await db.flush()
            expired = await state.expire_approvals(tenant.id)
            assert expired_approval in expired
            assert expired_approval.status == RemediationApprovalStatus.expired
            assert plan.status == RemediationPlanStatus.expired

            with pytest.raises(RemediationStateError):
                await state.transition_plan(
                    tenant.id,
                    plan.id,
                    RemediationPlanStatus.approved,
                    context={"approval_id": expired_approval.id, "nonce": expired_approval.nonce},
                )
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_artifact_hash_determinism_uniqueness_and_sanitization():
    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db)
        try:
            producer = FakeProducer()
            service = RemediationPlanService(db, event_producer=producer)
            plan = await service.create_draft_plan_shell(
                tenant_id=tenant.id,
                summary="Fix token=super-secret raw_provider_payload AKIAIOSFODNN7EXAMPLE",
                expected_impact="No cloud mutation.",
            )
            artifact = await service.attach_artifact_placeholder(
                tenant_id=tenant.id,
                plan_id=plan.id,
                content="Review ghp_supersecretsecretsecretsecret and raw_provider_payload safely.",
                risk_flags={"token": "super-secret", "raw_provider_payload": "hidden"},
            )
            expected_hash = artifact_hash(RemediationArtifactType.documentation_only, artifact.content_redacted)
            assert artifact.artifact_hash == expected_hash

            serialized = json.dumps(
                {
                    "plan": {"summary": plan.summary, "impact": plan.expected_impact},
                    "artifact": {
                        "content": artifact.content_redacted,
                        "flags": artifact.risk_flags,
                        "events": [event for _, event in producer.events],
                    },
                },
                sort_keys=True,
            )
            for term in UNSAFE_TERMS:
                assert term.lower() not in serialized.lower()

            duplicate = RemediationArtifact(
                tenant_id=tenant.id,
                plan_id=plan.id,
                artifact_type=RemediationArtifactType.documentation_only,
                content_redacted=artifact.content_redacted,
                artifact_hash=artifact.artifact_hash,
                risk_flags={},
            )
            db.add(duplicate)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_remediation_rls_policy_and_tenant_isolation():
    su = await asyncpg.connect(SUPERUSER_DSN)
    app = await asyncpg.connect(APP_USER_DSN)
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    plan_a = uuid.uuid4()
    plan_b = uuid.uuid4()
    try:
        await su.execute(
            """INSERT INTO tenants (id, name, slug, plan, status, settings, created_at, updated_at)
               VALUES ($1, 'rls-a', $2, 'free', 'active', '{}'::jsonb, now(), now()),
                      ($3, 'rls-b', $4, 'free', 'active', '{}'::jsonb, now(), now())""",
            tenant_a,
            f"rls-a-{tenant_a.hex[:8]}",
            tenant_b,
            f"rls-b-{tenant_b.hex[:8]}",
        )
        for tenant_id, plan_id in ((tenant_a, plan_a), (tenant_b, plan_b)):
            await su.execute(
                """INSERT INTO remediation_plans
                   (id, tenant_id, risk_level, status, summary, expected_impact, created_at, updated_at)
                   VALUES ($1, $2, 'medium'::remediation_risk_level,
                           'plan_drafted'::remediation_plan_status,
                           'rls plan', 'rls impact', now(), now())""",
                plan_id,
                tenant_id,
            )

        policy_rows = await su.fetch(
            "SELECT tablename FROM pg_policies WHERE policyname = 'tenant_isolation' AND tablename LIKE 'remediation_%'"
        )
        found = {row["tablename"] for row in policy_rows}
        assert "remediation_plans" in found
        assert "remediation_approvals" in found

        async with app.transaction():
            await app.execute(f"SET LOCAL app.current_tenant_id = '{tenant_a}'")
            rows = await app.fetch("SELECT id FROM remediation_plans WHERE id = ANY($1::uuid[])", [plan_a, plan_b])
            ids = {row["id"] for row in rows}
            assert plan_a in ids
            assert plan_b not in ids
    finally:
        await su.execute("DELETE FROM remediation_plans WHERE tenant_id = ANY($1::uuid[])", [tenant_a, tenant_b])
        await su.execute("DELETE FROM tenants WHERE id = ANY($1::uuid[])", [tenant_a, tenant_b])
        await su.close()
        await app.close()
