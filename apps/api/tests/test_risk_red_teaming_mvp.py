from __future__ import annotations

import inspect
import json
import secrets
import uuid

import pytest
from sqlalchemy import select, text

from app.api.v1.endpoints import risk as risk_api
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import NotFoundException
from app.main import app
from app.models.risk import AdversarialProbeCategory, AdversarialProbeRun, RedTeamProbeResult, VulnerabilityRegisterItem
from app.schemas.risk import AdversarialProbeRunCreate, VulnerabilityUpdateRequest
from app.services import risk_red_teaming
from tests.test_sprint4_phase4_approval_workflow import _tenant, _user


UNSAFE_OUTPUT_TERMS = (
    "gsk_",
    "sk-",
    "ghp_",
    "xox",
    "vault://",
    "secret/authclaw/",
    "raw_provider_payload",
    "-----BEGIN",
    "legally compliant",
    "guaranteed compliant",
    "audit-ready guaranteed",
)


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    await db.rollback()
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        for table in (
            "risk_posture_snapshots",
            "vulnerability_register_items",
            "red_team_probe_results",
            "adversarial_probe_runs",
            "user_roles",
            "users",
        ):
            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


def _registered_api_routes() -> set[tuple[str, str]]:
    prefix = settings.API_PREFIX.rstrip("/")
    registered: set[tuple[str, str]] = set()
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith(prefix):
            continue
        normalized_path = path.removeprefix(prefix) or "/"
        for method in operations:
            registered.add((method.upper(), normalized_path))
    return registered


def _safe_json(value) -> str:
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    else:
        payload = value
    serialized = json.dumps(payload, sort_keys=True).lower()
    for term in UNSAFE_OUTPUT_TERMS:
        assert term.lower() not in serialized
    return serialized


def test_risk_red_teaming_routes_and_rbac_surface_registered():
    expected = {
        ("GET", "/risk/probes"),
        ("POST", "/risk/probes/run"),
        ("GET", "/risk/probes/{run_id}"),
        ("GET", "/risk/probe-runs"),
        ("POST", "/risk/probe-runs"),
        ("GET", "/risk/probe-runs/{run_id}"),
        ("GET", "/risk/vulnerabilities"),
        ("PATCH", "/risk/vulnerabilities/{vulnerability_id}"),
        ("GET", "/risk/posture"),
        ("POST", "/risk/seed-demo"),
    }
    assert expected <= _registered_api_routes()
    assert set(risk_api.RISK_READ_ROLES) >= {"viewer", "auditor", "analyst"}
    assert set(risk_api.RISK_RUN_ROLES) >= {"analyst", "admin", "owner"}
    assert set(risk_api.RISK_UPDATE_ROLES) >= {"admin", "owner"}
    assert "viewer" not in risk_api.RISK_RUN_ROLES
    assert "auditor" not in risk_api.RISK_RUN_ROLES
    assert "analyst" not in risk_api.RISK_UPDATE_ROLES


@pytest.mark.asyncio
async def test_seed_demo_is_idempotent_tenant_scoped_and_safe():
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "risk-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "risk-b-" + secrets.token_hex(3))
        try:
            admin_a = await _user(db, tenant_a.id, "admin", "risk-admin-a")
            admin_b = await _user(db, tenant_b.id, "admin", "risk-admin-b")
            await risk_api.seed_demo(tenant=tenant_a, db=db, current_user=admin_a)
            second = await risk_api.seed_demo(tenant=tenant_a, db=db, current_user=admin_a)
            await risk_api.seed_demo(tenant=tenant_b, db=db, current_user=admin_b)

            assert second["probe_runs_created"] == 0
            probes_a = await risk_api.list_probe_runs(tenant=tenant_a, db=db, _user=admin_a)
            probes_b = await risk_api.list_probe_runs(tenant=tenant_b, db=db, _user=admin_b)
            assert probes_a.total == 7
            assert probes_b.total == 7
            assert {item.category for item in probes_a.items} == {item.value for item in AdversarialProbeCategory}
            assert all(item.execution_mode == "simulated" for item in probes_a.items)
            assert all(item.raw_payload_stored is False for item in probes_a.items)

            vulnerabilities = await risk_api.list_vulnerabilities(tenant=tenant_a, db=db, _user=admin_a)
            assert vulnerabilities.total == 5
            assert any(item.remediation_summary for item in vulnerabilities.items)
            posture = await risk_api.get_posture(tenant=tenant_a, db=db, _user=admin_a)
            assert posture.verdict in {"needs_review", "no_go"}
            assert "auditor review required" in posture.evidence_summary.lower()
            _safe_json(probes_a)
            _safe_json(vulnerabilities)
            _safe_json(posture)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_probe_create_update_register_and_cross_tenant_blocked():
    async with AsyncSessionLocal() as db:
        tenant_a = await _tenant(db, "risk-create-a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "risk-create-b-" + secrets.token_hex(3))
        try:
            analyst_a = await _user(db, tenant_a.id, "analyst", "risk-analyst-a")
            analyst_b = await _user(db, tenant_b.id, "analyst", "risk-analyst-b")
            admin_a = await _user(db, tenant_a.id, "admin", "riskadmin-update-a")
            created = await risk_api.create_probe_run(
                AdversarialProbeRunCreate(
                    name="Credential leakage simulated probe with sanitized marker",
                    category="credential_leakage",
                    target_surface="gateway",
                    model_target="route-selected model",
                ),
                tenant=tenant_a,
                db=db,
                current_user=analyst_a,
            )
            assert created.execution_mode == "simulated"
            assert created.status == "completed"
            assert created.raw_payload_stored is False
            assert created.results
            assert all(result.raw_payload_stored is False for result in created.results)
            assert "sanitized marker" in created.name

            with pytest.raises(NotFoundException):
                await risk_api.get_probe_run(created.id, tenant=tenant_b, db=db, _user=analyst_b)

            await risk_api.seed_demo(tenant=tenant_a, db=db, current_user=analyst_a)
            vulnerabilities = await risk_api.list_vulnerabilities(tenant=tenant_a, db=db, _user=analyst_a, severity="high")
            target = vulnerabilities.items[0]
            updated = await risk_api.update_vulnerability(
                target.id,
                VulnerabilityUpdateRequest(status="remediating", remediation_summary="Evidence-supported remediation linkage created.", confidence=90),
                tenant=tenant_a,
                db=db,
                _user=admin_a,
            )
            assert updated.status == "remediating"
            assert updated.confidence == 90
            assert updated.remediation_summary == "Evidence-supported remediation linkage created."
            with pytest.raises(NotFoundException):
                await risk_api.update_vulnerability(
                    target.id,
                    VulnerabilityUpdateRequest(status="resolved"),
                    tenant=tenant_b,
                    db=db,
                    _user=analyst_b,
                )
            _safe_json(updated)
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_risk_rows_do_not_store_external_attack_payloads_or_call_external_clients():
    source = inspect.getsource(risk_red_teaming)
    forbidden_imports = ("subprocess", "boto3", "terraform", "httpx", "requests", "openai", "anthropic")
    assert not any(term in source for term in forbidden_imports)
    assert risk_red_teaming.LIVE_PROVIDER_PROBING_ENABLED is False

    async with AsyncSessionLocal() as db:
        tenant = await _tenant(db, "risk-storage-" + secrets.token_hex(3))
        try:
            admin = await _user(db, tenant.id, "admin", "risk-admin-storage")
            await risk_api.seed_demo(tenant=tenant, db=db, current_user=admin)
            await risk_red_teaming.set_tenant_context(db, tenant.id)
            probe_rows = (await db.execute(select(AdversarialProbeRun).where(AdversarialProbeRun.tenant_id == tenant.id))).scalars().all()
            result_rows = (await db.execute(select(RedTeamProbeResult).where(RedTeamProbeResult.tenant_id == tenant.id))).scalars().all()
            vulnerability_rows = (
                await db.execute(select(VulnerabilityRegisterItem).where(VulnerabilityRegisterItem.tenant_id == tenant.id))
            ).scalars().all()
            assert probe_rows
            assert result_rows
            assert vulnerability_rows
            assert all(row.raw_payload_stored is False for row in probe_rows)
            assert all(row.raw_payload_stored is False for row in result_rows)
            _safe_json(
                {
                    "probes": [
                        {
                            "preview": row.safe_prompt_preview,
                            "summary": row.result_summary,
                            "evidence": row.evidence,
                        }
                        for row in probe_rows
                    ],
                    "results": [
                        {
                            "input": row.sanitized_input_summary,
                            "output": row.sanitized_output_summary,
                            "evidence_summary": row.evidence_summary,
                        }
                        for row in result_rows
                    ],
                    "vulnerabilities": [
                        {
                            "title": row.title,
                            "description": row.description,
                            "evidence_summary": row.evidence_summary,
                            "remediation_summary": row.remediation_summary,
                        }
                        for row in vulnerability_rows
                    ],
                }
            )
        finally:
            await _cleanup(db, tenant.id)
