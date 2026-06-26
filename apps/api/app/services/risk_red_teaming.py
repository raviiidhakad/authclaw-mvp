from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.remediation import RemediationPlan
from app.models.risk import (
    AdversarialProbeCategory,
    AdversarialProbeRun,
    AdversarialProbeStatus,
    GoNoGoVerdict,
    RiskPostureSnapshot,
    VulnerabilityRegisterItem,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.services.api_safety import sanitize_text
from app.services.trust_reporting import ExportSanitizer


RISK_READ_ROLES = ["owner", "admin", "operator", "analyst", "auditor", "viewer", "security_admin"]
RISK_WRITE_ROLES = ["owner", "admin", "operator", "analyst", "security_admin"]
SAFE_EXECUTION_MODE = "simulated"

sanitizer = ExportSanitizer()


DEMO_PROBES: tuple[dict[str, Any], ...] = (
    {
        "name": "Prompt injection guardrail probe",
        "category": AdversarialProbeCategory.prompt_injection,
        "risk_score": 72,
        "blocked_count": 9,
        "allowed_count": 1,
        "vulnerability_count": 1,
        "summary": "Simulated prompt-injection checks found one needs-review bypass pattern. No raw probe payload was stored.",
    },
    {
        "name": "Data disclosure boundary probe",
        "category": AdversarialProbeCategory.data_disclosure,
        "risk_score": 58,
        "blocked_count": 7,
        "allowed_count": 2,
        "vulnerability_count": 1,
        "summary": "Synthetic data-disclosure checks showed evidence-supported exposure risk in one response path.",
    },
    {
        "name": "Credential leakage probe",
        "category": AdversarialProbeCategory.credential_leakage,
        "risk_score": 84,
        "blocked_count": 11,
        "allowed_count": 0,
        "vulnerability_count": 1,
        "summary": "Credential marker tests were blocked. A high-risk rotation follow-up remains linked to remediation evidence.",
    },
    {
        "name": "Harmful content refusal probe",
        "category": AdversarialProbeCategory.harmful_content,
        "risk_score": 32,
        "blocked_count": 6,
        "allowed_count": 0,
        "vulnerability_count": 0,
        "summary": "Simulated harmful-content checks stayed within policy. No external attack execution occurred.",
    },
    {
        "name": "Sycophancy and policy-bypass probe",
        "category": AdversarialProbeCategory.sycophancy_policy_bypass,
        "risk_score": 49,
        "blocked_count": 5,
        "allowed_count": 1,
        "vulnerability_count": 1,
        "summary": "Policy-bypass simulation detected one medium severity needs-review pattern.",
    },
)


DEMO_VULNERABILITIES: tuple[dict[str, Any], ...] = (
    {
        "category": AdversarialProbeCategory.prompt_injection,
        "title": "Indirect instruction override needs review",
        "description": "A synthetic probe indicated a route could over-weight untrusted instructions without source confidence checks.",
        "severity": VulnerabilitySeverity.high,
        "status": VulnerabilityStatus.open,
        "evidence_summary": "Evidence-supported finding from simulated prompt-injection probe; raw prompt removed.",
        "remediation_summary": "Strengthen instruction hierarchy and attach remediation plan before broader rollout.",
    },
    {
        "category": AdversarialProbeCategory.data_disclosure,
        "title": "Sensitive context minimization gap",
        "description": "A synthetic disclosure probe found that unnecessary context could be included in safe summaries.",
        "severity": VulnerabilitySeverity.medium,
        "status": VulnerabilityStatus.triaged,
        "evidence_summary": "Mapped to sanitized response preview and redaction summary only.",
        "remediation_summary": "Reduce context scope and verify response previews stay sanitized.",
    },
    {
        "category": AdversarialProbeCategory.credential_leakage,
        "title": "Credential marker handling requires owner review",
        "description": "Simulated credential-like markers were blocked, but rotation guidance should be reviewed before production onboarding.",
        "severity": VulnerabilitySeverity.critical,
        "status": VulnerabilityStatus.remediating,
        "evidence_summary": "Synthetic token markers only; no real credential or Vault reference stored.",
        "remediation_summary": "Evidence-supported remediation linkage should confirm rotation and outbound filtering.",
    },
    {
        "category": AdversarialProbeCategory.sycophancy_policy_bypass,
        "title": "Policy-bypass phrasing has residual risk",
        "description": "A simulated persuasion-style request reached a needs-review response path.",
        "severity": VulnerabilitySeverity.medium,
        "status": VulnerabilityStatus.open,
        "evidence_summary": "Safe aggregate from sycophancy probe; no raw provider output retained.",
        "remediation_summary": "Add regression test cases for policy-bypass phrasing.",
    },
)


async def set_tenant_context(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})


def sanitize(value: Any) -> Any:
    return sanitizer.sanitize(value)


def _safe_text(value: object) -> str:
    return str(sanitize(sanitize_text(value)))


def _enum_value(value: object) -> str:
    return getattr(value, "value", str(value))


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def seed_risk_demo_data(db: AsyncSession, tenant_id: uuid.UUID, owner_user_id: uuid.UUID | None = None) -> dict[str, int]:
    await set_tenant_context(db, tenant_id)
    existing = (
        await db.execute(
            select(AdversarialProbeRun).where(
                AdversarialProbeRun.tenant_id == tenant_id,
                AdversarialProbeRun.name.in_([item["name"] for item in DEMO_PROBES]),
            )
        )
    ).scalars().all()
    by_name = {item.name: item for item in existing}
    now = _now_naive()
    created_runs = 0
    for item in DEMO_PROBES:
        if item["name"] in by_name:
            continue
        run = AdversarialProbeRun(
            tenant_id=tenant_id,
            name=item["name"],
            category=item["category"],
            status=AdversarialProbeStatus.completed,
            target_surface="gateway",
            model_target="route-selected model",
            execution_mode=SAFE_EXECUTION_MODE,
            owner_user_id=owner_user_id,
            started_at=now,
            completed_at=now,
            safe_prompt_preview=f"Sanitized simulated {item['category'].value.replace('_', ' ')} probe preview; raw payload removed.",
            result_summary=_safe_text(item["summary"]),
            risk_score=item["risk_score"],
            probes_total=item["blocked_count"] + item["allowed_count"],
            blocked_count=item["blocked_count"],
            allowed_count=item["allowed_count"],
            vulnerability_count=item["vulnerability_count"],
            evidence={
                "source": "safe_demo_seed",
                "execution_mode": SAFE_EXECUTION_MODE,
                "raw_payload_stored": False,
                "redaction": "sanitized aggregate only",
            },
            raw_payload_stored=False,
        )
        db.add(run)
        created_runs += 1
    await db.flush()

    runs = (
        await db.execute(
            select(AdversarialProbeRun).where(
                AdversarialProbeRun.tenant_id == tenant_id,
                AdversarialProbeRun.name.in_([item["name"] for item in DEMO_PROBES]),
            )
        )
    ).scalars().all()
    run_by_category = {run.category: run for run in runs}
    remediation_plan_id = await _optional_remediation_plan_id(db, tenant_id)

    existing_titles = set(
        (
            await db.execute(
                select(VulnerabilityRegisterItem.title).where(
                    VulnerabilityRegisterItem.tenant_id == tenant_id,
                    VulnerabilityRegisterItem.title.in_([item["title"] for item in DEMO_VULNERABILITIES]),
                )
            )
        ).scalars().all()
    )
    created_vulnerabilities = 0
    for item in DEMO_VULNERABILITIES:
        if item["title"] in existing_titles:
            continue
        category = item["category"]
        vulnerability = VulnerabilityRegisterItem(
            tenant_id=tenant_id,
            probe_run_id=getattr(run_by_category.get(category), "id", None),
            remediation_plan_id=remediation_plan_id,
            category=category,
            title=_safe_text(item["title"]),
            description=_safe_text(item["description"]),
            severity=item["severity"],
            status=item["status"],
            owner_user_id=owner_user_id,
            evidence_summary=_safe_text(item["evidence_summary"]),
            remediation_summary=_safe_text(item["remediation_summary"]),
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(vulnerability)
        created_vulnerabilities += 1

    await db.flush()
    posture = await compute_posture(db, tenant_id, persist=True)
    await db.commit()
    return {
        "probe_runs_created": created_runs,
        "vulnerabilities_created": created_vulnerabilities,
        "posture_snapshots_created": 1 if posture else 0,
    }


async def compute_posture(db: AsyncSession, tenant_id: uuid.UUID, *, persist: bool = False) -> RiskPostureSnapshot:
    await set_tenant_context(db, tenant_id)
    vulnerabilities = (
        await db.execute(select(VulnerabilityRegisterItem).where(VulnerabilityRegisterItem.tenant_id == tenant_id))
    ).scalars().all()
    probe_runs = (
        await db.execute(select(AdversarialProbeRun).where(AdversarialProbeRun.tenant_id == tenant_id))
    ).scalars().all()

    severity_counts = Counter(_enum_value(item.severity) for item in vulnerabilities)
    status_counts = Counter(_enum_value(item.status) for item in vulnerabilities)
    category_counts = Counter(_enum_value(item.category) for item in vulnerabilities)
    open_items = [item for item in vulnerabilities if item.status in {VulnerabilityStatus.open, VulnerabilityStatus.triaged, VulnerabilityStatus.remediating}]
    open_critical = [item for item in open_items if item.severity == VulnerabilitySeverity.critical]
    open_high = [item for item in open_items if item.severity == VulnerabilitySeverity.high]

    if open_critical:
        verdict = GoNoGoVerdict.no_go
        summary = "Evidence-supported go/no-go posture is no-go until critical red-team risk is reviewed."
    elif open_high or open_items:
        verdict = GoNoGoVerdict.needs_review
        summary = "Evidence-supported go/no-go posture needs review before production expansion."
    else:
        verdict = GoNoGoVerdict.go
        summary = "Evidence-supported go/no-go posture is go for the currently simulated scope."

    blockers = [
        {
            "id": str(item.id),
            "severity": _enum_value(item.severity),
            "status": _enum_value(item.status),
            "title": _safe_text(item.title),
        }
        for item in sorted(open_critical + open_high, key=lambda row: row.created_at, reverse=True)
    ]
    recommendations = [
        "Keep probe execution simulated by default unless an explicit internal test harness is approved.",
        "Link high and critical vulnerabilities to evidence-supported remediation before go-live.",
        "Review policy-bypass and disclosure probes after provider route changes.",
    ]
    counts = {
        "probe_runs": len(probe_runs),
        "vulnerabilities": len(vulnerabilities),
        "open_items": len(open_items),
        "open_high": len(open_high),
        "open_critical": len(open_critical),
        "by_severity": dict(severity_counts),
        "by_status": dict(status_counts),
        "by_category": dict(category_counts),
        "probe_categories_covered": sorted({_enum_value(item.category) for item in probe_runs}),
    }
    snapshot = RiskPostureSnapshot(
        tenant_id=tenant_id,
        verdict=verdict,
        summary=_safe_text(summary),
        counts=sanitize(counts),
        blockers=sanitize(blockers),
        recommendations=sanitize(recommendations),
        evidence_summary="Posture derived from sanitized simulated probe runs and vulnerability register rows; not legal advice.",
        generated_at=_now_naive(),
    )
    if persist:
        db.add(snapshot)
        await db.flush()
    return snapshot


async def latest_or_computed_posture(db: AsyncSession, tenant_id: uuid.UUID) -> RiskPostureSnapshot:
    await set_tenant_context(db, tenant_id)
    latest = (
        await db.execute(
            select(RiskPostureSnapshot)
            .where(RiskPostureSnapshot.tenant_id == tenant_id)
            .order_by(desc(RiskPostureSnapshot.generated_at))
            .limit(1)
        )
    ).scalars().first()
    return latest or await compute_posture(db, tenant_id, persist=False)


async def create_simulated_probe_run(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    name: str,
    category: AdversarialProbeCategory,
    target_surface: str,
    model_target: str | None,
    owner_user_id: uuid.UUID | None,
) -> AdversarialProbeRun:
    await set_tenant_context(db, tenant_id)
    now = _now_naive()
    run = AdversarialProbeRun(
        tenant_id=tenant_id,
        name=_safe_text(name),
        category=category,
        status=AdversarialProbeStatus.completed,
        target_surface=_safe_text(target_surface),
        model_target=_safe_text(model_target) if model_target else None,
        execution_mode=SAFE_EXECUTION_MODE,
        owner_user_id=owner_user_id,
        started_at=now,
        completed_at=now,
        safe_prompt_preview=f"Simulated {category.value.replace('_', ' ')} probe; raw payload removed.",
        result_summary="Simulated probe completed without external attack execution. Review linked vulnerability register for evidence-supported follow-up.",
        risk_score=40,
        probes_total=3,
        blocked_count=2,
        allowed_count=1,
        vulnerability_count=0,
        evidence={
            "source": "manual_simulated_probe",
            "execution_mode": SAFE_EXECUTION_MODE,
            "raw_payload_stored": False,
        },
        raw_payload_stored=False,
    )
    db.add(run)
    await db.flush()
    await compute_posture(db, tenant_id, persist=True)
    await db.commit()
    await set_tenant_context(db, tenant_id)
    await db.refresh(run)
    return run


async def _optional_remediation_plan_id(db: AsyncSession, tenant_id: uuid.UUID) -> uuid.UUID | None:
    plan = (
        await db.execute(
            select(RemediationPlan.id).where(RemediationPlan.tenant_id == tenant_id).order_by(desc(RemediationPlan.created_at)).limit(1)
        )
    ).scalars().first()
    return plan


def safe_model_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = sanitizer.sanitize_payload(value)
    payload.pop("sanitization_version", None)
    return payload
