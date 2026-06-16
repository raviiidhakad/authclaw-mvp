import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.models.tenant import Tenant
from app.models.user import User
from app.models.compliance import ComplianceScore, ComplianceFramework
from app.core.engine.compliance import ComplianceRuleChecker

router = APIRouter()


@router.get("/scores")
async def get_compliance_scores(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the latest compliance scores for all frameworks.
    """
    scores = {}
    for framework in ["gdpr", "hipaa", "soc2"]:
        result = await db.execute(
            select(ComplianceScore)
            .where(
                ComplianceScore.tenant_id == tenant.id,
                ComplianceScore.framework == framework,
            )
            .order_by(desc(ComplianceScore.calculated_at))
            .limit(1)
        )
        score_record = result.scalars().first()
        if score_record:
            scores[framework] = {
                "score": score_record.score,
                "critical_violations": score_record.critical_violations,
                "policy_failures": score_record.policy_failures,
                "security_findings": score_record.security_findings,
                "breakdown": score_record.breakdown,
                "calculated_at": score_record.calculated_at.isoformat(),
            }
        else:
            scores[framework] = None

    return scores


@router.get("/scores/{framework}")
async def get_compliance_score_by_framework(
    framework: str,
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the latest compliance score for a specific framework.
    """
    result = await db.execute(
        select(ComplianceScore)
        .where(
            ComplianceScore.tenant_id == tenant.id,
            ComplianceScore.framework == framework,
        )
        .order_by(desc(ComplianceScore.calculated_at))
        .limit(1)
    )
    score_record = result.scalars().first()
    if score_record:
        return {
            "framework": framework,
            "score": score_record.score,
            "critical_violations": score_record.critical_violations,
            "policy_failures": score_record.policy_failures,
            "security_findings": score_record.security_findings,
            "breakdown": score_record.breakdown,
            "calculated_at": score_record.calculated_at.isoformat(),
        }
    return {"framework": framework, "score": None, "message": "No score calculated yet."}


@router.post("/scores/calculate")
async def calculate_compliance_scores(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Calculate and persist compliance scores for all frameworks.
    """
    checker = ComplianceRuleChecker(db, tenant.id)
    results = await checker.calculate_all()

    persisted = {}
    for framework_name, result_data in results.items():
        score_record = ComplianceScore(
            tenant_id=tenant.id,
            framework=framework_name,
            score=result_data["score"],
            critical_violations=result_data["critical_violations_30d"],
            policy_failures=result_data["violations_30d"],
            security_findings=sum(1 for v in result_data["checks"].values() if not v),
            breakdown=result_data["checks"],
            calculated_at=datetime.utcnow(),
        )
        db.add(score_record)
        persisted[framework_name] = {
            "score": result_data["score"],
            "checks": result_data["checks"],
            "violations_30d": result_data["violations_30d"],
            "critical_violations_30d": result_data["critical_violations_30d"],
        }

    await db.commit()
    return persisted


@router.get("/scores/history")
async def get_compliance_history(
    framework: str = Query("gdpr"),
    limit: int = Query(30, ge=1, le=365),
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical compliance scores for a framework.
    """
    result = await db.execute(
        select(ComplianceScore)
        .where(
            ComplianceScore.tenant_id == tenant.id,
            ComplianceScore.framework == framework,
        )
        .order_by(desc(ComplianceScore.calculated_at))
        .limit(limit)
    )
    scores = result.scalars().all()

    return [{
        "score": s.score,
        "critical_violations": s.critical_violations,
        "policy_failures": s.policy_failures,
        "security_findings": s.security_findings,
        "breakdown": s.breakdown,
        "calculated_at": s.calculated_at.isoformat(),
    } for s in scores]


@router.get("/dashboard")
async def get_compliance_dashboard(
    tenant: Tenant = Depends(get_current_tenant),
    _=Depends(require_roles(["owner", "admin", "auditor", "analyst", "viewer"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a combined compliance dashboard view with latest scores for all frameworks.
    """
    dashboard = {}
    for framework in ["gdpr", "hipaa", "soc2"]:
        result = await db.execute(
            select(ComplianceScore)
            .where(
                ComplianceScore.tenant_id == tenant.id,
                ComplianceScore.framework == framework,
            )
            .order_by(desc(ComplianceScore.calculated_at))
            .limit(1)
        )
        latest = result.scalars().first()
        if latest:
            dashboard[framework] = {
                "score": latest.score,
                "status": "compliant" if latest.score >= 80 else "at_risk" if latest.score >= 50 else "non_compliant",
                "critical_violations": latest.critical_violations,
                "last_calculated": latest.calculated_at.isoformat(),
            }
        else:
            dashboard[framework] = {
                "score": None,
                "status": "not_calculated",
                "critical_violations": 0,
                "last_calculated": None,
            }

    return dashboard
