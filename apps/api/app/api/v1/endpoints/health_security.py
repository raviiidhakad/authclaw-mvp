"""
AuthClaw Sprint 1 — Security Pipeline Health Endpoint
------------------------------------------------------
Exposes component-level health status for the security pipeline.
Used by load balancers, monitoring systems, and operational dashboards.

GET /health/security-pipeline

Response format:
  {
    "status": "healthy" | "degraded" | "unhealthy",
    "components": {
      "presidio_pool":   { "status": "healthy", "workers": 3 },
      "policy_cache":    { "status": "healthy", "backend": "redis" },
      "feature_flags":   { "FF_SECURITY_PIPELINE": true, ... },
      "spacy_model":     { "status": "healthy", "model": "en_core_web_sm" }
    },
    "pipeline_active": true,
    "checked_at": "2026-06-20T08:00:00Z"
  }

Status logic:
  "healthy"   — all components operational
  "degraded"  — pipeline active but one non-critical component is down
  "unhealthy" — pipeline active but Presidio pool OR policy cache is down
"""
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.config import settings

router = APIRouter()


@router.get(
    "/health/security-pipeline",
    tags=["Health"],
    summary="Security Pipeline Health",
    description="Returns component-level health status for the Sprint 1 security pipeline.",
    responses={
        200: {"description": "All components healthy"},
        206: {"description": "Pipeline degraded — one or more non-critical components offline"},
        503: {"description": "Pipeline unhealthy — critical component offline"},
    },
)
async def security_pipeline_health() -> JSONResponse:
    """
    Component-level health check for the Sprint 1 security pipeline.

    Returns:
        JSON with overall status and per-component status details.
        HTTP 200 = healthy, 206 = degraded, 503 = unhealthy.
    """
    components: Dict[str, Any] = {}
    issues = []
    critical_failures = []

    # ── Feature Flags ────────────────────────────────────────────────────────
    feature_flags = {
        "FF_SECURITY_PIPELINE": settings.FF_SECURITY_PIPELINE,
        "FF_INBOUND_SCAN": settings.FF_INBOUND_SCAN,
        "FF_OUTBOUND_SCAN": settings.FF_OUTBOUND_SCAN,
        "FF_STREAM_SCAN": settings.FF_STREAM_SCAN,
        "FF_SECURITY_SHADOW_MODE": settings.FF_SECURITY_SHADOW_MODE,
    }
    components["feature_flags"] = {
        "status": "healthy",
        "flags": feature_flags,
    }
    try:
        from app.core.policy.opa_integration import opa_runtime_health

        opa_health = opa_runtime_health()
        components["opa_runtime"] = {
            "status": "healthy" if opa_health["enabled"] else "disabled",
            "policy_engine_mode": opa_health.get("policy_engine_mode"),
            "runtime_available": bool(opa_health["runtime_available"]),
            "runtime_mode": opa_health["runtime_mode"],
            "strict_mode": opa_health.get("strict_mode"),
            "fail_closed": opa_health.get("fail_closed"),
            "cache": opa_health["cache"],
            "policy_version_status": opa_health["policy_version_status"],
            "metrics": opa_health["metrics"],
        }
    except Exception:
        components["opa_runtime"] = {
            "status": "unhealthy",
            "runtime_available": False,
            "reason": "OPA runtime health check failed.",
        }
        if settings.ENABLE_OPA_RUNTIME_INTEGRATION:
            issues.append("opa_runtime_health_failed")

    pipeline_active = settings.FF_SECURITY_PIPELINE

    # ── Presidio ProcessPool ─────────────────────────────────────────────────
    if pipeline_active:
        try:
            from app.core.detection.presidio_engine import presidio_engine
            pool_healthy = presidio_engine.is_healthy()
            pool = presidio_engine._pool
            worker_count = settings.PRESIDIO_POOL_MAX_WORKERS

            if pool_healthy:
                components["presidio_pool"] = {
                    "status": "healthy",
                    "max_workers": worker_count,
                    "pool_initialized": pool is not None,
                }
            else:
                components["presidio_pool"] = {
                    "status": "unhealthy",
                    "reason": "ProcessPool is not initialized or has crashed.",
                    "max_workers": worker_count,
                }
                critical_failures.append("presidio_pool")
        except Exception as exc:
            components["presidio_pool"] = {
                "status": "unhealthy",
                "reason": str(exc),
            }
            critical_failures.append("presidio_pool")
    else:
        components["presidio_pool"] = {
            "status": "disabled",
            "reason": "FF_SECURITY_PIPELINE is False. Set FF_SECURITY_PIPELINE=true to enable.",
        }

    # ── Policy Cache (Redis) ─────────────────────────────────────────────────
    if pipeline_active:
        try:
            from app.core.policy.cache import policy_cache
            cache_healthy = policy_cache.is_healthy()

            if cache_healthy:
                # Ping Redis for live connectivity check
                try:
                    ping_ok = await policy_cache._redis.ping()
                    components["policy_cache"] = {
                        "status": "healthy",
                        "backend": "redis",
                        "key_prefix": settings.POLICY_CACHE_KEY_PREFIX,
                        "ping": "ok" if ping_ok else "failed",
                    }
                    if not ping_ok:
                        issues.append("policy_cache redis ping failed")
                except Exception as ping_exc:
                    components["policy_cache"] = {
                        "status": "degraded",
                        "backend": "redis",
                        "reason": f"Ping failed: {ping_exc}",
                    }
                    issues.append("policy_cache_ping_failed")
            else:
                components["policy_cache"] = {
                    "status": "unhealthy",
                    "reason": "Redis connection not established.",
                }
                critical_failures.append("policy_cache")
        except Exception as exc:
            components["policy_cache"] = {
                "status": "unhealthy",
                "reason": str(exc),
            }
            critical_failures.append("policy_cache")
    else:
        components["policy_cache"] = {
            "status": "disabled",
            "reason": "FF_SECURITY_PIPELINE is False.",
        }

    # ── SpaCy Model ──────────────────────────────────────────────────────────
    try:
        import spacy
        model_name = "en_core_web_sm"
        # spacy.util.is_package() correctly detects installed wheel-based models
        if spacy.util.is_package(model_name):
            components["spacy_model"] = {
                "status": "healthy",
                "model": model_name,
                "note": "Workers load this model in the ProcessPool subprocess.",
            }
        else:
            components["spacy_model"] = {
                "status": "unhealthy",
                "model": model_name,
                "reason": "Model not installed. Run: python -m spacy download en_core_web_sm",
            }
            critical_failures.append("spacy_model")

    except ImportError:
        components["spacy_model"] = {
            "status": "not_installed",
            "reason": "spacy package is not installed.",
        }
        critical_failures.append("spacy_model")

    # ── Classify overall status ───────────────────────────────────────────────
    if critical_failures and pipeline_active:
        overall_status = "unhealthy"
        http_status = 503
    elif issues and pipeline_active:
        overall_status = "degraded"
        http_status = 206
    else:
        overall_status = "healthy" if pipeline_active else "disabled"
        http_status = 200

    return JSONResponse(
        status_code=http_status,
        content={
            "status": overall_status,
            "pipeline_active": pipeline_active,
            "components": components,
            "critical_failures": critical_failures,
            "warnings": issues,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        },
    )

