from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping


@dataclass(frozen=True)
class TenantPlanLimits:
    plan_name: str
    requests_per_minute: int
    requests_per_day: int
    api_key_requests_per_minute: int
    route_model_requests_per_minute: int
    provider_requests_per_minute: int
    concurrent_gateway_requests: int
    concurrent_streams: int
    max_body_bytes: int
    connector_scan_concurrency: int
    connector_scan_interval_seconds: int
    report_generation_per_hour: int
    remediation_job_concurrency: int


PLAN_LIMITS: dict[str, TenantPlanLimits] = {
    "free": TenantPlanLimits(
        plan_name="free",
        requests_per_minute=60,
        requests_per_day=1_000,
        api_key_requests_per_minute=30,
        route_model_requests_per_minute=30,
        provider_requests_per_minute=60,
        concurrent_gateway_requests=5,
        concurrent_streams=1,
        max_body_bytes=32 * 1024,
        connector_scan_concurrency=1,
        connector_scan_interval_seconds=60 * 60,
        report_generation_per_hour=5,
        remediation_job_concurrency=1,
    ),
    "team": TenantPlanLimits(
        plan_name="team",
        requests_per_minute=600,
        requests_per_day=10_000,
        api_key_requests_per_minute=300,
        route_model_requests_per_minute=300,
        provider_requests_per_minute=600,
        concurrent_gateway_requests=25,
        concurrent_streams=5,
        max_body_bytes=128 * 1024,
        connector_scan_concurrency=2,
        connector_scan_interval_seconds=15 * 60,
        report_generation_per_hour=30,
        remediation_job_concurrency=2,
    ),
    "enterprise": TenantPlanLimits(
        plan_name="enterprise",
        requests_per_minute=6_000,
        requests_per_day=250_000,
        api_key_requests_per_minute=3_000,
        route_model_requests_per_minute=3_000,
        provider_requests_per_minute=6_000,
        concurrent_gateway_requests=250,
        concurrent_streams=50,
        max_body_bytes=512 * 1024,
        connector_scan_concurrency=10,
        connector_scan_interval_seconds=5 * 60,
        report_generation_per_hour=250,
        remediation_job_concurrency=10,
    ),
    "internal": TenantPlanLimits(
        plan_name="internal",
        requests_per_minute=20_000,
        requests_per_day=1_000_000,
        api_key_requests_per_minute=10_000,
        route_model_requests_per_minute=10_000,
        provider_requests_per_minute=20_000,
        concurrent_gateway_requests=500,
        concurrent_streams=100,
        max_body_bytes=1024 * 1024,
        connector_scan_concurrency=25,
        connector_scan_interval_seconds=60,
        report_generation_per_hour=1_000,
        remediation_job_concurrency=25,
    ),
    "demo": TenantPlanLimits(
        plan_name="demo",
        requests_per_minute=1_000,
        requests_per_day=25_000,
        api_key_requests_per_minute=500,
        route_model_requests_per_minute=500,
        provider_requests_per_minute=1_000,
        concurrent_gateway_requests=50,
        concurrent_streams=10,
        max_body_bytes=256 * 1024,
        connector_scan_concurrency=3,
        connector_scan_interval_seconds=10 * 60,
        report_generation_per_hour=50,
        remediation_job_concurrency=3,
    ),
}

PLAN_ALIASES = {
    "starter": "team",
    "professional": "team",
    "pro": "team",
}


def canonical_plan_name(plan: Any, tenant_settings: Mapping[str, Any] | None = None) -> str:
    configured = None
    if tenant_settings:
        configured = tenant_settings.get("plan") or tenant_settings.get("tier")
    raw = str(configured or getattr(plan, "value", plan) or "free").strip().lower()
    return PLAN_ALIASES.get(raw, raw if raw in PLAN_LIMITS else "free")


def plan_limits_for(plan: Any, tenant_settings: Mapping[str, Any] | None = None) -> TenantPlanLimits:
    plan_name = canonical_plan_name(plan, tenant_settings)
    limits = PLAN_LIMITS[plan_name]
    overrides = (tenant_settings or {}).get("rate_limits") if tenant_settings else None
    if not isinstance(overrides, Mapping):
        return limits

    allowed_fields = {
        field
        for field in TenantPlanLimits.__dataclass_fields__
        if field != "plan_name"
    }
    sanitized: dict[str, int] = {}
    for key, value in overrides.items():
        if key not in allowed_fields:
            continue
        try:
            sanitized[key] = max(1, int(value))
        except (TypeError, ValueError):
            continue
    return replace(limits, **sanitized) if sanitized else limits
