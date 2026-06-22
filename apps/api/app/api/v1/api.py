from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, providers, policies, gateway, gateway_routes,
    audit, settings, tenants, users, api_keys, compliance,
    agent, approvals, oidc, health_security, integrations, findings,
    remediation,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(oidc.router, prefix="/auth/oidc", tags=["SSO Authentication"])
api_router.include_router(settings.router, prefix="/settings", tags=["Settings"])
api_router.include_router(providers.router, prefix="/providers", tags=["Providers"])
api_router.include_router(policies.router, prefix="/policies", tags=["Policies"])
api_router.include_router(gateway.router, prefix="/gateway", tags=["AI Gateway"])
api_router.include_router(gateway_routes.router, prefix="/gateway-routes", tags=["Gateway Routes"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Logs"])
api_router.include_router(tenants.router, prefix="/tenants", tags=["Tenants"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["API Keys"])
api_router.include_router(compliance.router, prefix="/compliance", tags=["Compliance"])
api_router.include_router(agent.router, prefix="/ai", tags=["AI Assistant"])
api_router.include_router(approvals.router, prefix="/approvals", tags=["Approvals"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["Cloud Integrations"])
api_router.include_router(findings.router, prefix="/findings", tags=["Security Findings"])
api_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"])
# Sprint 1: Security pipeline health endpoint (no auth required — used by load balancers)
api_router.include_router(health_security.router, prefix="", tags=["Health"])
