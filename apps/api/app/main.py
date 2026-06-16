from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.exceptions import setup_exception_handlers
from app.api.v1.api import api_router
from app.api.middleware import TenantContextMiddleware

# Setup structured logging
setup_logging()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AuthClaw MVP API",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
)

# Add Custom Middleware
app.add_middleware(TenantContextMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers
setup_exception_handlers(app)

app.include_router(api_router, prefix=settings.API_PREFIX)

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV
    }

# Placeholders for future routers (will be added in later days)
# from app.routes import auth, tenants, users, providers, policies, gateway, audit, compliance, settings_route
# app.include_router(auth.router, prefix=f"{settings.API_PREFIX}/auth", tags=["Auth"])
# app.include_router(tenants.router, prefix=f"{settings.API_PREFIX}/tenants", tags=["Tenants"])
