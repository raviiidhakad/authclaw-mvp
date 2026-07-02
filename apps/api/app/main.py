from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.exceptions import setup_exception_handlers
from app.api.v1.api import api_router
from app.api.openai_compat import router as openai_compat_router
from app.api.middleware import TenantContextMiddleware

# Setup structured logging
setup_logging()

from contextlib import asynccontextmanager
from app.core.events.producer import producer
from app.workers.audit_worker import AuditWorker
from app.workers.security_worker import SecurityWorker

# Sprint 1: Security pipeline singletons
from app.core.detection.presidio_engine import presidio_engine
from app.core.policy.cache import policy_cache


audit_worker = AuditWorker()
security_worker = SecurityWorker()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await producer.start()
    await audit_worker.start()
    await security_worker.start()
    # Sprint 1: Start security pipeline services (guarded by feature flag)
    if settings.FF_SECURITY_PIPELINE:
        await policy_cache.start()
        await presidio_engine.start()
    yield
    # Shutdown
    if settings.FF_SECURITY_PIPELINE:
        await presidio_engine.stop()
        await policy_cache.stop()
    await security_worker.stop()
    await audit_worker.stop()
    await producer.stop()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AuthClaw MVP API",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    lifespan=lifespan,
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
app.include_router(openai_compat_router, prefix="/v1", tags=["OpenAI-Compatible Gateway"])

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV
    }

