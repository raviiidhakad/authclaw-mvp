"""
AuthClaw Database Engine

Provides async SQLAlchemy engine and session factory.

RLS Context Management
----------------------
PostgreSQL Row Level Security requires the session to carry a tenant-scoped
GUC (Grand Unified Configuration) variable: app.current_tenant_id.

Implementation: SET LOCAL (transaction-scoped) + pool reset hook (defense-in-depth)

  Layer 1 — SET LOCAL in get_current_tenant():
    SET LOCAL is scoped to the current transaction. When the FastAPI request
    lifecycle commits or rolls back the session, the GUC resets automatically.
    With SQLAlchemy autobegin=True this is always within a transaction.

  Layer 2 — Pool reset event hook:
    When a connection is returned to the pool, _reset_tenant_context() fires
    synchronously and issues RESET app.current_tenant_id. This is defence-in-depth:
    if a code path somehow commits without a rollback or the session is reused
    outside normal FastAPI lifecycle, stale tenant context is never carried forward.
"""
import logging
from typing import AsyncGenerator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Async engine ─────────────────────────────────────────────────────────────
import sys
from sqlalchemy.pool import NullPool

if "pytest" in sys.modules:
    engine = create_async_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,
        echo=settings.APP_DEBUG,
        future=True,
    )
else:
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        echo=settings.APP_DEBUG,
        future=True,
    )

# ── Pool-level defence-in-depth: clear tenant context on connection return ───
@event.listens_for(engine.sync_engine, "reset")
def _reset_tenant_context(
    dbapi_conn,
    connection_record,
    reset_state,
) -> None:
    """
    Defense-in-depth Layer 2: issued synchronously when connection returns to pool.

    SET LOCAL (Layer 1) already handles this within the transaction, but this hook
    guarantees a clean connection even if the session lifecycle is misused.
    Non-fatal: any error is swallowed so the pool return always succeeds.
    """
    try:
        cursor = dbapi_conn.cursor()
        cursor.execute("RESET app.current_tenant_id")
        cursor.close()
    except Exception:
        # Never prevent the connection from returning to the pool
        pass


# ── Session factory ──────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Raw database session — no tenant context set.
    Use ONLY for authentication endpoints that run before the tenant is known.
    All business-data endpoints must use get_current_tenant() which sets RLS context.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
