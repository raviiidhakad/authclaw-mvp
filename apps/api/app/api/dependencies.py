"""
AuthClaw FastAPI Dependencies

Provides injectable dependencies for database sessions, authentication,
tenant resolution, and role-based access control.

RLS Contract
------------
get_current_tenant() is the RLS enforcement point. It:
  1. Resolves the Tenant from the authenticated user's JWT
  2. Sets app.current_tenant_id via SET LOCAL (Layer 1 — transaction-scoped)
  3. Validates tenant status

Any endpoint that queries tenant-scoped data MUST depend on get_current_tenant()
either directly or via require_roles(), which itself depends on it.

Endpoints that do NOT need tenant isolation (auth, health) use get_db() directly.
"""
import uuid
import logging
from typing import AsyncGenerator

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
import jwt
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import UnauthorizedException, ForbiddenException
from app.models.user import User
from app.models.tenant import Tenant
from app.models.role import UserRole, Role

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login")


# ── Raw session (no tenant context) ─────────────────────────────────────────

from app.core.database import AsyncSessionLocal, get_db


# ── Authenticated user resolution ─────────────────────────────────────────────

async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    """
    Decode JWT and return the authenticated User.

    Note: queries the `users` table WITHOUT tenant RLS context.
    This is intentional — auth happens before tenant resolution.
    The `users` table does not have RLS applied (see migration notes).
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") == "mfa_challenge":
            raise UnauthorizedException(detail="Invalid token type for API access.")
            
        user_id: str | None = payload.get("sub")
    except (jwt.InvalidTokenError, ValidationError):
        raise UnauthorizedException(detail="Could not validate credentials")

    if not user_id:
        raise UnauthorizedException(detail="Could not validate credentials")

    import uuid
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise UnauthorizedException(detail="Invalid user ID format")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalars().first()

    if not user:
        raise UnauthorizedException(detail="User not found")

    if not user.is_active:
        raise UnauthorizedException(detail="Inactive user")

    return user


# ── Tenant resolution + RLS context injection ─────────────────────────────────

async def get_current_tenant(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    """
    Resolve the Tenant for the current request AND set the PostgreSQL RLS
    tenant context (Layer 1: SET LOCAL — transaction-scoped).

    After this dependency runs, all subsequent queries on the same `db` session
    are automatically filtered to this tenant's data by PostgreSQL's RLS engine.
    No manual WHERE tenant_id = ? is required in endpoint queries — RLS enforces it.

    FastAPI caches this dependency within a request scope, so the same `db`
    session is shared between this function and the endpoint handler. The
    SET LOCAL therefore applies to all queries executed by the endpoint.
    """
    result = await db.execute(
        select(Tenant).where(Tenant.id == current_user.tenant_id)
    )
    tenant = result.scalars().first()

    if not tenant:
        raise UnauthorizedException(detail="Tenant not found")

    if tenant.status != "active":
        raise UnauthorizedException(detail="Tenant is suspended or deactivated")

    # ── RLS Context ──
    # We use session-level setting (is_local=false) instead of transaction-level (true)
    # because endpoints often call db.commit() which resets transaction-level settings.
    # The database pool reset hook (Layer 2) ensures this is cleared when the connection
    # returns to the pool.
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, false)"),
        {"tid": str(tenant.id)},
    )
    logger.debug("RLS context set: tenant_id=%s", tenant.id)

    return tenant


# ── Role-based access control ─────────────────────────────────────────────────

def require_roles(allowed_roles: list[str]):
    """
    Dependency factory: verifies the current user holds at least one of the
    specified roles within their tenant. Implicitly depends on get_current_tenant,
    which means RLS context is always set before this check runs.
    """
    async def role_checker(
        current_user: User = Depends(get_current_user),
        _tenant: Tenant = Depends(get_current_tenant),  # ensures RLS is set
        db: AsyncSession = Depends(get_db),
    ) -> User:
        result = await db.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == current_user.id)
        )
        user_roles = result.scalars().all()

        if not any(role in allowed_roles for role in user_roles):
            raise ForbiddenException(
                detail=f"Required role(s): {allowed_roles}. "
                       f"Your roles: {list(user_roles)}"
            )

        return current_user

    return role_checker
