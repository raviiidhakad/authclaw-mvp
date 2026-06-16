from typing import AsyncGenerator
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
import jwt
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import UnauthorizedException, ForbiddenException
from app.models.user import User
from app.models.tenant import Tenant
from app.models.role import UserRole, Role

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login")

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session

async def get_current_user(
    db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> User:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        token_data = payload.get("sub")
    except (jwt.InvalidTokenError, ValidationError):
        raise UnauthorizedException(detail="Could not validate credentials")
    
    if not token_data:
        raise UnauthorizedException(detail="Could not validate credentials")
        
    result = await db.execute(select(User).where(User.id == token_data))
    user = result.scalars().first()
    
    if not user:
        raise UnauthorizedException(detail="User not found")
        
    if not user.is_active:
        raise UnauthorizedException(detail="Inactive user")
        
    return user

async def get_current_tenant(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalars().first()
    
    if not tenant:
        raise UnauthorizedException(detail="Tenant not found")
        
    if tenant.status != "active":
        raise UnauthorizedException(detail="Inactive tenant")
        
    return tenant

def require_roles(allowed_roles: list[str]):
    async def role_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        result = await db.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == current_user.id)
        )
        user_roles = result.scalars().all()
        
        if not any(role in allowed_roles for role in user_roles):
            raise ForbiddenException(detail="You do not have permission to perform this action")
            
        return current_user
        
    return role_checker
