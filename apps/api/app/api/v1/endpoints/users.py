import uuid
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.dependencies import get_db, get_current_tenant, get_current_user, require_roles
from app.core.exceptions import NotFoundException, BadRequestException, ForbiddenException
from app.core.security import get_password_hash
from app.models.user import User
from app.models.tenant import Tenant
from app.models.role import Role, UserRole
from app.schemas.user import UserCreateAdmin, UserUpdate, RoleAssign, UserResponseWithRoles

router = APIRouter()

async def _get_user_with_roles(user: User, tenant_id: uuid.UUID, db: AsyncSession) -> UserResponseWithRoles:
    result = await db.execute(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user.id, UserRole.tenant_id == tenant_id)
    )
    roles = list(result.scalars().all())
    
    response = UserResponseWithRoles.model_validate(user)
    response.roles = roles
    return response


@router.get("", response_model=List[UserResponseWithRoles])
async def list_users(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"]))
):
    """
    List all users in the current tenant.
    """
    result = await db.execute(
        select(User).where(User.tenant_id == tenant.id).order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    
    response_list = []
    for user in users:
        formatted = await _get_user_with_roles(user, tenant.id, db)
        response_list.append(formatted)
        
    return response_list


@router.post("", response_model=UserResponseWithRoles, status_code=201)
async def create_user(
    body: UserCreateAdmin,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin"]))
):
    """
    Create a new user within the current tenant and assign them a role.
    """
    # Check if user email already exists
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalars().first():
        raise BadRequestException(detail="A user with this email already exists.")
        
    # Find the role
    role_result = await db.execute(select(Role).where(Role.name == body.role_name))
    role = role_result.scalars().first()
    if not role:
        raise BadRequestException(detail=f"Role '{body.role_name}' does not exist.")
        
    # Create user
    user = User(
        email=body.email,
        password_hash=get_password_hash(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        tenant_id=tenant.id,
        is_active=True
    )
    db.add(user)
    await db.flush()
    
    # Assign role
    user_role = UserRole(
        user_id=user.id,
        role_id=role.id,
        tenant_id=tenant.id
    )
    db.add(user_role)
    
    await db.flush()
    await db.refresh(user)
    await db.commit()
    
    return await _get_user_with_roles(user, tenant.id, db)


@router.get("/{user_id}", response_model=UserResponseWithRoles)
async def get_user(
    user_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific user. Users can access their own profile; owner/admin can access any.
    """
    if current_user.id != user_id:
        # Check permissions
        # Require roles owner/admin to view other users
        result = await db.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == current_user.id, UserRole.tenant_id == tenant.id)
        )
        user_roles = result.scalars().all()
        if not any(role in ["owner", "admin"] for role in user_roles):
            raise ForbiddenException(detail="You do not have permission to view this user")
            
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant.id)
    )
    user = result.scalars().first()
    if not user:
        raise NotFoundException(detail="User not found")
        
    return await _get_user_with_roles(user, tenant.id, db)


@router.patch("/{user_id}", response_model=UserResponseWithRoles)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update details of a user. Users can edit their own profile; owner/admin can edit any.
    """
    if current_user.id != user_id:
        result = await db.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == current_user.id, UserRole.tenant_id == tenant.id)
        )
        user_roles = result.scalars().all()
        if not any(role in ["owner", "admin"] for role in user_roles):
            raise ForbiddenException(detail="You do not have permission to update this user")
            
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant.id)
    )
    user = result.scalars().first()
    if not user:
        raise NotFoundException(detail="User not found")
        
    if body.email is not None:
        user.email = body.email
    if body.first_name is not None:
        user.first_name = body.first_name
    if body.last_name is not None:
        user.last_name = body.last_name
    if body.is_active is not None:
        user.is_active = body.is_active
        
    await db.flush()
    await db.refresh(user)
    await db.commit()
    
    return await _get_user_with_roles(user, tenant.id, db)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _check_role: User = Depends(require_roles(["owner", "admin"]))
):
    """
    Delete a user from the tenant. Owner/admin only. Cannot delete yourself.
    """
    if current_user.id == user_id:
        raise BadRequestException(detail="You cannot delete your own user account.")
        
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant.id)
    )
    user = result.scalars().first()
    if not user:
        raise NotFoundException(detail="User not found")
        
    await db.delete(user)
    await db.commit()


@router.put("/{user_id}/roles", response_model=UserResponseWithRoles)
async def assign_user_roles(
    user_id: uuid.UUID,
    body: RoleAssign,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _check_role: User = Depends(require_roles(["owner", "admin"]))
):
    """
    Assign roles to a user. Overwrites existing roles. Owner/admin only.
    """
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == tenant.id)
    )
    user = result.scalars().first()
    if not user:
        raise NotFoundException(detail="User not found")
        
    # Resolve role IDs
    role_result = await db.execute(
        select(Role).where(Role.name.in_(body.roles))
    )
    roles = role_result.scalars().all()
    if len(roles) != len(body.roles):
        raise BadRequestException(detail="One or more specified roles do not exist.")
        
    # Delete existing roles
    delete_result = await db.execute(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.tenant_id == tenant.id)
    )
    existing_user_roles = delete_result.scalars().all()
    for ur in existing_user_roles:
        await db.delete(ur)
        
    await db.flush()
    
    # Add new roles
    for role in roles:
        ur = UserRole(
            user_id=user.id,
            role_id=role.id,
            tenant_id=tenant.id
        )
        db.add(ur)
        
    await db.flush()
    await db.refresh(user)
    await db.commit()
    
    return await _get_user_with_roles(user, tenant.id, db)
