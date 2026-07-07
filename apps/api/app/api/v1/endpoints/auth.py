import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slugify import slugify

from app.api.dependencies import get_db, get_current_user
from app.core.security import (
    create_access_token,
    get_password_hash,
    protect_mfa_secret,
    reveal_mfa_secret,
    verify_password,
)
from app.core.rate_limit.limiter import rate_limiter
from app.core.exceptions import UnauthorizedException, BadRequestException
from app.models.user import User
from app.models.tenant import Tenant
from app.models.role import Role, UserRole
from app.models.token import RefreshToken
from app.schemas.auth import (
    LoginRequest,
    Token,
    UserCreate,
    UserResponse,
    RefreshRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    LoginMfaResponse,
    LoginMfaRequest,
)
from app.core.events.producer import producer
from app.schemas.events import SecurityEvent, UserEvent
import pyotp

logger = logging.getLogger(__name__)
router = APIRouter()

async def _check_auth_limit(scope: str, identifier: str, limit: int = 5, window_seconds: int = 300) -> None:
    key_hash = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    allowed = await rate_limiter.check_rate_limit(
        f"rl:auth:{scope}:{key_hash}",
        limit,
        limit / window_seconds,
        fail_open=False,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many authentication attempts. Please retry later.",
            headers={"Retry-After": str(window_seconds)},
        )

@router.post("/login", response_model=Token | LoginMfaResponse)
async def login(
    request: LoginRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    OAuth2 compatible token login, get access and refresh tokens
    """
    client_host = http_request.client.host if http_request.client else "unknown"
    await _check_auth_limit("login", f"{request.email.lower()}:{client_host}")
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalars().first()
    
    if not user or not verify_password(request.password, user.password_hash):
        if user:
            await producer.publish("authclaw.security.events", SecurityEvent(
                event_type="user.login.failed",
                tenant_id=user.tenant_id,
                actor_id=user.id,
                payload={"reason": "invalid_credentials"}
            ))
        raise UnauthorizedException(detail="Incorrect email or password")
    
    if not user.is_active:
        await producer.publish("authclaw.security.events", SecurityEvent(
            event_type="user.login.failed",
            tenant_id=user.tenant_id,
            actor_id=user.id,
            payload={"reason": "inactive_account"}
        ))
        raise UnauthorizedException(detail="Inactive user")

    # If MFA is enabled, issue a challenge token instead of access tokens
    if user.mfa_enabled:
        mfa_token = create_access_token(
            subject=str(user.id), 
            expires_delta=timedelta(minutes=5),
            token_type="mfa_challenge"
        )
        await producer.publish("authclaw.security.events", SecurityEvent(
            event_type="user.login.mfa_challenge",
            tenant_id=user.tenant_id,
            actor_id=user.id,
            payload={}
        ))
        return LoginMfaResponse(mfa_token=mfa_token).dict()

    # Generate access token
    access_token = create_access_token(subject=str(user.id))

    # Generate refresh token
    raw_refresh = secrets.token_hex(32)
    refresh_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
    family = str(secrets.token_hex(16))
    
    db_refresh = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        family=family,
        is_revoked=False,
        expires_at=datetime.utcnow() + timedelta(days=14)
    )
    db.add(db_refresh)
    
    # Update last login
    user.last_login_at = datetime.utcnow()
    
    await db.commit()

    await producer.publish("authclaw.security.events", SecurityEvent(
        event_type="user.login.success",
        tenant_id=user.tenant_id,
        actor_id=user.id,
        payload={"method": "password"}
    ))
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": raw_refresh
    }

@router.post("/login/mfa", response_model=Token)
async def login_mfa(
    request: LoginMfaRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Complete login using MFA challenge token and TOTP code.
    """
    import jwt
    from pydantic import ValidationError
    from app.core.config import settings

    try:
        payload = jwt.decode(
            request.mfa_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != "mfa_challenge":
            raise UnauthorizedException(detail="Invalid token type for MFA challenge.")
        user_id = payload.get("sub")
    except (jwt.InvalidTokenError, ValidationError):
        raise UnauthorizedException(detail="Invalid or expired MFA token")

    if not user_id:
        raise UnauthorizedException(detail="Invalid MFA token payload")

    import uuid
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise UnauthorizedException(detail="Invalid user ID format")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalars().first()

    if not user or not user.is_active or not user.mfa_enabled:
        raise UnauthorizedException(detail="User not eligible for MFA login")

    client_host = http_request.client.host if http_request.client else "unknown"
    await _check_auth_limit("login_mfa", f"{user.id}:{client_host}")

    # Verify TOTP
    totp = pyotp.TOTP(reveal_mfa_secret(user.mfa_secret))
    if not totp.verify(request.code):
        raise UnauthorizedException(detail="Invalid MFA code")

    # Issue real tokens
    access_token = create_access_token(subject=str(user.id))
    raw_refresh = secrets.token_hex(32)
    refresh_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
    family = str(secrets.token_hex(16))

    db_refresh = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        family=family,
        is_revoked=False,
        expires_at=datetime.utcnow() + timedelta(days=14)
    )
    db.add(db_refresh)
    
    user.last_login_at = datetime.utcnow()
    await db.commit()

    await producer.publish("authclaw.security.events", SecurityEvent(
        event_type="user.login.mfa_success",
        tenant_id=user.tenant_id,
        actor_id=user.id,
        payload={}
    ))

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": raw_refresh
    }


@router.post("/signup", response_model=UserResponse, status_code=201)
async def signup(
    request: UserCreate, db: AsyncSession = Depends(get_db)
) -> User:
    """
    Create new tenant and user.
    """
    # Check if user exists
    result = await db.execute(select(User).where(User.email == request.email))
    if result.scalars().first():
        raise BadRequestException(detail="A user with this email already exists.")
        
    # Create tenant
    company_name = request.company_name or f"{request.first_name}'s Organization"
    tenant_slug = slugify(company_name)
    
    # Check if tenant slug already exists
    tenant_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    if tenant_result.scalars().first():
        raise BadRequestException(detail="An organization with this name already exists. Please choose a different name.")
        
    tenant = Tenant(
        name=company_name,
        slug=tenant_slug
    )
    db.add(tenant)
    await db.flush()
    
    # Set the tenant context for RLS before inserting the user
    from sqlalchemy import text
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)").bindparams(
            tenant_id=str(tenant.id)
        )
    )

    # Create user
    user = User(
        email=request.email,
        password_hash=get_password_hash(request.password),
        first_name=request.first_name,
        last_name=request.last_name,
        tenant_id=tenant.id,
        is_active=True,
    )
    db.add(user)
    await db.flush()  # get user.id

    # Assign owner role to the first user in the new tenant
    role_result = await db.execute(select(Role).where(Role.name == "owner"))
    owner_role = role_result.scalars().first()
    if owner_role:
        user_role = UserRole(user_id=user.id, role_id=owner_role.id, tenant_id=tenant.id)
        db.add(user_role)

    await db.commit()
    
    # Re-set tenant context for the new transaction implicitly started by refresh
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)").bindparams(
            tenant_id=str(tenant.id)
        )
    )
    await db.refresh(user)

    await producer.publish("authclaw.user.events", UserEvent(
        event_type="user.created",
        tenant_id=tenant.id,
        actor_id=user.id,
        payload={"email": user.email, "method": "signup"}
    ))

    return user


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current user information.
    """
    return current_user


@router.post("/refresh", response_model=Token)
async def refresh_tokens(
    request: RefreshRequest, db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Refresh access token and rotate the refresh token
    """
    incoming_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
    
    # Query database for matching token
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == incoming_hash)
    )
    db_token = result.scalars().first()
    
    if not db_token:
        raise UnauthorizedException(detail="Invalid refresh token")
        
    # Check if token is revoked (indicates reuse/leak)
    if db_token.is_revoked:
        # Revoke all active tokens in the same family
        fam_result = await db.execute(
            select(RefreshToken).where(RefreshToken.family == db_token.family)
        )
        tokens_to_revoke = fam_result.scalars().all()
        for tok in tokens_to_revoke:
            tok.is_revoked = True
        await db.commit()
        raise UnauthorizedException(detail="Token reuse detected. All tokens revoked.")
        
    # Check expiration
    if db_token.expires_at < datetime.utcnow():
        raise UnauthorizedException(detail="Refresh token expired")
        
    # Mark old token as revoked
    db_token.is_revoked = True
    
    # Generate new pair
    access_token = create_access_token(subject=str(db_token.user_id))
    raw_refresh = secrets.token_hex(32)
    refresh_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
    
    new_db_token = RefreshToken(
        user_id=db_token.user_id,
        token_hash=refresh_hash,
        family=db_token.family,
        is_revoked=False,
        expires_at=datetime.utcnow() + timedelta(days=14)
    )
    db.add(new_db_token)
    await db.commit()
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": raw_refresh
    }


@router.post("/logout")
async def logout(
    request: RefreshRequest, db: AsyncSession = Depends(get_db)
):
    """
    Revoke current refresh token family
    """
    incoming_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == incoming_hash)
    )
    db_token = result.scalars().first()
    
    if db_token:
        # Revoke all tokens in family
        fam_result = await db.execute(
            select(RefreshToken).where(RefreshToken.family == db_token.family)
        )
        tokens_to_revoke = fam_result.scalars().all()
        for tok in tokens_to_revoke:
            tok.is_revoked = True
        await db.commit()
        
    return {"detail": "Successfully logged out"}


@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)
):
    """
    Generate password reset token and log it in development mode
    """
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalars().first()
    
    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        user.reset_token_hash = token_hash
        user.reset_token_expires_at = datetime.utcnow() + timedelta(hours=1)
        await db.commit()

        
    return {"detail": "If the email exists, a password reset link has been generated."}


@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest, db: AsyncSession = Depends(get_db)
):
    """
    Reset user password using token
    """
    incoming_hash = hashlib.sha256(request.token.encode()).hexdigest()
    result = await db.execute(
        select(User).where(
            User.reset_token_hash == incoming_hash,
            User.reset_token_expires_at > datetime.utcnow()
        )
    )
    user = result.scalars().first()
    
    if not user:
        raise BadRequestException(detail="Invalid or expired reset token")
        
    user.password_hash = get_password_hash(request.new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    await db.commit()
    
    return {"detail": "Password has been reset successfully."}

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate a new MFA secret for the current user. 
    Does NOT enable MFA until verified.
    """
    # Generate new base32 secret
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="AuthClaw"
    )
    
    # Store secret temporarily or permanently, but keep mfa_enabled=False
    current_user.mfa_secret = protect_mfa_secret(secret)
    await db.commit()
    
    return {
        "secret": secret,
        "uri": uri
    }

@router.post("/mfa/verify")
async def verify_mfa(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify the TOTP code and enable MFA for the user.
    """
    if not current_user.mfa_secret:
        raise BadRequestException(detail="MFA secret not set. Please setup MFA first.")
        
    await _check_auth_limit("mfa_verify", str(current_user.id))
    totp = pyotp.TOTP(reveal_mfa_secret(current_user.mfa_secret))
    if not totp.verify(request.code):
        raise UnauthorizedException(detail="Invalid MFA code")
        
    current_user.mfa_enabled = True
    await db.commit()
    
    return {"detail": "MFA enabled successfully."}
