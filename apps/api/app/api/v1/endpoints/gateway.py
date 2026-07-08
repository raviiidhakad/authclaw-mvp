import hashlib
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Request, Header, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from fastapi.responses import JSONResponse

from app.api.dependencies import get_db, get_current_tenant, require_roles
from app.core.exceptions import UnauthorizedException, NotFoundException
from app.models.api_key import ApiKey, ApiKeyScope
from app.models.tenant import Tenant
from app.models.user import User
from app.models.gateway import GatewayRequest, RequestStatus
from app.core.engine.gateway import GatewayService
from app.schemas.gateway import GatewayRequestListResponse, GatewayRequestDetail
from app.services.api_safety import sanitize_text, sanitize_trace_text as _sanitize_trace_text

router = APIRouter()

def _extract_gateway_token(authorization: str | None, x_api_key: str | None) -> str:
    token = (x_api_key or "").strip()
    if token:
        return token
    auth_header = (authorization or "").strip()
    scheme, _, value = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise UnauthorizedException(detail="Missing or invalid gateway API key header")
    return value.strip()

async def verify_api_key(
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> ApiKey:
    """Verifies an AuthClaw gateway API key from Authorization or X-API-Key."""
    token = _extract_gateway_token(authorization, x_api_key)
    
    # Hash the incoming key and compare to stored hash
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # ENTERPRISE SECURITY FIX:
    # api_keys is protected by RLS. Since gateway auth runs before tenant context is known,
    # we use a SECURITY DEFINER function to bypass RLS securely for this specific lookup.
    from sqlalchemy import text
    stmt = select(ApiKey).from_statement(text("SELECT * FROM gateway_lookup_api_key(:hash)")).params(hash=token_hash)
    result = await db.execute(stmt)
    api_key = result.scalars().first()
    
    if not api_key:
        raise UnauthorizedException(detail="Invalid API Key")

    if api_key.scope == ApiKeyScope.read_only:
        raise UnauthorizedException(detail="API key is not allowed to call the gateway")
    
    # BUG-03 FIX: Check key expiry
    if api_key.expires_at is not None and api_key.expires_at < datetime.utcnow():
        raise UnauthorizedException(detail="API Key has expired")

    # Update last_used_at (best-effort)
    # We must briefly set the tenant context to allow the UPDATE to pass RLS,
    # but we use transaction-local setting (is_local=true) so it clears on commit.
    try:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(api_key.tenant_id)}
        )
        api_key.last_used_at = datetime.utcnow()
        await db.commit()
    except Exception:
        await db.rollback()
        
    return api_key



from app.core.rate_limit.limiter import check_gateway_limits

async def rate_limit_dependency(api_key: ApiKey = Depends(verify_api_key), db: AsyncSession = Depends(get_db)) -> ApiKey:
    """Enforces global, tenant, and api key rate limits."""
    await check_gateway_limits(str(api_key.tenant_id), str(api_key.id), db)
    return api_key

@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    api_key: ApiKey = Depends(rate_limit_dependency),
    db: AsyncSession = Depends(get_db)
):
    """
    OpenAI-compatible chat completions endpoint.
    Intercepts the request, runs policies, and forwards to the upstream provider.
    """
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": {"message": "Invalid JSON payload"}})
        
    try:
        gateway_service = GatewayService(db)
        
        # Enable RLS context for this tenant
        from sqlalchemy import text
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, false)"),
            {"tid": str(api_key.tenant_id)},
        )
        
        result = await gateway_service.process_chat_request(
            tenant_id=api_key.tenant_id,
            user_id=api_key.user_id,
            api_key_id=api_key.id,
            payload=payload
        )
        
        status_code = result.get("status_code", 200)
        if "response" in result:
            return result["response"]
            
        data = result.get("data", {})
        return JSONResponse(status_code=status_code, content=data)
    except Exception:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "message": "Gateway request failed before completion.",
                    "type": "gateway_error",
                    "code": "gateway_request_failed",
                }
            },
        )


@router.get("/requests", response_model=GatewayRequestListResponse)
async def list_gateway_requests(
    skip: int = 0,
    limit: int = 50,
    status: RequestStatus | None = Query(None),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "analyst", "auditor", "viewer"]))
):
    """
    List all gateway requests for the current tenant with optional status filter.
    """
    base = select(GatewayRequest).where(GatewayRequest.tenant_id == tenant.id)
    if status:
        base = base.where(GatewayRequest.status == status)
    
    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0
    
    items_q = base.order_by(GatewayRequest.created_at.desc()).offset(skip).limit(limit)
    items = (await db.execute(items_q)).scalars().all()
    for item in items:
        if item.error_message:
            item.error_message = sanitize_text(item.error_message)
    
    return GatewayRequestListResponse(items=items, total=total)


@router.get("/requests/{request_id}", response_model=GatewayRequestDetail)
async def get_gateway_request(
    request_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_roles(["owner", "admin", "analyst", "auditor", "viewer"]))
):
    """
    Get detailed information about a specific gateway request, including response and violations.
    """
    result = await db.execute(
        select(GatewayRequest)
        .options(
            selectinload(GatewayRequest.response),
            selectinload(GatewayRequest.violations)
        )
        .where(GatewayRequest.id == request_id, GatewayRequest.tenant_id == tenant.id)
    )
    gw_request = result.scalars().first()
    
    if not gw_request:
        raise NotFoundException(detail="Gateway request not found")
        
    prompt_preview = _sanitize_trace_text(gw_request.prompt_redacted or gw_request.prompt_original)
    original_preview = _sanitize_trace_text(gw_request.prompt_original)
    response_text = None
    if gw_request.response:
        response_text = gw_request.response.response_redacted or gw_request.response.response_original

    detail = GatewayRequestDetail.model_validate(gw_request)
    detail.prompt_original = original_preview
    detail.prompt_redacted = prompt_preview if prompt_preview != original_preview else None
    detail.request_payload = {"messages": [{"role": "user", "content": original_preview}]}
    if detail.prompt_redacted:
        detail.modified_payload = {"messages": [{"role": "user", "content": prompt_preview}]}
    if response_text:
        detail.response_payload = {"message": _sanitize_trace_text(response_text)}

    return detail
