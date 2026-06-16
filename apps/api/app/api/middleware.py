from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from contextvars import ContextVar
import uuid

# Context variables for the current request
tenant_context: ContextVar[str] = ContextVar("tenant_context", default="")
user_context: ContextVar[str] = ContextVar("user_context", default="")
trace_context: ContextVar[str] = ContextVar("trace_context", default="")

class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # We generate a unique trace ID for each request
        trace_id = str(uuid.uuid4())
        trace_context.set(trace_id)
        request.state.trace_id = trace_id
        
        # We can extract the tenant ID if present in a custom header (e.g. X-Tenant-ID)
        # But for MVP, we'll mostly rely on the JWT token resolving to a tenant via dependencies
        tenant_id = request.headers.get("x-tenant-id", "")
        tenant_context.set(tenant_id)
        request.state.tenant_id = tenant_id

        # Proceed with the request
        response = await call_next(request)
        
        # Ensure trace ID is in the response headers
        response.headers["X-Trace-ID"] = trace_id
        
        return response
