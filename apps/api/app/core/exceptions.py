from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from typing import Any, Dict, Optional
import uuid

class AuthClawException(Exception):
    """Base exception for all custom AuthClaw errors."""
    def __init__(
        self,
        status_code: int,
        type_uri: str,
        title: str,
        detail: str,
        instance: Optional[str] = None
    ):
        self.status_code = status_code
        self.type_uri = type_uri
        self.title = title
        self.detail = detail
        self.instance = instance

class ValidationException(AuthClawException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=422,
            type_uri="https://authclaw.io/errors/validation",
            title="Validation Error",
            detail=detail
        )

class BadRequestException(AuthClawException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(
            status_code=400,
            type_uri="https://authclaw.io/errors/bad-request",
            title="Bad Request",
            detail=detail
        )

class NotFoundException(AuthClawException):
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            status_code=404,
            type_uri="https://authclaw.io/errors/not-found",
            title="Not Found",
            detail=detail
        )

class UnauthorizedException(AuthClawException):
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(
            status_code=401,
            type_uri="https://authclaw.io/errors/unauthorized",
            title="Unauthorized",
            detail=detail
        )

class ForbiddenException(AuthClawException):
    def __init__(self, detail: str = "Permission denied"):
        super().__init__(
            status_code=403,
            type_uri="https://authclaw.io/errors/forbidden",
            title="Forbidden",
            detail=detail
        )

class ConflictException(AuthClawException):
    def __init__(self, detail: str = "Resource conflict"):
        super().__init__(
            status_code=409,
            type_uri="https://authclaw.io/errors/conflict",
            title="Conflict",
            detail=detail
        )

class RateLimitException(AuthClawException):
    def __init__(self, detail: str = "Too many requests", retry_after: int = 60):
        super().__init__(
            status_code=429,
            type_uri="https://authclaw.io/errors/rate-limit",
            title="Too Many Requests",
            detail=detail
        )
        self.retry_after = retry_after

async def custom_exception_handler(request: Request, exc: AuthClawException) -> JSONResponse:
    """Handles custom AuthClaw exceptions and formats them as RFC 7807 Problem Details."""
    headers = {}
    if isinstance(exc, RateLimitException):
        headers["Retry-After"] = str(exc.retry_after)

    payload = {
        "type": exc.type_uri,
        "title": exc.title,
        "status": exc.status_code,
        "detail": exc.detail,
        "instance": exc.instance or request.url.path,
        "trace_id": str(uuid.uuid4()) # In reality, get from context var
    }
    return JSONResponse(status_code=exc.status_code, content=payload, headers=headers)

async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Formats Pydantic validation errors as RFC 7807 Problem Details."""
    detail = []
    for error in exc.errors():
        loc = ".".join([str(x) for x in error.get("loc", [])])
        msg = error.get("msg", "")
        detail.append(f"{loc}: {msg}")
    
    payload = {
        "type": "https://authclaw.io/errors/validation",
        "title": "Validation Error",
        "status": 422,
        "detail": "; ".join(detail),
        "instance": request.url.path,
        "trace_id": str(uuid.uuid4())
    }
    return JSONResponse(status_code=422, content=payload)

async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Fallback for standard FastAPI HTTPExceptions."""
    payload = {
        "type": f"https://authclaw.io/errors/http-{exc.status_code}",
        "title": "HTTP Error",
        "status": exc.status_code,
        "detail": str(exc.detail),
        "instance": request.url.path,
        "trace_id": str(uuid.uuid4())
    }
    return JSONResponse(status_code=exc.status_code, content=payload)

def setup_exception_handlers(app):
    """Registers exception handlers on the FastAPI app."""
    app.add_exception_handler(AuthClawException, custom_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
