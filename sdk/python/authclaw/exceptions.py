"""AuthClaw Python SDK exception hierarchy."""

from __future__ import annotations


class AuthClawError(Exception):
    """Base class for all SDK errors."""


class AuthenticationError(AuthClawError):
    """Raised when an AuthClaw API key is absent or rejected."""


class AuthorizationError(AuthClawError):
    """Raised when a caller is authenticated but not permitted."""


class RateLimitError(AuthClawError):
    """Raised when AuthClaw or an upstream provider reports a rate limit."""


class TimeoutError(AuthClawError):
    """Raised when an SDK operation exceeds its configured timeout."""


class ValidationError(AuthClawError):
    """Raised when a request or configuration contract is invalid."""


class ConnectionError(AuthClawError):
    """Raised when the SDK cannot reach the configured AuthClaw endpoint."""


class ServerError(AuthClawError):
    """Raised when AuthClaw returns an unexpected server-side failure."""


class ConfigurationError(AuthClawError):
    """Raised when SDK configuration is incomplete or inconsistent."""


class StreamingError(AuthClawError):
    """Raised for streaming contract or stream lifecycle errors."""
