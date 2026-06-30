"""SDK configuration loading and validation."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .client_contracts import (
    ApiKeyConfigurationContract,
    RetryConfigurationContract,
    SdkMetadataContract,
    TimeoutConfigurationContract,
)
from .auth import ApiKeyManager
from .exceptions import ConfigurationError


@dataclass(frozen=True, slots=True)
class AuthClawConfig:
    """Resolved SDK configuration for synchronous clients."""

    api_key: str | None
    base_url: str
    api_version: str
    timeout: TimeoutConfigurationContract
    retry: RetryConfigurationContract
    metadata: SdkMetadataContract

    @classmethod
    def from_contracts(
        cls,
        api_key: ApiKeyConfigurationContract | None = None,
        timeout: TimeoutConfigurationContract | None = None,
        retry: RetryConfigurationContract | None = None,
        metadata: SdkMetadataContract | None = None,
    ) -> "AuthClawConfig":
        api_key_contract = api_key or ApiKeyConfigurationContract()
        auth_manager = ApiKeyManager.from_contract(api_key_contract)
        resolved_key = auth_manager.api_key
        resolved_api_version = api_key_contract.api_version.strip("/")
        resolved_timeout = timeout or TimeoutConfigurationContract()
        resolved_retry = retry or RetryConfigurationContract()
        _validate_api_version(resolved_api_version)
        _validate_timeout(resolved_timeout)
        _validate_retry(resolved_retry)
        return cls(
            api_key=resolved_key,
            base_url=_normalize_base_url(api_key_contract.base_url),
            api_version=resolved_api_version,
            timeout=resolved_timeout,
            retry=resolved_retry,
            metadata=metadata or SdkMetadataContract(),
        )

    @classmethod
    def from_env(cls, env_var: str = "AUTHCLAW_API_KEY") -> "AuthClawConfig":
        return cls.from_contracts(ApiKeyConfigurationContract(api_key_env_var=env_var))

    def require_api_key(self) -> str:
        return self.auth_manager().require_api_key()

    def auth_manager(self) -> ApiKeyManager:
        return ApiKeyManager(api_key=self.api_key)

    def build_url(self, path: str) -> str:
        clean_path = path.lstrip("/")
        if clean_path.startswith(f"{self.api_version}/"):
            return f"{self.base_url}/{clean_path}"
        return f"{self.base_url}/{self.api_version}/{clean_path}"


def _normalize_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    if not normalized:
        raise ConfigurationError("AuthClaw base_url must not be empty")
    return normalized


def _validate_api_version(api_version: str) -> None:
    if not api_version:
        raise ConfigurationError("AuthClaw api_version must not be empty")


def _validate_timeout(timeout: TimeoutConfigurationContract) -> None:
    values = (
        timeout.connect_timeout_seconds,
        timeout.read_timeout_seconds,
        timeout.write_timeout_seconds,
    )
    if any(value <= 0 for value in values):
        raise ConfigurationError("AuthClaw timeout values must be positive")
    if timeout.total_timeout_seconds is not None and timeout.total_timeout_seconds <= 0:
        raise ConfigurationError("AuthClaw total_timeout_seconds must be positive")


def _validate_retry(retry: RetryConfigurationContract) -> None:
    if retry.max_attempts < 1:
        raise ConfigurationError("AuthClaw retry max_attempts must be at least 1")
    if retry.initial_delay_seconds < 0 or retry.max_delay_seconds < 0:
        raise ConfigurationError("AuthClaw retry delays must be non-negative")
    if retry.initial_delay_seconds > retry.max_delay_seconds and retry.max_delay_seconds > 0:
        raise ConfigurationError("AuthClaw retry initial delay must not exceed max delay")
