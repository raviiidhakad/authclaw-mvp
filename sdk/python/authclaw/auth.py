"""Authentication helpers for the AuthClaw Python SDK."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .client_contracts import ApiKeyConfigurationContract, SdkMetadataContract
from .exceptions import ConfigurationError
from .version import SDK_VERSION


@dataclass(frozen=True, slots=True)
class ApiKeyManager:
    """Resolve and render AuthClaw API key authentication."""

    api_key: str | None
    api_key_env_var: str = "AUTHCLAW_API_KEY"

    @classmethod
    def from_contract(cls, contract: ApiKeyConfigurationContract) -> "ApiKeyManager":
        api_key = contract.api_key or os.getenv(contract.api_key_env_var)
        return cls(api_key=api_key, api_key_env_var=contract.api_key_env_var)

    @classmethod
    def from_env(cls, env_var: str = "AUTHCLAW_API_KEY") -> "ApiKeyManager":
        return cls(api_key=os.getenv(env_var), api_key_env_var=env_var)

    def require_api_key(self) -> str:
        if not self.api_key:
            raise ConfigurationError("AuthClaw API key is required for this operation")
        return self.api_key

    def authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.require_api_key()}"}


def build_default_headers(
    metadata: SdkMetadataContract,
    *,
    accept: str = "application/json",
    content_type: str = "application/json",
) -> dict[str, str]:
    return {
        "Accept": accept,
        "Content-Type": content_type,
        "User-Agent": f"{metadata.user_agent_prefix}/{SDK_VERSION}",
    }


def build_authenticated_headers(
    manager: ApiKeyManager,
    metadata: SdkMetadataContract,
    *,
    accept: str = "application/json",
    content_type: str = "application/json",
) -> dict[str, str]:
    headers = build_default_headers(metadata, accept=accept, content_type=content_type)
    headers.update(manager.authorization_header())
    return headers
