"""Version metadata for the AuthClaw Python SDK."""

from __future__ import annotations

from dataclasses import asdict, dataclass


SDK_VERSION = "0.1.0"
SUPPORTED_API_VERSION = "v1"
MINIMUM_AUTHCLAW_VERSION = "0.11.0"


@dataclass(frozen=True, slots=True)
class SdkVersionContract:
    """Semantic version and compatibility metadata for the SDK package."""

    sdk_version: str = SDK_VERSION
    supported_api_version: str = SUPPORTED_API_VERSION
    minimum_authclaw_version: str = MINIMUM_AUTHCLAW_VERSION
    major: int = 0
    minor: int = 1
    patch: int = 0

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def get_version() -> SdkVersionContract:
    """Return the SDK version contract without touching runtime services."""

    return SdkVersionContract()
