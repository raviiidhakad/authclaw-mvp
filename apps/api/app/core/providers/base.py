import httpx
from abc import ABC, abstractmethod
from typing import Dict, Any, AsyncGenerator, Tuple
from app.models.provider import Provider

class BaseProviderAdapter(ABC):
    """
    Standard Provider Adapter Interface.
    Every provider must implement these methods.
    """

    @abstractmethod
    def validate_configuration(self, config: Dict[str, Any]) -> None:
        """Validate provider-specific JSON configuration."""
        pass

    @abstractmethod
    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        """Return the (url, headers) for the provider."""
        pass

    @abstractmethod
    def transform_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Map OpenAI-compatible Gateway payload to Provider payload."""
        pass

    @abstractmethod
    def transform_response(self, response_body: Dict[str, Any]) -> Dict[str, Any]:
        """Map Provider response to OpenAI-compatible Gateway response."""
        pass

    @abstractmethod
    async def stream_response(self, response: httpx.Response) -> AsyncGenerator[bytes, None]:
        """Handle provider-specific SSE streaming logic, yielding standard OpenAI chunks."""
        pass

    @abstractmethod
    def normalize_error(self, status_code: int, response_body: str) -> Dict[str, Any]:
        """Map Provider error response to standard AuthClaw HTTP error dict."""
        pass
