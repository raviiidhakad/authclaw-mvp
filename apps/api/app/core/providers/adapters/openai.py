import json
import httpx
from typing import Dict, Any, AsyncGenerator, Tuple
from app.models.provider import Provider
from app.models.provider import ProviderType
from app.core.providers.base import BaseProviderAdapter
from app.services.provider_credentials import retrieve_provider_api_key
from app.services.api_safety import sanitize_text

GROQ_OPENAI_BASE_URL = "https://api.groq.com/openai/v1"


def _looks_like_groq_provider(provider: Provider) -> bool:
    base_url = str((provider.config or {}).get("base_url", ""))
    return (
        provider.type == ProviderType.groq
        or "groq" in provider.name.lower()
        or "api.groq.com" in base_url.lower()
    )

class OpenAIAdapter(BaseProviderAdapter):
    def validate_configuration(self, config: Dict[str, Any]) -> None:
        pass

    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        api_key = await retrieve_provider_api_key(provider)
        url = "https://api.openai.com/v1/chat/completions"
        if provider.config and "base_url" in provider.config:
            url = provider.config["base_url"].rstrip("/") + "/chat/completions"
        elif _looks_like_groq_provider(provider):
            url = GROQ_OPENAI_BASE_URL + "/chat/completions"
            
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return url, headers

    def transform_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return payload

    def transform_response(self, response_body: Dict[str, Any]) -> Dict[str, Any]:
        return response_body

    async def stream_response(self, response: httpx.Response) -> AsyncGenerator[bytes, None]:
        async for chunk in response.aiter_lines():
            if chunk:
                yield f"{chunk}\n\n".encode("utf-8")

    def normalize_error(self, status_code: int, response_body: str) -> Dict[str, Any]:
        try:
            body = json.loads(response_body)
        except Exception:
            body = {"error": {"message": response_body}}
        if status_code == 401:
            return {
                "error": {
                    "message": "Provider authentication failed. Update the provider credential in Settings.",
                    "type": "provider_auth_error",
                    "code": "invalid_provider_credentials",
                }
            }
        return {
            "error": {
                "message": sanitize_text(body.get("error", {}).get("message", "Upstream provider error")),
                "type": body.get("error", {}).get("type", "provider_error"),
                "code": body.get("error", {}).get("code", str(status_code)),
            }
        }
