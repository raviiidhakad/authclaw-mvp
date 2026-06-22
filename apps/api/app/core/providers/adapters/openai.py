import json
import httpx
from typing import Dict, Any, AsyncGenerator, Tuple
from app.models.provider import Provider
from app.core.providers.base import BaseProviderAdapter
from app.core.encryption import decrypt_value

class OpenAIAdapter(BaseProviderAdapter):
    def validate_configuration(self, config: Dict[str, Any]) -> None:
        pass

    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        api_key = decrypt_value(provider.api_key_encrypted)
        url = "https://api.openai.com/v1/chat/completions"
        if provider.config and "base_url" in provider.config:
            url = provider.config["base_url"].rstrip("/") + "/chat/completions"
            
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
        return {
            "error": {
                "message": body.get("error", {}).get("message", "Upstream provider error"),
                "type": body.get("error", {}).get("type", "provider_error"),
                "code": body.get("error", {}).get("code", str(status_code)),
            }
        }
