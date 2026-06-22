from typing import Dict, Any, Tuple
from app.models.provider import Provider
from app.core.providers.adapters.openai import OpenAIAdapter
from app.core.encryption import decrypt_value

class GeminiAdapter(OpenAIAdapter):
    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        api_key = decrypt_value(provider.api_key_encrypted)
        url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        if provider.config and "base_url" in provider.config:
            url = provider.config["base_url"].rstrip("/") + "/chat/completions"
            
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return url, headers
