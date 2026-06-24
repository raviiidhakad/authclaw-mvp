from typing import Dict, Any, Tuple
from app.models.provider import Provider
from app.core.providers.adapters.openai import OpenAIAdapter
from app.services.provider_credentials import retrieve_provider_api_key

class GeminiAdapter(OpenAIAdapter):
    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        api_key = await retrieve_provider_api_key(provider)
        url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        if provider.config and "base_url" in provider.config:
            url = provider.config["base_url"].rstrip("/") + "/chat/completions"
            
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return url, headers
