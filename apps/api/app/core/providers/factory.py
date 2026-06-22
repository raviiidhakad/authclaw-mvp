from app.models.provider import ProviderType
from app.core.providers.base import BaseProviderAdapter
from app.core.providers.adapters.openai import OpenAIAdapter
from app.core.providers.adapters.azure import AzureOpenAIAdapter
from app.core.providers.adapters.gemini import GeminiAdapter
from app.core.providers.adapters.anthropic import AnthropicAdapter
from app.core.providers.adapters.cohere import CohereAdapter

class ProviderAdapterFactory:
    @staticmethod
    def get_adapter(provider_type: ProviderType) -> BaseProviderAdapter:
        if provider_type == ProviderType.openai:
            return OpenAIAdapter()
        elif provider_type == ProviderType.groq:
            return OpenAIAdapter()
        elif provider_type == ProviderType.azure_openai:
            return AzureOpenAIAdapter()
        elif provider_type == ProviderType.gemini:
            return GeminiAdapter()
        elif provider_type == ProviderType.anthropic:
            return AnthropicAdapter()
        elif provider_type == ProviderType.cohere:
            return CohereAdapter()
        else:
            # Fallback
            return OpenAIAdapter()
