from typing import Dict, Any, Tuple
from app.models.provider import Provider
from app.core.providers.adapters.openai import OpenAIAdapter
from app.services.provider_credentials import retrieve_provider_api_key

class AzureOpenAIAdapter(OpenAIAdapter):
    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        config = provider.config or {}
        auth_type = config.get("auth_type", "api_key")
        
        if auth_type == "azure_ad":
            from app.core.engine.azure_auth import azure_ad_client
            client_id = config.get("azure_client_id")
            azure_tenant_id = config.get("azure_tenant_id")
            client_secret = await retrieve_provider_api_key(provider)
            api_key = await azure_ad_client.get_cached_token(azure_tenant_id, client_id, client_secret)
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
        else:
            api_key = await retrieve_provider_api_key(provider)
            headers = {
                "api-key": api_key,
                "Content-Type": "application/json",
            }
            
        resource = config.get("azure_resource_name", "YOUR_RESOURCE")
        deployment = config.get("azure_deployment_id", "YOUR_DEPLOYMENT")
        api_version = config.get("azure_api_version", "2024-02-01")
        url = f"https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
        
        return url, headers
