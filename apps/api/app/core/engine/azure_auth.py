import logging
import httpx
from fastapi import HTTPException
from app.core.redis import RedisClient

logger = logging.getLogger(__name__)

class AzureADClient:
    def __init__(self):
        self._redis = None

    @property
    def redis(self):
        return self._redis or RedisClient.get()

    @redis.setter
    def redis(self, value):
        self._redis = value

    async def get_access_token(self, tenant_id: str, client_id: str, client_secret: str) -> str:
        """
        Fetches an OAuth2 access token from Azure AD using client credentials.
        """
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        
        # Scope for Azure OpenAI
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://cognitiveservices.azure.com/.default"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(token_url, data=data, timeout=10.0)
                response.raise_for_status()
                
                token_data = response.json()
                return token_data["access_token"]
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch Azure AD token: HTTP {e.response.status_code} - {e.response.text}")
            raise HTTPException(status_code=502, detail="Upstream Azure AD authentication failed.")
        except httpx.RequestError as e:
            logger.error(f"Network error fetching Azure AD token: {e}")
            raise HTTPException(status_code=502, detail="Upstream Azure AD is unreachable.")
        except Exception as e:
            logger.error(f"Unexpected error fetching Azure AD token: {e}")
            raise HTTPException(status_code=500, detail="Internal error authenticating with Azure AD.")

    async def get_cached_token(self, azure_tenant_id: str, client_id: str, client_secret: str) -> str:
        """
        Checks Redis for a cached token, otherwise fetches and caches a new one.
        Fail-close behavior: if Redis fails to fetch or cache, we still try to get the token,
        but if the network call fails, we bubble up the 502.
        """
        cache_key = f"azure:ad:token:{azure_tenant_id}:{client_id}"
        
        try:
            cached_token = await self.redis.get(cache_key)
            if cached_token:
                return cached_token
        except Exception as e:
            logger.warning(f"Redis cache read failed for Azure AD token: {e}")
        
        # Cache miss or Redis error, fetch new token
        token = await self.get_access_token(azure_tenant_id, client_id, client_secret)
        
        try:
            # Cache the token with 55-minute TTL (tokens usually expire in 60m)
            await self.redis.set(cache_key, token, ex=3300)
        except Exception as e:
            logger.warning(f"Redis cache write failed for Azure AD token: {e}")
            
        return token

azure_ad_client = AzureADClient()
