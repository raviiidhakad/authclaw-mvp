import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.core.engine.azure_auth import AzureADClient
from fastapi import HTTPException
import httpx

@pytest.fixture
def azure_client():
    return AzureADClient()

@pytest.mark.asyncio
async def test_get_cached_token_hit(azure_client):
    with patch("app.core.engine.azure_auth.RedisClient.get") as mock_get:
        mock_redis = MagicMock()
        mock_get.return_value = mock_redis
        mock_redis.get = AsyncMock(return_value="cached_token")
        
        azure_client.redis = mock_redis
        
        token = await azure_client.get_cached_token("tenant_id", "client_id", "secret")
        
        assert token == "cached_token"
        mock_redis.get.assert_called_once_with("azure:ad:token:tenant_id:client_id")

@pytest.mark.asyncio
async def test_get_cached_token_miss_fetches_new(azure_client):
    with patch("app.core.engine.azure_auth.RedisClient.get") as mock_get:
        mock_redis = MagicMock()
        mock_get.return_value = mock_redis
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock()
        
        azure_client.redis = mock_redis
        
        with patch.object(azure_client, 'get_access_token', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = "new_token"
            
            token = await azure_client.get_cached_token("tenant_id", "client_id", "secret")
            
            assert token == "new_token"
            mock_fetch.assert_called_once_with("tenant_id", "client_id", "secret")
            mock_redis.set.assert_called_once_with("azure:ad:token:tenant_id:client_id", "new_token", ex=3300)

@pytest.mark.asyncio
async def test_get_access_token_success(azure_client):
    class MockResponse:
        def __init__(self):
            self.status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"access_token": "fresh_token"}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = MockResponse()
        
        token = await azure_client.get_access_token("tenant_id", "client_id", "secret")
        assert token == "fresh_token"

@pytest.mark.asyncio
async def test_get_access_token_failure(azure_client):
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.RequestError("Failed to connect")
        
        with pytest.raises(HTTPException) as exc_info:
            await azure_client.get_access_token("tenant_id", "client_id", "secret")
            
        assert exc_info.value.status_code == 502
        assert "unreachable" in str(exc_info.value.detail)
