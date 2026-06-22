import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.core.rate_limit.limiter import RateLimiter, check_gateway_limits
from fastapi import HTTPException
import redis.asyncio as redis

@pytest.fixture
def rate_limiter():
    return RateLimiter()

@pytest.mark.asyncio
async def test_token_bucket_lua_script(rate_limiter):
    with patch("app.core.rate_limit.limiter.RedisClient.get") as mock_get:
        mock_redis = MagicMock()
        mock_get.return_value = mock_redis
        
        mock_script = AsyncMock(return_value=1)
        mock_redis.register_script.return_value = mock_script
        
        rate_limiter.redis = mock_redis
        
        allowed = await rate_limiter.check_rate_limit("test_key", 100, 10.0)
        
        assert allowed is True
        mock_redis.register_script.assert_called_once()
        mock_script.assert_called_once()

@pytest.mark.asyncio
async def test_token_bucket_fail_open(rate_limiter):
    with patch("app.core.rate_limit.limiter.RedisClient.get") as mock_get:
        mock_redis = MagicMock()
        mock_get.return_value = mock_redis
        
        mock_script = AsyncMock(side_effect=redis.RedisError("Connection lost"))
        mock_redis.register_script.return_value = mock_script
        
        rate_limiter.redis = mock_redis
        
        # Should return True due to fail-open
        allowed = await rate_limiter.check_rate_limit("test_key", 100, 10.0)
        
        assert allowed is True

@pytest.mark.asyncio
async def test_check_gateway_limits_success():
    with patch("app.core.rate_limit.limiter.rate_limiter.check_rate_limit", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = True
        mock_db = MagicMock()
        
        # Should not raise exception
        await check_gateway_limits("tenant_1", "key_1", mock_db, "provider_1")
        
        assert mock_check.call_count == 4

@pytest.mark.asyncio
async def test_check_gateway_limits_exceeded():
    with patch("app.core.rate_limit.limiter.rate_limiter.check_rate_limit", new_callable=AsyncMock) as mock_check:
        with patch("app.core.engine.audit.AuditEngine.log_rate_limit_exceeded", new_callable=AsyncMock) as mock_log:
            mock_check.side_effect = [True, False] # Second limit fails
            mock_db = MagicMock()
            
            with pytest.raises(HTTPException) as exc_info:
                await check_gateway_limits("tenant_1", "key_1", mock_db)
                
            assert exc_info.value.status_code == 429
            assert "Rate limit exceeded" in str(exc_info.value.detail)
            mock_log.assert_called_once()
