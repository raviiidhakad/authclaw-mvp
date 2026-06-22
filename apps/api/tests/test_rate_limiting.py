import pytest
import uuid
from app.core.rate_limit import RateLimiter

@pytest.fixture
def rate_limiter():
    return RateLimiter()

@pytest.mark.asyncio
async def test_tenant_rate_limiting_burst(rate_limiter, monkeypatch):
    import time
    mock_time = time.time()
    monkeypatch.setattr(time, "time", lambda: mock_time)

    tenant_id = uuid.uuid4()
    key = f"rl:tnt:{tenant_id}"
    
    # Simulate a burst of exactly 100 requests (capacity)
    for _ in range(100):
        allowed = await rate_limiter.check_rate_limit(key, capacity=100, refill_rate_per_sec=10.0)
        assert allowed is True
        
    # The 101st request should fail instantly because no time has passed to refill
    allowed = await rate_limiter.check_rate_limit(key, capacity=100, refill_rate_per_sec=10.0)
    assert allowed is False

@pytest.mark.asyncio
async def test_api_key_rate_limiting(rate_limiter, monkeypatch):
    import time
    mock_time = time.time()
    monkeypatch.setattr(time, "time", lambda: mock_time)
    
    api_key_id = uuid.uuid4()
    key = f"rl:key:{api_key_id}"
    
    # Exhaust API Key capacity
    for _ in range(10):
        allowed = await rate_limiter.check_rate_limit(key, capacity=10, refill_rate_per_sec=100.0)
        assert allowed is True
        
    allowed = await rate_limiter.check_rate_limit(key, capacity=10, refill_rate_per_sec=100.0)
    assert allowed is False
