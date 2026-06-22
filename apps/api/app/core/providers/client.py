import httpx
import logging
import asyncio
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type, RetryError
from redis.asyncio import Redis

from app.core.providers.circuit_breaker import SharedCircuitBreaker, CircuitState, CircuitBreakerException

logger = logging.getLogger(__name__)

# Singleton HTTP client with connection pooling
_http_client = httpx.AsyncClient(
    limits=httpx.Limits(max_connections=500, max_keepalive_connections=100),
    timeout=httpx.Timeout(30.0)
)

class ResilientProviderClient:
    def __init__(self, provider_name: str, redis_client: Redis):
        self.provider_name = provider_name
        self.circuit_breaker = SharedCircuitBreaker(redis_client, provider_name)
        
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError))
    )
    async def _make_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        return await _http_client.request(method, url, **kwargs)

    async def execute(self, method: str, url: str, **kwargs) -> httpx.Response:
        # Check Circuit Breaker
        state = await self.circuit_breaker.get_state()
        if state == CircuitState.OPEN:
            logger.warning(f"Circuit OPEN for provider {self.provider_name}. Rejecting request.")
            raise CircuitBreakerException(f"Provider {self.provider_name} is currently unavailable.")
            
        try:
            # We enforce a strict timeout constraint to prevent thread starvation
            kwargs['timeout'] = kwargs.get('timeout', httpx.Timeout(15.0))
            
            response = await self._make_request(method, url, **kwargs)
            
            # 429 and 500+ are considered upstream failures
            if response.status_code == 429 or response.status_code >= 500:
                await self.circuit_breaker.record_failure()
            else:
                await self.circuit_breaker.record_success()
                
            return response
            
        except (httpx.RequestError, RetryError) as e:
            # Hard failures (timeouts, dns) also count against circuit breaker
            await self.circuit_breaker.record_failure()
            raise e
