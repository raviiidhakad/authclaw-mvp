import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from fastapi import HTTPException
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type, RetryError
from redis.asyncio import Redis

from app.core.providers.factory import ProviderAdapterFactory
from app.core.providers.circuit_breaker import SharedCircuitBreaker, CircuitState, CircuitBreakerException
from app.models.provider import Provider

logger = logging.getLogger(__name__)


@dataclass
class ProviderResponse:
    """Typed result returned by AIProviderClient."""
    status_code: int
    body: Dict[str, Any]
    provider_name: str
    provider_type: str
    latency_ms: int

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def error_message(self) -> Optional[str]:
        err = self.body.get("error")
        if not err:
            return None
        if isinstance(err, dict):
            return err.get("message")
        return str(err)

    @property
    def error_type(self) -> Optional[str]:
        err = self.body.get("error")
        if isinstance(err, dict):
            return err.get("type")
        return None

    @property
    def error_code(self) -> Optional[str]:
        err = self.body.get("error")
        if isinstance(err, dict):
            code = err.get("code")
            if code is not None:
                return str(code)
        return None


class AIProviderClient:
    """Handles HTTP communication with upstream AI providers through adapters."""

    async def get_provider_connection_details(self, provider: Provider) -> tuple[str, Dict[str, str]]:
        adapter = ProviderAdapterFactory.get_adapter(provider.type)
        return await adapter.get_connection_details(provider)

    async def chat_completion(
        self,
        provider: Provider,
        payload: Dict[str, Any],
    ) -> ProviderResponse:
        adapter = ProviderAdapterFactory.get_adapter(provider.type)

        try:
            url, headers = await adapter.get_connection_details(provider)
        except Exception as exc:
            if isinstance(exc, HTTPException) and exc.status_code == 502:
                return ProviderResponse(
                    status_code=502,
                    body={"error": {"message": str(exc.detail), "type": "auth_error", "code": "azure_ad_unavailable"}},
                    provider_name=provider.name,
                    provider_type=provider.type.value,
                    latency_ms=0,
                )
            logger.error(
                "Failed to decrypt API key or fetch provider token.",
                extra={"provider_id": str(provider.id)},
            )
            return ProviderResponse(
                status_code=500,
                body={"error": {"message": "Gateway configuration error: cannot authenticate provider.", "type": "gateway_error", "code": "auth_failed"}},
                provider_name=provider.name,
                provider_type=provider.type.value,
                latency_ms=0,
            )

        request_payload = adapter.transform_request(payload)

        start_time = time.monotonic()
        status_code = 500
        body: Dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=request_payload, headers=headers)
                status_code = int(response.status_code)
                try:
                    raw_body = response.json()
                    if 200 <= status_code < 300:
                        body = adapter.transform_response(raw_body)
                    else:
                        body = adapter.normalize_error(status_code, response.text)
                except (ValueError, json.JSONDecodeError):
                    if 200 <= status_code < 300:
                        body = {"error": {"message": f"Provider returned non-JSON response (HTTP {status_code})", "type": "parse_error", "code": "invalid_json"}}
                    else:
                        body = adapter.normalize_error(status_code, response.text)

        except httpx.ConnectError as exc:
            status_code = 502
            body = {"error": {"message": f"Cannot connect to provider: {exc}", "type": "connection_error", "code": "bad_gateway"}}
        except httpx.ReadTimeout:
            status_code = 504
            body = {"error": {"message": "Provider read timeout.", "type": "timeout_error", "code": "read_timeout"}}
        except httpx.WriteTimeout:
            status_code = 504
            body = {"error": {"message": "Provider write timeout.", "type": "timeout_error", "code": "write_timeout"}}
        except httpx.TimeoutException:
            status_code = 504
            body = {"error": {"message": "Provider request timed out.", "type": "timeout_error", "code": "timeout"}}
        except Exception:
            logger.exception("Unexpected error calling provider %s", provider.id)
            status_code = 500
            body = {"error": {"message": "Internal gateway error while calling provider.", "type": "gateway_error", "code": "internal_error"}}

        latency_ms = int((time.monotonic() - start_time) * 1000)
        return ProviderResponse(
            status_code=status_code,
            body=body,
            provider_name=provider.name,
            provider_type=provider.type.value,
            latency_ms=latency_ms,
        )

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
