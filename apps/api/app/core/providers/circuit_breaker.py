import time
from enum import Enum
from redis.asyncio import Redis

class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class SharedCircuitBreaker:
    """
    A Redis-backed circuit breaker to prevent cascading upstream failures.
    State is shared across all pods to guarantee strict failure tolerances.
    """
    def __init__(
        self, 
        redis_client: Redis, 
        provider_name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 30
    ):
        self.redis = redis_client
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.key_prefix = f"provider:circuit:{provider_name}"
        
        self.state_key = f"{self.key_prefix}:state"
        self.failures_key = f"{self.key_prefix}:failures"
        self.last_failure_key = f"{self.key_prefix}:last_failure"

    async def get_state(self) -> CircuitState:
        state_data = await self.redis.get(self.state_key)
        if not state_data:
            return CircuitState.CLOSED
            
        current_state = CircuitState(state_data.decode("utf-8"))
        
        if current_state == CircuitState.OPEN:
            last_failure = await self.redis.get(self.last_failure_key)
            if last_failure:
                time_since_failure = time.time() - float(last_failure)
                if time_since_failure >= self.recovery_timeout:
                    # Transition to HALF_OPEN
                    await self._transition_to(CircuitState.HALF_OPEN)
                    return CircuitState.HALF_OPEN
        
        return current_state

    async def record_success(self):
        """Record a successful request. Transitions HALF_OPEN to CLOSED."""
        state = await self.get_state()
        if state == CircuitState.HALF_OPEN:
            await self._transition_to(CircuitState.CLOSED)
        elif state == CircuitState.CLOSED:
            # Reset failures on success
            await self.redis.set(self.failures_key, 0)

    async def record_failure(self):
        """Record an upstream failure (429, 500, 502, 503, 504)."""
        state = await self.get_state()
        
        if state == CircuitState.HALF_OPEN:
            # Immediate failback to OPEN
            await self._transition_to(CircuitState.OPEN)
            return
            
        if state == CircuitState.CLOSED:
            failures = await self.redis.incr(self.failures_key)
            await self.redis.set(self.last_failure_key, time.time())
            
            if failures >= self.failure_threshold:
                await self._transition_to(CircuitState.OPEN)

    async def _transition_to(self, new_state: CircuitState):
        pipeline = self.redis.pipeline()
        pipeline.set(self.state_key, new_state.value)
        if new_state == CircuitState.CLOSED:
            pipeline.set(self.failures_key, 0)
        elif new_state == CircuitState.OPEN:
            pipeline.set(self.last_failure_key, time.time())
        await pipeline.execute()

class CircuitBreakerException(Exception):
    pass
