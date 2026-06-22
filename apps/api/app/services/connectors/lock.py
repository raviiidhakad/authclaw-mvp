"""
Redis distributed lock for connector scans.

Uses SET NX EX for acquisition and an owner-token Lua script for release. This
prevents one worker replica from deleting another replica's lock after expiry
and reacquisition.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field


RELEASE_IF_OWNER_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
end
return 0
"""


@dataclass
class RedisIntegrationLock:
    redis: object
    integration_id: uuid.UUID
    ttl_seconds: int
    owner_token: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def key(self) -> str:
        return f"lock:integration_sync:{self.integration_id}"

    async def acquire(self) -> bool:
        acquired = await self.redis.set(
            self.key,
            self.owner_token,
            nx=True,
            ex=self.ttl_seconds,
        )
        return bool(acquired)

    async def release(self) -> bool:
        released = await self.redis.eval(
            RELEASE_IF_OWNER_SCRIPT,
            1,
            self.key,
            self.owner_token,
        )
        return bool(released)

