from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import redis.asyncio as redis
from fastapi import HTTPException

from app.core.exceptions import RateLimitException
from app.core.engine.streaming import StreamingEngine
from app.core.rate_limit.limiter import check_gateway_limits
from app.core.rate_limit.plans import plan_limits_for
from app.core.rate_limit.tenant_limiter import LimitDecision, TenantPlanLimiter
from app.services.trust_reporting import ReportGenerationRequest, ReportGenerationService
from app.workers.connector_worker import ConnectorWorker
from app.models.integration import CloudProvider, IntegrationStatus


class FakeRedis:
    def __init__(self):
        self.values: dict[str, int | str] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    async def decr(self, key):
        self.values[key] = int(self.values.get(key, 0)) - 1
        return self.values[key]

    async def delete(self, key):
        self.values.pop(key, None)
        return 1

    async def expire(self, key, ttl):
        self.ttls[key] = ttl
        return True

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        self.ttls[key] = ex
        return True


class FailingRedis(FakeRedis):
    async def incr(self, key):
        raise redis.RedisError("redis down")


class FakeDb:
    def __init__(self, tenant=None):
        self.tenant = tenant
        self.execute = AsyncMock(return_value=SimpleNamespace(
            scalars=lambda: SimpleNamespace(first=lambda: self.tenant)
        ))
        self.flush = AsyncMock()


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


def test_tenant_plan_limits_are_tiered_and_alias_existing_db_plans():
    free = plan_limits_for("free")
    team = plan_limits_for("team")
    enterprise = plan_limits_for("enterprise")
    internal = plan_limits_for("internal")
    demo = plan_limits_for("demo")
    starter = plan_limits_for("starter")

    assert free.requests_per_minute < team.requests_per_minute < enterprise.requests_per_minute
    assert demo.concurrent_streams >= team.concurrent_streams
    assert internal.requests_per_day > enterprise.requests_per_day
    assert starter.plan_name == "team"


@pytest.mark.asyncio
async def test_gateway_api_key_rate_limit_is_safe_and_audited():
    with patch("app.core.rate_limit.limiter.rate_limiter.check_rate_limit", new_callable=AsyncMock) as mock_check:
        with patch("app.core.engine.audit.AuditEngine.log_rate_limit_exceeded", new_callable=AsyncMock) as mock_log:
            mock_check.side_effect = [True, True, False]

            with pytest.raises(HTTPException) as exc:
                await check_gateway_limits(str(uuid.uuid4()), str(uuid.uuid4()), FakeDb())

            assert exc.value.status_code == 429
            assert exc.value.detail == "Rate limit exceeded. Please retry later."
            assert exc.value.headers["X-RateLimit-Scope"] == "api_key_minute"
            assert "rl:" not in exc.value.detail
            mock_log.assert_awaited_once()


@pytest.mark.asyncio
async def test_gateway_route_provider_limits_happen_before_provider_egress():
    with patch("app.core.rate_limit.limiter.rate_limiter.check_rate_limit", new_callable=AsyncMock) as mock_check:
        mock_check.side_effect = [False]

        with pytest.raises(HTTPException) as exc:
            await check_gateway_limits(
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                FakeDb(),
                provider_id=str(uuid.uuid4()),
                route_id=str(uuid.uuid4()),
                model="llama-3.3-70b-versatile",
                include_base=False,
            )

        assert exc.value.status_code == 429
        assert exc.value.headers["X-RateLimit-Scope"] == "provider_minute"
        assert mock_check.await_count == 1


@pytest.mark.asyncio
async def test_rate_limit_store_unavailable_fails_closed_for_gateway():
    with patch("app.core.rate_limit.limiter.rate_limiter.check_rate_limit", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = False

        with pytest.raises(HTTPException) as exc:
            await check_gateway_limits(str(uuid.uuid4()), str(uuid.uuid4()), FakeDb())

        assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_tenant_limiter_is_tenant_isolated_and_releases_concurrency():
    limiter = TenantPlanLimiter(redis_client=FakeRedis())
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    a = await limiter.acquire_remediation_job(FakeDb(), tenant_a)
    b = await limiter.acquire_remediation_job(FakeDb(), tenant_b)

    assert a.allowed is True
    assert b.allowed is True
    assert f"rl:active:remediation:{tenant_a}" in limiter.redis.values
    assert f"rl:active:remediation:{tenant_b}" in limiter.redis.values

    await limiter.release_remediation_job(tenant_a)
    assert f"rl:active:remediation:{tenant_a}" not in limiter.redis.values


@pytest.mark.asyncio
async def test_destructive_limiter_fails_closed_when_redis_unavailable():
    limiter = TenantPlanLimiter(redis_client=FailingRedis())

    decision = await limiter.acquire_remediation_job(FakeDb(), uuid.uuid4())

    assert decision.allowed is False
    assert decision.scope == "remediation_job_concurrency"


class FakeStreamLimiter:
    def __init__(self):
        self.released = 0

    async def acquire_stream(self, db, tenant_id, api_key_id):
        return LimitDecision(True, "stream_concurrency", "free")

    async def release_stream(self, tenant_id, api_key_id):
        self.released += 1


class FakeAuditEngine:
    def __init__(self):
        self.failed = []

    async def publish_stream_failed(self, **kwargs):
        self.failed.append(kwargs)

    async def publish_stream_started(self, **kwargs):
        pass

    async def publish_stream_completed(self, **kwargs):
        pass


class FakeAdapter:
    def transform_request(self, payload):
        return payload

    async def stream_response(self, response):
        yield b"data: [DONE]\n\n"


class BrokenAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, *args, **kwargs):
        raise RuntimeError("provider unavailable")


@pytest.mark.asyncio
async def test_streaming_failure_releases_active_quota(monkeypatch):
    limiter = FakeStreamLimiter()
    engine = StreamingEngine(FakeAuditEngine(), rate_limiter=limiter)
    monkeypatch.setattr("app.core.engine.streaming.httpx.AsyncClient", BrokenAsyncClient)

    response = await engine.stream_response(
        tenant_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
        provider_id=uuid.uuid4(),
        url="https://provider.example.test",
        headers={},
        payload={"messages": [{"role": "user", "content": "hello"}]},
        provider_name="mock",
        adapter=FakeAdapter(),
    )
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)

    assert limiter.released == 1
    assert any("Gateway streaming failed safely" in str(chunk) for chunk in chunks)


class DenyConnectorLimiter:
    async def acquire_connector_scan(self, db, tenant_id, provider, integration_id):
        return LimitDecision(False, "connector_scan_concurrency", "free")

    async def release_connector_scan(self, tenant_id):
        raise AssertionError("release should not run when acquire is denied")


class FakeConnectorRedis:
    def __init__(self):
        self.values = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def eval(self, script, numkeys, key, owner):
        self.values.pop(key, None)
        return 1


@pytest.mark.asyncio
async def test_connector_scan_throttled_after_duplicate_lock(monkeypatch):
    monkeypatch.setattr("app.workers.connector_worker.settings.FF_USE_REAL_CONNECTORS", True)
    with patch.object(ConnectorWorker, "_load_connector_modules", lambda self: None):
        producer = FakeProducer()
        worker = ConnectorWorker(
            redis_client=FakeConnectorRedis(),
            registry=SimpleNamespace(),
            credential_service=SimpleNamespace(),
            inventory_service=SimpleNamespace(),
            raw_store=SimpleNamespace(),
            event_producer=producer,
            rate_limiter=DenyConnectorLimiter(),
        )
    integration = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        provider_type=CloudProvider.github,
        status=IntegrationStatus.active,
    )

    result = await worker.scan_integration_loaded(FakeDb(), integration)

    assert result.status == "skipped_connector_scan_concurrency"
    assert producer.events[-1][1]["error_code"] == "connector_scan_concurrency"


class DenyReportLimiter:
    async def check_report_generation(self, db, tenant_id):
        return LimitDecision(False, "report_generation", "free", retry_after=120)


@pytest.mark.asyncio
async def test_report_generation_throttled_before_run_creation():
    producer = FakeProducer()
    service = ReportGenerationService(FakeDb(), event_producer=producer, rate_limiter=DenyReportLimiter())

    with pytest.raises(RateLimitException) as exc:
        await service.generate_report(
            uuid.uuid4(),
            ReportGenerationRequest(
                report_type="trust_overview",
                requested_by=uuid.uuid4(),
                filters={},
            ),
        )

    assert exc.value.status_code == 429
    assert exc.value.detail == "Rate limit exceeded. Please retry later."
    assert producer.events[-1][1]["event_type"] == "report_generation.rate_limited"
