"""
AuthClaw Sprint 2 — Connector Registry Tests
---------------------------------------------
Tests for:
  - RawFindingData DTO construction
  - BaseConnector.make_dedup_hash() determinism and format
  - BaseConnector._normalize_severity() mappings + fail-safe
  - ConnectorRegistry.register() decorator
  - ConnectorRegistry.create() validation
  - ConnectorRegistry.circuit_breaker_status()
  - CircuitBreaker state machine: CLOSED → OPEN → HALF_OPEN → CLOSED
  - CircuitBreaker.call() rejects when OPEN
  - async_retry: success on first attempt, retry on transient error,
    raise after max retries, RateLimitError sleep, reraise_types bypass
  - with_scan_timeout: raises TimeoutError when exceeded
"""
from __future__ import annotations

import asyncio
import uuid
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.services.connectors.base import BaseConnector, RawFindingData
from app.services.connectors.registry import ConnectorRegistry
from app.services.connectors.resiliency import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    RateLimitError,
    RetryConfig,
    async_retry,
    with_scan_timeout,
)


# ── Helpers & Fixtures ─────────────────────────────────────────────────────────

def _make_integration(
    provider: CloudProvider = CloudProvider.aws,
    status: IntegrationStatus = IntegrationStatus.active,
) -> CloudIntegration:
    """Build a mock CloudIntegration ORM object."""
    integration = MagicMock(spec=CloudIntegration)
    integration.id = uuid.uuid4()
    integration.tenant_id = uuid.uuid4()
    integration.target_identifier = "123456789012"
    integration.provider_type = provider
    integration.status = status
    return integration


class _ConcreteConnector(BaseConnector):
    """Minimal concrete connector for testing BaseConnector methods."""
    PROVIDER = CloudProvider.aws

    async def validate_credentials(self) -> None:
        pass

    async def fetch_findings(self) -> List[RawFindingData]:
        return []


@pytest.fixture(autouse=True)
def reset_registry():
    """Ensure each test starts with a clean registry."""
    ConnectorRegistry._reset_for_testing()
    yield
    ConnectorRegistry._reset_for_testing()


@pytest.fixture
def integration():
    return _make_integration()


@pytest.fixture
def connector(integration):
    return _ConcreteConnector(integration=integration, credentials={})


# ── RawFindingData ─────────────────────────────────────────────────────────────

class TestRawFindingData:
    def test_required_fields_only(self):
        f = RawFindingData(
            external_id="alert-1",
            resource_id="arn:aws:s3:::my-bucket",
            title="Public S3 Bucket",
            severity=FindingSeverity.high,
        )
        assert f.external_id == "alert-1"
        assert f.description is None
        assert f.raw_payload == {}

    def test_all_fields(self):
        f = RawFindingData(
            external_id="eid",
            resource_id="rid",
            title="T",
            severity=FindingSeverity.critical,
            description="desc",
            remediation_instructions="fix it",
            raw_payload={"key": "val"},
        )
        assert f.raw_payload == {"key": "val"}
        assert f.remediation_instructions == "fix it"


# ── BaseConnector utilities ────────────────────────────────────────────────────

class TestMakeDedupHash:
    def test_returns_64_hex_chars(self, connector):
        h = connector.make_dedup_hash("ext-001", "arn:aws:s3:::bucket")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic_same_inputs(self, connector):
        h1 = connector.make_dedup_hash("ext-001", "res-001")
        h2 = connector.make_dedup_hash("ext-001", "res-001")
        assert h1 == h2

    def test_different_external_id_gives_different_hash(self, connector):
        h1 = connector.make_dedup_hash("ext-001", "res-001")
        h2 = connector.make_dedup_hash("ext-002", "res-001")
        assert h1 != h2

    def test_different_resource_id_gives_different_hash(self, connector):
        h1 = connector.make_dedup_hash("ext-001", "res-001")
        h2 = connector.make_dedup_hash("ext-001", "res-002")
        assert h1 != h2

    def test_different_integration_gives_different_hash(self):
        """Two integrations with identical external/resource IDs must have different hashes."""
        i1 = _make_integration()
        i2 = _make_integration()
        c1 = _ConcreteConnector(i1, {})
        c2 = _ConcreteConnector(i2, {})
        assert c1.make_dedup_hash("ext", "res") != c2.make_dedup_hash("ext", "res")


class TestNormalizeSeverity:
    @pytest.mark.parametrize("raw,expected", [
        ("critical",     FindingSeverity.critical),
        ("CRITICAL",     FindingSeverity.critical),
        ("high",         FindingSeverity.high),
        ("HIGH",         FindingSeverity.high),
        ("medium",       FindingSeverity.medium),
        ("MEDIUM",       FindingSeverity.medium),
        ("warning",      FindingSeverity.medium),
        ("WARNING",      FindingSeverity.medium),
        ("low",          FindingSeverity.low),
        ("LOW",          FindingSeverity.low),
        ("informational",FindingSeverity.low),
        ("INFORMATIONAL",FindingSeverity.low),
        ("note",         FindingSeverity.low),
        ("NOTE",         FindingSeverity.low),
    ])
    def test_known_values(self, connector, raw, expected):
        assert connector._normalize_severity(raw) == expected

    def test_unknown_value_defaults_to_critical_failsafe(self, connector):
        """Unknown severity must default to CRITICAL — fail-safe by design."""
        result = connector._normalize_severity("BANANA")
        assert result == FindingSeverity.critical

    def test_empty_string_defaults_to_critical(self, connector):
        result = connector._normalize_severity("")
        assert result == FindingSeverity.critical


# ── ConnectorRegistry ──────────────────────────────────────────────────────────

class TestConnectorRegistryRegister:
    def test_register_succeeds(self):
        @ConnectorRegistry.register
        class _A(BaseConnector):
            PROVIDER = CloudProvider.aws
            async def validate_credentials(self): pass
            async def fetch_findings(self): return []

        assert CloudProvider.aws in ConnectorRegistry._connectors

    def test_registered_providers_list(self):
        @ConnectorRegistry.register
        class _B(BaseConnector):
            PROVIDER = CloudProvider.github
            async def validate_credentials(self): pass
            async def fetch_findings(self): return []

        assert "github" in ConnectorRegistry.registered_providers()

    def test_duplicate_registration_raises(self):
        @ConnectorRegistry.register
        class _C(BaseConnector):
            PROVIDER = CloudProvider.gcp
            async def validate_credentials(self): pass
            async def fetch_findings(self): return []

        with pytest.raises(ValueError, match="already registered"):
            @ConnectorRegistry.register
            class _D(BaseConnector):
                PROVIDER = CloudProvider.gcp
                async def validate_credentials(self): pass
                async def fetch_findings(self): return []

    def test_non_base_connector_raises(self):
        with pytest.raises(TypeError, match="must inherit from BaseConnector"):
            @ConnectorRegistry.register
            class _NotAConnector:
                PROVIDER = CloudProvider.aws

    def test_missing_provider_raises(self):
        with pytest.raises(AttributeError, match="must define the PROVIDER"):
            @ConnectorRegistry.register
            class _NoProv(BaseConnector):
                async def validate_credentials(self): pass
                async def fetch_findings(self): return []


class TestConnectorRegistryCreate:
    def _register_aws(self):
        @ConnectorRegistry.register
        class _Aws(BaseConnector):
            PROVIDER = CloudProvider.aws
            async def validate_credentials(self): pass
            async def fetch_findings(self): return []
        return _Aws

    def test_create_returns_correct_type(self):
        cls = self._register_aws()
        integration = _make_integration(CloudProvider.aws)
        conn = ConnectorRegistry.create(integration, {"key": "val"})
        assert isinstance(conn, cls)

    def test_create_disabled_raises(self):
        self._register_aws()
        integration = _make_integration(
            CloudProvider.aws, status=IntegrationStatus.disabled
        )
        with pytest.raises(ValueError, match="DISABLED"):
            ConnectorRegistry.create(integration, {})

    def test_create_unregistered_provider_raises(self):
        # Only aws registered; request github
        self._register_aws()
        integration = _make_integration(CloudProvider.github)
        with pytest.raises(ValueError, match="No connector registered"):
            ConnectorRegistry.create(integration, {})

    def test_circuit_breaker_created_on_access(self):
        self._register_aws()
        integration = _make_integration(CloudProvider.aws)
        ConnectorRegistry.create(integration, {})
        # Verify circuit breaker is lazily created when accessed
        cb = ConnectorRegistry.get_circuit_breaker(CloudProvider.aws)
        assert cb.state == CircuitState.CLOSED


# ── CircuitBreaker ─────────────────────────────────────────────────────────────

class TestCircuitBreaker:
    @pytest.fixture
    def cb(self):
        return CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1)

    @pytest.mark.asyncio
    async def test_starts_closed(self, cb):
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_successful_call_stays_closed(self, cb):
        result = await cb.call(AsyncMock(return_value=42))
        assert result == 42
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_opens_after_failure_threshold(self, cb):
        failing = AsyncMock(side_effect=RuntimeError("cloud error"))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failing)
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_open_circuit_rejects_calls(self, cb):
        failing = AsyncMock(side_effect=RuntimeError("cloud error"))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failing)

        probe = AsyncMock(return_value=99)
        with pytest.raises(CircuitOpenError):
            await cb.call(probe)
        probe.assert_not_called()

    @pytest.mark.asyncio
    async def test_transitions_to_half_open_after_timeout(self, cb):
        failing = AsyncMock(side_effect=RuntimeError("err"))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failing)

        assert cb.state == CircuitState.OPEN
        # Wait for recovery_timeout (1 second in fixture)
        await asyncio.sleep(1.1)

        # Next call should be allowed as HALF_OPEN probe
        success = AsyncMock(return_value="ok")
        result = await cb.call(success)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_probe_failure_returns_to_open(self, cb):
        failing = AsyncMock(side_effect=RuntimeError("err"))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failing)

        await asyncio.sleep(1.1)

        # Probe fails — should return to OPEN
        with pytest.raises(RuntimeError):
            await cb.call(AsyncMock(side_effect=RuntimeError("still failing")))
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_reset_restores_closed_state(self, cb):
        failing = AsyncMock(side_effect=RuntimeError("err"))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failing)
        assert cb.state == CircuitState.OPEN
        await cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_status_dict_structure(self, cb):
        status = cb.status_dict()
        assert "state" in status
        assert "failure_count" in status
        assert "failure_threshold" in status
        assert "recovery_timeout_seconds" in status


# ── async_retry ────────────────────────────────────────────────────────────────

class TestAsyncRetry:
    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self):
        fn = AsyncMock(return_value="result")
        result = await async_retry(fn, config=RetryConfig(max_retries=3))
        assert result == "result"
        fn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_retries_on_transient_error_then_succeeds(self):
        fn = AsyncMock(side_effect=[RuntimeError("blip"), "ok"])
        result = await async_retry(
            fn,
            config=RetryConfig(max_retries=3, base_delay=0.01),
        )
        assert result == "ok"
        assert fn.await_count == 2

    @pytest.mark.asyncio
    async def test_raises_after_max_retries_exhausted(self):
        fn = AsyncMock(side_effect=RuntimeError("always fails"))
        with pytest.raises(RuntimeError, match="always fails"):
            await async_retry(
                fn,
                config=RetryConfig(max_retries=2, base_delay=0.01),
            )
        assert fn.await_count == 3  # 1 initial + 2 retries

    @pytest.mark.asyncio
    async def test_reraise_types_bypass_retry(self):
        fn = AsyncMock(side_effect=PermissionError("denied"))
        with pytest.raises(PermissionError):
            await async_retry(
                fn,
                config=RetryConfig(max_retries=3, base_delay=0.01),
                reraise_types=(PermissionError,),
            )
        fn.assert_awaited_once()  # No retry on PermissionError

    @pytest.mark.asyncio
    async def test_rate_limit_error_sleeps_retry_after(self):
        fn = AsyncMock(side_effect=[RateLimitError(retry_after=0), "ok"])
        with patch("app.services.connectors.resiliency.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await async_retry(fn, config=RetryConfig(max_retries=2, base_delay=0.01))
        assert result == "ok"
        mock_sleep.assert_any_call(0)  # retry_after=0 in test


# ── with_scan_timeout ──────────────────────────────────────────────────────────

class TestWithScanTimeout:
    @pytest.mark.asyncio
    async def test_completes_within_timeout(self):
        async def quick():
            return "done"
        with patch("app.services.connectors.resiliency.settings") as mock_settings:
            mock_settings.MAX_SCAN_DURATION = 5
            result = await with_scan_timeout(quick())
        assert result == "done"

    @pytest.mark.asyncio
    async def test_raises_timeout_error(self):
        async def slow():
            await asyncio.sleep(10)

        with patch("app.services.connectors.resiliency.settings") as mock_settings:
            mock_settings.MAX_SCAN_DURATION = 0
            with pytest.raises(asyncio.TimeoutError):
                await with_scan_timeout(slow())
