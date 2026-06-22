"""
AuthClaw Sprint 2 — Connector Registry & Factory
-------------------------------------------------
Central registry that maps CloudProvider enum values to concrete connector
classes, and manages the per-provider circuit breaker singletons.

Usage:
    # Registration (done at module import by each connector file):
    @ConnectorRegistry.register
    class AWSConnector(BaseConnector):
        PROVIDER = CloudProvider.aws
        ...

    # Instantiation (done by ConnectorWorker):
    connector = ConnectorRegistry.create(integration, credentials)

    # Health data (done by GET /health/connectors):
    status = ConnectorRegistry.circuit_breaker_status()

Design principles:
  • Connectors self-register via the @ConnectorRegistry.register decorator.
    The registry never hard-codes specific connector classes — new providers
    can be added by creating a file and importing it (done in connector_sync.py).
  • One CircuitBreaker per provider is created lazily on first access and
    reused for the lifetime of the worker process (one event loop).
  • ConnectorRegistry.create() validates that both integration.status != DISABLED
    and a connector class exists before instantiating, providing a single
    validation gate used by all callers.
"""
from __future__ import annotations

import logging
from typing import Dict, Type

from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.services.connectors.base import BaseConnector
from app.services.connectors.resiliency import CircuitBreaker

logger = logging.getLogger(__name__)


class ConnectorRegistry:
    """
    Class-level registry mapping CloudProvider → connector class + circuit breaker.

    All state is stored as class variables — the registry is a singleton
    by design (no instantiation needed).
    """

    _connectors: Dict[CloudProvider, Type[BaseConnector]] = {}
    _circuit_breakers: Dict[CloudProvider, CircuitBreaker] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    @classmethod
    def register(cls, connector_cls: Type[BaseConnector]) -> Type[BaseConnector]:
        """
        Class decorator that registers a connector class.

        Validates:
          - The class inherits from BaseConnector.
          - The class defines the PROVIDER class variable.
          - No duplicate registration for the same provider.

        Usage:
            @ConnectorRegistry.register
            class AWSConnector(BaseConnector):
                PROVIDER = CloudProvider.aws
        """
        if not issubclass(connector_cls, BaseConnector):
            raise TypeError(
                f"{connector_cls.__name__} must inherit from BaseConnector."
            )
        if not hasattr(connector_cls, "PROVIDER"):
            raise AttributeError(
                f"{connector_cls.__name__} must define the PROVIDER class variable."
            )
        provider = connector_cls.PROVIDER
        if provider in cls._connectors:
            raise ValueError(
                f"Connector for provider '{provider}' is already registered "
                f"({cls._connectors[provider].__name__}). "
                f"Cannot register {connector_cls.__name__} for the same provider."
            )
        cls._connectors[provider] = connector_cls
        logger.info(
            "ConnectorRegistry: registered %s for provider '%s'.",
            connector_cls.__name__,
            provider.value,
        )
        return connector_cls

    # ── Circuit Breaker management ────────────────────────────────────────────

    @classmethod
    def get_circuit_breaker(cls, provider: CloudProvider) -> CircuitBreaker:
        """
        Return the singleton CircuitBreaker for a provider.
        Created lazily on first call; reused for the process lifetime.
        """
        if provider not in cls._circuit_breakers:
            cls._circuit_breakers[provider] = CircuitBreaker(
                name=f"{provider.value}_connector",
                failure_threshold=5,
                recovery_timeout=300,
            )
            logger.debug(
                "ConnectorRegistry: created circuit breaker for '%s'.",
                provider.value,
            )
        return cls._circuit_breakers[provider]

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        integration: CloudIntegration,
        credentials: dict,
    ) -> BaseConnector:
        """
        Instantiate the correct connector for the given integration.

        Validates:
          - integration.status is not DISABLED.
          - A connector class is registered for integration.provider_type.

        Args:
            integration:   CloudIntegration ORM record (read-only reference).
            credentials:   Decrypted credential dict from VaultCredentialService.

        Returns:
            Concrete BaseConnector instance ready for validate_credentials()
            and fetch_findings() calls.

        Raises:
            ValueError:  If integration is DISABLED or no connector is registered.
        """
        if integration.status == IntegrationStatus.disabled:
            raise ValueError(
                f"Integration {integration.id} is DISABLED. "
                "Cannot create a connector for a disabled integration."
            )

        provider = integration.provider_type
        connector_cls = cls._connectors.get(provider)
        if connector_cls is None:
            raise ValueError(
                f"No connector registered for provider '{provider.value}'. "
                f"Registered providers: {[p.value for p in cls._connectors]}"
            )

        connector = connector_cls(integration=integration, credentials=credentials)
        logger.debug(
            "ConnectorRegistry: created %s for integration %s (tenant %s).",
            connector_cls.__name__,
            integration.id,
            integration.tenant_id,
        )
        return connector

    # ── Introspection ─────────────────────────────────────────────────────────

    @classmethod
    def registered_providers(cls) -> list[str]:
        """Return list of provider names with registered connectors."""
        return [p.value for p in cls._connectors]

    @classmethod
    def circuit_breaker_status(cls) -> dict[str, dict]:
        """
        Return a JSON-serializable snapshot of all circuit breaker states.
        Used by GET /health/connectors to surface per-provider health.

        Returns dict keyed by provider name:
          {
            "aws":    {"state": "CLOSED", "failure_count": 0, ...},
            "github": {"state": "OPEN",   "failure_count": 5, ...},
          }
        """
        return {
            provider.value: breaker.status_dict()
            for provider, breaker in cls._circuit_breakers.items()
        }

    @classmethod
    def _reset_for_testing(cls) -> None:
        """
        Clear registry state. Called only in test setUp/tearDown.
        Not for production use.
        """
        cls._connectors.clear()
        cls._circuit_breakers.clear()
