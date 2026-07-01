from typing import List, Optional
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, PostgresDsn, RedisDsn

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "AuthClaw"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_VERSION: str = "0.1.0"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # Database
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str

    # Security
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENCRYPTION_KEY: str  # Fernet key for provider API keys
    ENCRYPTION_PROVIDER: str = "kms"
    KMS_KEY_ID: str = "alias/authclaw-master-key"
    VAULT_ADDR: str = "http://vault:8200"
    VAULT_TOKEN: str = "root"
    VAULT_TRANSIT_KEY: str = "authclaw-key"
    VAULT_TRANSIT_MOUNT: str = "transit"

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # AI Providers
    OPENAI_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    ENABLE_PROVIDER_LIVE_VALIDATION: bool = False
    ENABLE_GATEWAY_LIVE_E2E: bool = False

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # Event Backbone
    KAFKA_BROKERS: str = "redpanda:9092"

    # ── Sprint 1: Security Pipeline Feature Flags ───────────────────────────
    # All flags default to False for zero-risk rollout.
    # Enable FF_SECURITY_PIPELINE first; then enable sub-flags independently.
    #
    # FF_SECURITY_PIPELINE   — Master gate. If False, all sub-flags are ignored.
    # FF_INBOUND_SCAN        — Enables Presidio scan + policy eval on prompts.
    # FF_OUTBOUND_SCAN       — Enables Presidio scan + policy eval on completions.
    # FF_STREAM_SCAN         — Enables sliding-window scanning of SSE streams.
    # FF_SECURITY_SHADOW_MODE — Detects and audits, but does NOT block or redact.
    #                           Use for dark-launch observation before enforcement.
    FF_SECURITY_PIPELINE: bool = False
    FF_INBOUND_SCAN: bool = False
    FF_OUTBOUND_SCAN: bool = False
    FF_STREAM_SCAN: bool = False
    FF_SECURITY_SHADOW_MODE: bool = False

    # ── Sprint 1: Presidio ProcessPool Settings ─────────────────────────────
    # Worker count uses the approved formula: min(8, max(1, cpu_count() - 1))
    # Resolved at runtime in presidio_engine.py — stored here for observability.
    PRESIDIO_POOL_MAX_WORKERS: int = min(8, max(1, (os.cpu_count() or 2) - 1))

    # ── Sprint 1: Streaming Pipeline Settings ──────────────────────────────
    # Sliding window buffer size in characters. Default 60 chars (~15 tokens).
    # Increase to detect longer PII patterns at the cost of stream latency.
    STREAMING_BUFFER_SIZE: int = 60

    # ── Sprint 1: Policy Cache Settings ────────────────────────────────────
    # Redis key prefix for compiled tenant policy caches.
    # Invalidated on policy.created / policy.updated / policy.deleted / tenant.deleted.
    POLICY_CACHE_KEY_PREFIX: str = "tenant:policy:compiled"

    # ── Sprint 2: Reversible Tokenization Settings ──────────────────────────
    # TTL for encrypted PII tokens stored in Redis for reversible tokenization.
    # Defines the maximum lifespan of a detokenization mapping.
    TOKEN_TTL_SECONDS: int = 3600

    # ── Sprint 2: Connector Safety Limits ──────────────────────────────────────
    # Maximum findings retrieved per connector sync. Prevents memory exhaustion
    # on very large cloud environments. ConnectorWorker truncates at this limit.
    MAX_FINDINGS_PER_SYNC: int = 10_000

    # Maximum wall-clock seconds a single connector sync may run before it is
    # cancelled. The distributed lock TTL is set to MAX_SCAN_DURATION + 60s
    # to allow graceful shutdown before the lock expires.
    MAX_SCAN_DURATION: int = 300

    # Redis SET NX EX lock TTL for connector scans. Must be greater than
    # MAX_SCAN_DURATION unless a future heartbeat extension is added.
    CONNECTOR_SCAN_LOCK_TTL_SECONDS: int = 360

    # Long-running connector worker poll interval.
    CONNECTOR_WORKER_POLL_INTERVAL_SECONDS: int = 60

    # Maximum findings injected into LangGraph AgentState per scan target.
    # Prevents LLM context window overflow. ContextBuilder selects the top N
    # by severity (CRITICAL first) from the ACTIVE finding inventory.
    MAX_AGENT_CONTEXT_FINDINGS: int = 15

    # ── Sprint 2: Vault KV Credential Storage ───────────────────────────────
    # KV mount and path prefix for integration credentials.
    # Full path: {VAULT_INTEGRATION_MOUNT}/{VAULT_INTEGRATION_PATH_PREFIX}/{tenant_id}/integrations/{id}
    VAULT_INTEGRATION_MOUNT: str = "secret"
    VAULT_INTEGRATION_PATH_PREFIX: str = "authclaw/tenants"

    # ── Sprint 2: ClickHouse Settings ───────────────────────────────────────
    # Previously used via getattr fallback in clickhouse.py.
    # Promoted to typed settings for Sprint 2.
    CLICKHOUSE_URL: str = "http://clickhouse:8123"
    CLICKHOUSE_USER: str = "authclaw"
    CLICKHOUSE_PASSWORD: str = "authclaw_clickhouse_local_password"
    CLICKHOUSE_DB: str = "authclaw"

    # ── Sprint 2: Feature Flags ─────────────────────────────────────────────
    # Master gate for the connector subsystem. Keeps mock_findings path intact
    # until a tenant successfully registers and validates a CloudIntegration.
    # When False: agent.py uses mock_findings (Sprint 1 behaviour).
    # When True:  agent.py uses FindingInventoryService.get_prioritized().
    FF_USE_REAL_CONNECTORS: bool = False

    # Sprint 5: external trust sharing is disabled by default. Phase 5 only
    # exposes owner-gated create/list/revoke foundations when explicitly enabled.
    ENABLE_EXTERNAL_TRUST_SHARING: bool = False
    EXTERNAL_TRUST_SHARING_MAX_EXPIRY_DAYS: int = 30

    # Gateway raw audit retention is disabled by default. When False, legacy
    # prompt_original/response_original columns receive sanitized previews plus
    # hash metadata instead of raw prompt/response bodies.
    ENABLE_RAW_GATEWAY_AUDIT_RETENTION: bool = False

    # Policy engine mode:
    #   python - existing YAML/Python evaluator only
    #   opa    - authoritative OPA/Rego HTTP runtime
    #   hybrid - compare OPA + Python decisions and fail closed on mismatch
    POLICY_ENGINE_MODE: str = "python"
    ENABLE_OPA_RUNTIME_INTEGRATION: bool = False
    OPA_URL: str = "http://opa:8181/v1/data/authclaw/gateway/decision"
    OPA_POLICY_URL: str = "http://opa:8181/v1/data/authclaw/gateway/decision"
    OPA_RUNTIME_MODE: str = "STRICT"
    OPA_STRICT_MODE: bool = True
    OPA_FAIL_CLOSED: bool = True
    OPA_TIMEOUT_SECONDS: float = 2.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

settings = Settings()
