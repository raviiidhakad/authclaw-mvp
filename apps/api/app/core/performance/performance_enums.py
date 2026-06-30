"""
E4.3 performance benchmark enum contracts.

Enum identifiers in this module are stable schema values for benchmark plans and
results. They do not execute benchmarks or modify runtime behavior.
"""
from __future__ import annotations

from enum import Enum


PERFORMANCE_SCHEMA = "authclaw.performance.benchmark/v1"
PERFORMANCE_SCHEMA_VERSION = 1
PERFORMANCE_CONTRACT_VERSION = 1


class BenchmarkTarget(str, Enum):
    """Systems and paths covered by E4.3 performance measurement contracts."""

    GATEWAY_LATENCY = "gateway_latency"
    GATEWAY_THROUGHPUT = "gateway_throughput"
    STREAMING_LATENCY = "streaming_latency"
    STREAMING_THROUGHPUT = "streaming_throughput"
    AUDIT_EXPORT_GENERATION = "audit_export_generation"
    AUDIT_VERIFICATION = "audit_verification"
    OPA_EVALUATION = "opa_evaluation"
    TOKENIZATION = "tokenization"
    POLICY_EVALUATION = "policy_evaluation"
    PROVIDER_RESPONSE = "provider_response"
    MEMORY = "memory"
    CPU = "cpu"
    CONCURRENCY = "concurrency"
    LARGE_PAYLOADS = "large_payloads"
    LARGE_STREAMING_SESSIONS = "large_streaming_sessions"
    LARGE_AUDIT_EXPORTS = "large_audit_exports"


class BenchmarkKind(str, Enum):
    """Benchmark families used by E4.3 plans."""

    LATENCY = "latency"
    THROUGHPUT = "throughput"
    CONCURRENCY = "concurrency"
    MEMORY = "memory"
    CPU = "cpu"
    COMPOSITE = "composite"


class BenchmarkScenarioId(str, Enum):
    """Canonical scenario identifiers for current AuthClaw performance scope."""

    GATEWAY_OPENAI_COMPAT_CHAT = "gateway.openai_compat.chat"
    GATEWAY_POLICY_BLOCK = "gateway.policy.block"
    GATEWAY_REDACTION = "gateway.redaction"
    STREAMING_SAFE_SSE = "streaming.safe_sse"
    STREAMING_LARGE_SESSION = "streaming.large_session"
    AUDIT_EXPORT_SMALL = "audit_export.small"
    AUDIT_EXPORT_MEDIUM = "audit_export.medium"
    AUDIT_EXPORT_LARGE = "audit_export.large"
    AUDIT_PACKAGE_VERIFICATION = "audit.package_verification"
    OPA_STRICT_DECISION = "opa.strict_decision"
    TOKENIZATION_REVERSIBLE = "tokenization.reversible"
    POLICY_YAML_EVALUATION = "policy.yaml_evaluation"
    PROVIDER_ADAPTER_RESPONSE = "provider.adapter_response"
    CONCURRENT_GATEWAY_REQUESTS = "concurrency.gateway_requests"


class BenchmarkUnit(str, Enum):
    """Units accepted by measurement and threshold contracts."""

    MILLISECONDS = "ms"
    REQUESTS_PER_SECOND = "requests_per_second"
    EVENTS_PER_SECOND = "events_per_second"
    BYTES = "bytes"
    KILOBYTES = "kb"
    MEGABYTES = "mb"
    PERCENT = "percent"
    COUNT = "count"


class ThresholdOperator(str, Enum):
    """Threshold comparison semantics stored as data only."""

    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    GREATER_THAN = "greater_than"


class BenchmarkAssessment(str, Enum):
    """Non-executing result assessment state."""

    NOT_EVALUATED = "not_evaluated"
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    ERROR = "error"


class RecommendationPriority(str, Enum):
    """Priority marker for future optimization recommendations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

