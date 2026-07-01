# AuthClaw PDF Gap Closure Phase 1: Gateway Performance Decision

Date: 2026-06-30

## Scope

This decision record addresses the PDF production-readiness gap for gateway
overhead and the Go/Rust hot-path decision. It does not deploy AuthClaw, use
live provider credentials, change gateway behavior, change public APIs, or make
legal compliance guarantees.

## Benchmark Command

Run from `apps/api`:

```powershell
.\.venv\Scripts\python.exe tests\performance\measure_gateway_e4_3.py --iterations 25 --warmups 5 --compact
```

Focused reproducibility test:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\performance\test_e4_3_gateway_benchmark.py -q
```

## Environment Assumptions

- OS: Windows 11
- Python: 3.12.13 from `apps/api/.venv`
- CPU: 12 logical cores, Intel64 Family 6 Model 154
- Provider: mocked local provider, no live provider keys
- Gateway path: existing `GatewayService.process_chat_request`
- Security path: mocked Presidio scan, mocked TokenVault storage, mocked event producer
- Streaming: disabled, safe non-streaming chat-completions path
- Runtime changes: none

## Benchmark Results

PDF target: gateway overhead p95 <= 50 ms.

Result summary: `PASS`, 12 passed, 0 failed, 12 total.

| Scenario | Concurrency | Samples | p50 overhead ms | p90 overhead ms | p95 overhead ms | p99 overhead ms | Max latency ms | Throughput req/s | Peak memory bytes | CPU % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| small_request | 1 | 25 | 7.126 | 7.602 | 7.927 | 8.187 | 8.245 | 138.25 | 412428 | 100.00 |
| medium_request | 1 | 25 | 7.140 | 7.806 | 7.848 | 8.098 | 8.176 | 135.94 | 407611 | 100.00 |
| large_request | 1 | 25 | 7.645 | 9.401 | 10.226 | 10.415 | 10.445 | 124.26 | 432152 | 93.19 |
| policy_allow | 1 | 25 | 7.999 | 10.197 | 10.584 | 11.410 | 11.659 | 119.43 | 422496 | 82.10 |
| policy_redact | 1 | 25 | 7.924 | 8.709 | 8.761 | 8.969 | 9.033 | 120.88 | 658112 | 98.21 |
| policy_hash_redact | 1 | 25 | 8.354 | 9.607 | 10.351 | 15.177 | 16.649 | 112.52 | 640599 | 91.41 |
| policy_synthetic_redact | 1 | 25 | 8.692 | 10.643 | 11.174 | 12.233 | 12.560 | 109.22 | 657777 | 100.00 |
| policy_reversible_tokenization | 1 | 25 | 8.011 | 8.721 | 9.005 | 10.533 | 11.000 | 119.94 | 703864 | 97.44 |
| policy_block | 1 | 25 | 13.863 | 18.183 | 19.105 | 20.754 | 21.236 | 67.19 | 341153 | 83.99 |
| multiple_tenants | 1 | 25 | 19.125 | 21.481 | 22.061 | 22.832 | 23.059 | 50.94 | 408258 | 82.77 |
| provider_mock_error | 1 | 25 | 15.236 | 20.096 | 21.010 | 21.645 | 21.866 | 61.96 | 359483 | 96.81 |
| concurrent_requests | 10 | 250 | 19.717 | 23.404 | 26.291 | 31.081 | 42.028 | 49.42 | 2862509 | 94.82 |

## <=50ms Verdict

PASS for local mocked, production-like gateway path validation.

All measured p95 overhead values are below the PDF target of 50 ms. The highest
p95 overhead was 26.291 ms for 10-way concurrent requests. This is evidence
that the current FastAPI gateway can satisfy the MVP overhead target in this
local mocked-provider benchmark.

This is not full production-scale proof. The benchmark intentionally avoids live
providers, cloud networking, managed database latency, real Redis, real
ClickHouse, real OPA service latency, and AWS load balancer effects.

## Provider Compatibility Matrix

| Provider | Non-streaming support | Streaming support | Policy/redaction support | Adapter contract coverage | Native reverse-proxy breadth |
|---|---|---|---|---|---|
| OpenAI-compatible / Groq | Supported through OpenAI adapter mapping and gateway route tests | Supported through common adapter stream contract and E2.3 streaming pipeline | Gateway-level policy/redaction before provider egress | Covered by gateway MVP and provider contract tests | Python/FastAPI gateway path, not native Go/Rust reverse proxy |
| OpenAI | Supported through `OpenAIAdapter` | Supported through common adapter stream contract | Gateway-level policy/redaction before provider egress | Covered by provider and gateway route override tests | Python/FastAPI gateway path, not native Go/Rust reverse proxy |
| Anthropic | Supported through `AnthropicAdapter` request transform | Supported by adapter contract surface; broad live streaming not proven here | Gateway-level policy/redaction before adapter transform | Covered by adapter transform and phase 6 provider tests | Python/FastAPI gateway path, not native Go/Rust reverse proxy |
| Cohere | Supported through `CohereAdapter` request transform | Supported by adapter contract surface; broad live streaming not proven here | Gateway-level policy/redaction before adapter transform | Covered by adapter transform and phase 6 provider tests | Python/FastAPI gateway path, not native Go/Rust reverse proxy |
| Azure OpenAI | Supported through `AzureOpenAIAdapter` | Supported through inherited OpenAI-compatible stream contract | Gateway-level policy/redaction before provider egress | Covered by phase 6 provider tests | Python/FastAPI gateway path, not native Go/Rust reverse proxy |

## Architecture Decision

Decision: KEEP the current FastAPI gateway for the MVP path and DEFER Go/Rust
hot-path implementation.

Rationale:

- Local mocked-provider benchmark passes the PDF <=50 ms p95 overhead target.
- Existing gateway tests cover route-selected provider/model behavior, policy
  block before provider call, redaction modes, provider errors, and multi-tenant
  route/API-key flows.
- A Go/Rust rewrite is not justified by current measured overhead evidence.
- Native reverse-proxy breadth is still partial because the current
  implementation is a Python/FastAPI gateway with provider adapters, not a
  native Go/Rust ingress proxy.

Go/Rust should start only if a later AWS or production-load benchmark fails the
50 ms p95 overhead target, or if provider-native payload compatibility cannot be
closed in the FastAPI gateway without unacceptable complexity.

## Risks

- Local benchmark does not include AWS ALB, ECS networking, RDS, Redis,
  ClickHouse, or live OPA service latency.
- CPU sampling is process-level and coarse; it is useful for trend observation,
  not capacity planning.
- Provider streaming compatibility is covered by adapter contracts and E2.3
  streaming tests, but this Phase 1 benchmark measures the safe non-stream path.
- Native reverse proxy breadth remains a PDF interpretation risk because the
  plan names a Go/Rust ingress, while current implementation is FastAPI.

## Follow-Up Recommendations

1. Run the same benchmark suite in Docker Compose with real Redis/PostgreSQL
   dependencies enabled.
2. Run the same suite in AWS staging before customer pilot.
3. Add live OPA latency scenarios when the OPA production proof phase begins.
4. Add live provider canary benchmarks without logging or exposing provider keys.
5. Keep Go/Rust hot-path work deferred until production evidence requires it.

## Final Phase 1 Decision

Phase 1 verdict: PASS for local mocked-provider PDF overhead proof.

Hot-path decision: KEEP FastAPI for MVP; DEFER Go/Rust until AWS/staging load
evidence or native provider compatibility evidence requires it.
