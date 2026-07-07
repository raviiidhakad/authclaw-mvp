# AuthClaw Gateway MVP Latency Benchmark

Status: `MVP-complete local benchmark proof`; production/staging proof is still pending.

Offline mocked benchmark. No live provider keys or network calls are used. The benchmark exercises the existing FastAPI gateway path through `GatewayService.process_chat_request` with mocked provider, Presidio, TokenVault, audit/event, and rate-limit side effects.

## Reproducible local command

Run from repo root with the Compose API container running:

```powershell
docker compose exec -T api python tests/performance/measure_gateway_e4_3.py --iterations 25 --warmups 5 --compact
```

Bare Python equivalent from `apps/api`:

```powershell
python tests/performance/measure_gateway_e4_3.py --iterations 25 --warmups 5 --compact
```

Focused benchmark correctness test:

```powershell
docker compose exec -T api python -m pytest tests/performance/test_e4_3_gateway_benchmark.py -q
```

## Local benchmark result

Run date: `2026-07-07`

- Iterations: `25`
- Warmup: `5`
- p95 overhead target: `<=50ms`
- Result: `met`

Command output summary: `summary,pass,12,0,12`

| Scenario | Concurrency | Samples | p50 overhead ms | p95 overhead ms | p99 overhead ms | max latency ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| small_request | 1 | 25 | 8.579 | 9.713 | 10.120 | 10.230 |
| medium_request | 1 | 25 | 8.663 | 10.012 | 12.890 | 13.790 |
| large_request | 1 | 25 | 8.572 | 9.392 | 10.187 | 10.440 |
| policy_allow | 1 | 25 | 8.850 | 14.106 | 14.161 | 14.172 |
| policy_redact | 1 | 25 | 10.393 | 11.315 | 12.248 | 12.536 |
| policy_hash_redact | 1 | 25 | 10.114 | 13.137 | 13.838 | 13.953 |
| policy_synthetic_redact | 1 | 25 | 9.222 | 14.070 | 14.366 | 14.396 |
| policy_reversible_tokenization | 1 | 25 | 9.076 | 9.889 | 10.411 | 10.576 |
| policy_block | 1 | 25 | 5.107 | 5.796 | 6.088 | 6.160 |
| multiple_tenants | 1 | 25 | 10.164 | 12.289 | 12.343 | 12.347 |
| provider_mock_error | 1 | 25 | 7.165 | 10.135 | 12.079 | 12.640 |
| concurrent_requests | 10 | 250 | 9.124 | 13.846 | 17.741 | 23.251 |

Security settings exercised: route-selected model, route-attached policy, redaction, fail-closed gateway path, and mocked audit write.

## Staging proof command

Run from the staging API container/task after AWS/staging deployment, using the same commit being evaluated:

```bash
python tests/performance/measure_gateway_e4_3.py --iterations 100 --warmups 10 --compact
```

Acceptance: every scenario reports `p95_overhead_ms <= 50.000`. Until this command is run in staging and its output is attached to the release evidence, production/staging proof remains pending.

