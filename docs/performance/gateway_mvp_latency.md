# AuthClaw Gateway MVP Latency Benchmark

Offline mocked benchmark. No live provider keys or network calls are used.

- Iterations: `50`
- Warmup: `5`
- p95 overhead target: `<=50ms`
- Result: `met`

| Path | p50 ms | p95 ms | p99 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| Direct mocked upstream | 0.002 | 0.002 | 0.005 | 0.005 |
| AuthClaw gateway | 7.055 | 9.196 | 9.353 | 9.353 |
| Gateway overhead | 7.053 | 9.194 | 9.348 | - |

Security settings exercised: route-selected model, route-attached policy, redaction, fail-closed gateway path, and mocked audit write.