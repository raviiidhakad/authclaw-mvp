# AuthClaw Gateway MVP Closeout

Date: 2026-06-24

## Verdict

Gateway MVP is accepted for the current OpenAI-compatible chat-completions scope.

The MVP is ready for local/demo external-agent validation with mocked and manually gated live-provider paths. It is not a full native reverse proxy, not a full OPA/Rego runtime, and not an AWS-deployed production gateway.

## Supported Scope

- OpenAI-compatible `/v1/chat/completions` gateway surface
- AuthClaw gateway API keys using `Authorization: Bearer ac_...`
- Tenant-scoped route/provider/model resolution
- Route model override
- Provider adapters for Groq/OpenAI-compatible, OpenAI, Anthropic, Cohere, and Azure OpenAI
- Inbound policy evaluation and redaction before provider egress
- Route-attached YAML policy enforcement through the Python adapter seam
- Strict buffered safe streaming only
- Sanitized gateway audit previews and original-content hashes
- Raw gateway audit retention disabled by default
- Live Groq validation gated behind local flags and local ignored key material

## Setup Flow

1. Add an upstream provider credential in Settings.
2. Create a gateway route that points to that provider.
3. Attach a policy where needed.
4. Generate the tenant AuthClaw gateway API key.
5. Call `/v1/chat/completions` with the AuthClaw key.
6. Inspect gateway traffic/audit metadata for route, provider, model, decision, redaction, status, and latency.

## Curl

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ac_xxx_replace_with_authclaw_gateway_key" \
  -H "Content-Type: application/json" \
  -d '{
    "route": "default",
    "model": "route-model-or-client-model",
    "messages": [
      {
        "role": "user",
        "content": "A demo user entered person@example.test and it should be protected."
      }
    ]
  }'
```

## Python

```python
from openai import OpenAI

client = OpenAI(
    api_key="ac_xxx_replace_with_authclaw_gateway_key",
    base_url="http://localhost:8000/v1",
)

response = client.chat.completions.create(
    model="route-model-or-client-model",
    messages=[
        {
            "role": "user",
            "content": "A demo user entered person@example.test and it should be protected.",
        }
    ],
    extra_body={"route": "default"},
)

print(response.choices[0].message.content)
```

## Node

```js
const response = await fetch("http://localhost:8000/v1/chat/completions", {
  method: "POST",
  headers: {
    Authorization: "Bearer ac_xxx_replace_with_authclaw_gateway_key",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    route: "default",
    model: "route-model-or-client-model",
    messages: [
      {
        role: "user",
        content: "A demo user entered person@example.test and it should be protected.",
      },
    ],
  }),
});

const data = await response.json();
console.log(data.choices?.[0]?.message?.content ?? data);
```

## Latency Benchmark

Command:

```powershell
$env:PYTHONPATH=(Get-Location).Path
.\.venv\Scripts\python.exe tests\performance\measure_gateway.py --iterations 50 --warmup 5 --upstream-delay-ms 0 --output ..\..\docs\performance\gateway_mvp_latency.md
```

Result from `docs/performance/gateway_mvp_latency.md`:

| Path | p50 ms | p95 ms | p99 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| Direct mocked upstream | 0.002 | 0.002 | 0.005 | 0.005 |
| AuthClaw gateway | 7.055 | 9.196 | 9.353 | 9.353 |
| Gateway overhead | 7.053 | 9.194 | 9.348 | - |

The local mocked p95 overhead target of `<=50ms` is met. This benchmark isolates AuthClaw processing with mocked upstream and mocked audit/event publishing. Live-provider latency, network jitter, production database latency, and production event backbone latency are not included.

## Provider Contract Coverage

Offline tests cover:

- Groq/OpenAI-compatible request/response path
- OpenAI request/response path
- Anthropic request mapping and OpenAI-compatible normalization
- Cohere request mapping and OpenAI-compatible normalization
- Azure OpenAI API-key path mapping
- Route model override
- Redacted prompt received by upstream
- Sanitized provider authentication errors
- Policy block before upstream call
- No provider key or Vault reference in client response or audit kwargs

Live-provider validation remains optional and manually gated. CI does not require real provider keys.

## Streaming Safety

Streaming is strict buffered safe by default:

- Passthrough streaming is rejected.
- Prompt content is sanitized before provider egress.
- Provider chunks are buffered and scanned/redacted before client release.
- Scanner failure terminates safely without releasing raw chunks.
- Provider stream errors return sanitized SSE error metadata.

## Audit Retention

`ENABLE_RAW_GATEWAY_AUDIT_RETENTION=false` by default.

New gateway audit records store sanitized prompt/response previews in legacy preview fields and store hashes of originals for integrity/deduplication. Raw retention is explicit and still not exposed through API serializers.

Historical rows created before this cleanup are a documented follow-up if a production migration/scrub is required.

## Security Posture

- AuthClaw gateway keys are separate from upstream provider keys.
- Upstream provider credentials remain server-side.
- Revoked/expired AuthClaw gateway keys are rejected.
- Disabled routes are rejected.
- Route-attached policy failure fails closed.
- Provider errors are sanitized before client/audit exposure.
- No legal compliance guarantees are made by the gateway.

## Remaining PDF Gaps

- Full OPA/Rego runtime
- Broader native reverse-proxy coverage beyond chat completions
- Production Go/Rust low-latency proxy if still required
- Optional/manual live-provider validation in a controlled environment
- Production deployment hardening and AWS rollout

## Recommended Next Track

Start a production gateway architecture track focused on native proxy breadth, full OPA/Rego evaluation, streaming latency under real provider load, and deployment hardening. Do not mix that with live AWS rollout until credentials, tenant isolation, and observability gates are finalized.
