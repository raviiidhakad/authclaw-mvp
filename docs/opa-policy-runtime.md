# AuthClaw OPA Policy Runtime

AuthClaw supports three gateway policy engine modes while preserving the existing YAML policy UX.

## Modes

| Mode | Behavior |
| --- | --- |
| `python` | Default. Uses the existing YAML/Python evaluator only. No OPA call is made. |
| `opa` | Uses the OPA/Rego HTTP runtime as the authoritative gateway policy decision. The existing YAML/Python adapter still derives sanitized compatibility metadata and safe redaction transforms. |
| `hybrid` | Evaluates both OPA and the Python/YAML adapter. If decisions disagree, the gateway fails closed before provider egress. |

Configuration:

```env
POLICY_ENGINE_MODE=python
OPA_URL=http://127.0.0.1:8181/v1/data/authclaw/gateway/decision
OPA_RUNTIME_MODE=STRICT
OPA_STRICT_MODE=true
OPA_FAIL_CLOSED=true
OPA_TIMEOUT_SECONDS=2.0
```

`ENABLE_OPA_RUNTIME_INTEGRATION=true` is still accepted for backward compatibility and maps to OPA mode when `POLICY_ENGINE_MODE` is left as `python`.

## Fail-Closed Behavior

In `opa` and `hybrid` mode, AuthClaw denies before provider egress when OPA returns:

- timeout
- connection failure
- HTTP error
- malformed JSON
- malformed response
- missing decision fields
- invalid sanitized input
- hybrid mismatch

Compatibility fallback is only available when `OPA_RUNTIME_MODE=COMPATIBILITY`, `OPA_STRICT_MODE=false`, or `OPA_FAIL_CLOSED=false`.

## Rego Decision Contract

OPA should return a decision at:

```text
/v1/data/authclaw/gateway/decision
```

Expected response shape:

```json
{
  "result": {
    "allow": true,
    "action": "allow",
    "reason": "OPA allowed request.",
    "matched_rules": [],
    "redaction_required": false,
    "metadata": {
      "engine": "opa"
    }
  }
}
```

Supported actions:

- `allow`
- `deny`
- `block`
- `redact`
- `warn`

`deny` and `block` prevent upstream provider calls. `redact` and `warn` require a safe redacted prompt from the existing YAML/Python adapter; if no redacted prompt is available, AuthClaw fails closed.

## YAML Compatibility

YAML remains the source of truth for policy authoring and API compatibility. The gateway builds a sanitized OPA input document from:

- tenant/route/provider/model metadata
- policy version/hash
- normalized YAML policy metadata
- hashed keyword/regex match identifiers
- Python/YAML adapter decision metadata
- request metadata such as `stream`

The OPA runtime does not receive raw provider keys, Vault references, raw provider payloads, or raw prompt bodies.

## Prompt Sanitization Tradeoff

Rego does not inspect the raw prompt. AuthClaw derives minimized match metadata before calling OPA:

- keyword matches are represented by deterministic hashed rule identifiers
- regex matches are represented by deterministic hashed rule identifiers
- redaction availability is represented by adapter metadata

This avoids sending raw prompt content to OPA logs while still allowing OPA to make authoritative allow/block/redact decisions for the existing YAML policy model.

## Rego Example

The production-shape example lives at:

```text
apps/api/opa/gateway.rego
```

It supports:

- normal prompt allow
- credential-leakage block through sanitized keyword match metadata
- disallowed-topic block through YAML content-filter metadata
- PII redaction requirement through sanitized adapter metadata
- malformed/unsupported request deny

## Local Validation

Start OPA locally with the example policy:

```powershell
docker run --rm -p 8181:8181 -v "${PWD}\apps\api\opa:/policies" openpolicyagent/opa:latest run --server --addr :8181 /policies
```

Or use the optional Compose profile:

```powershell
docker compose --profile opa up opa
```

Then run AuthClaw API tests with:

```powershell
$env:POLICY_ENGINE_MODE="opa"
$env:OPA_URL="http://127.0.0.1:8181/v1/data/authclaw/gateway/decision"
$env:OPA_STRICT_MODE="true"
$env:OPA_FAIL_CLOSED="true"
$env:ENABLE_REAL_OPA_SIDECAR_TESTS="true"
cd apps/api
.venv\Scripts\python.exe -m pytest tests/test_pdf_gap_phase8_real_opa_sidecar.py -q
```

Unit tests use mocked OPA HTTP interactions and do not require a live OPA server.

## Phase 8 Real Sidecar Validation Status

Validation date: 2026-07-01.

Runtime used:

- Docker sidecar with `openpolicyagent/opa:latest`.
- Started with `docker compose --profile opa up -d opa`.
- Rego policy mounted read-only from `apps/api/opa`.
- Decision endpoint: `http://127.0.0.1:8181/v1/data/authclaw/gateway/decision`.

Config used:

```env
POLICY_ENGINE_MODE=opa
OPA_URL=http://127.0.0.1:8181/v1/data/authclaw/gateway/decision
OPA_STRICT_MODE=true
OPA_FAIL_CLOSED=true
ENABLE_REAL_OPA_SIDECAR_TESTS=true
```

Hybrid validation used:

```env
POLICY_ENGINE_MODE=hybrid
OPA_URL=http://127.0.0.1:8181/v1/data/authclaw/gateway/decision
OPA_STRICT_MODE=true
OPA_FAIL_CLOSED=true
```

Real-runtime decision matrix:

| Case | Expected OPA action | Expected gateway behavior |
| --- | --- | --- |
| Normal chat completion metadata | `allow` | PASS: direct real OPA decision returned allow |
| Credential-leakage match metadata | `deny` | PASS: direct real OPA decision returned deny |
| Disallowed-topic match metadata | `deny` | PASS: direct real OPA decision returned deny |
| PII redaction-required metadata | `redact` | PASS: direct real OPA decision required redaction |
| Unsupported request type | `deny` | PASS: direct real OPA decision returned deny |
| Gateway allow path | `allow` | PASS: mocked provider was called |
| Gateway block path | `deny` | PASS: mocked provider was not called |
| Gateway redaction path | `redact` | PASS: fake email was removed before mocked provider egress |
| Hybrid real-runtime path | `allow` or safe fail-closed mismatch | PASS: test accepts only provider success or configured fail-closed mismatch |

Command used:

```powershell
$env:ENABLE_REAL_OPA_SIDECAR_TESTS="true"
$env:POLICY_ENGINE_MODE="opa"
$env:OPA_URL="http://127.0.0.1:8181/v1/data/authclaw/gateway/decision"
$env:OPA_STRICT_MODE="true"
$env:OPA_FAIL_CLOSED="true"
.venv\Scripts\python.exe -m pytest tests/test_pdf_gap_phase8_real_opa_sidecar.py -q
```

Result:

```text
5 passed
```

Fail-closed proof remains covered by the mocked Phase 4 runtime tests for timeout, unavailable runtime, malformed response, malformed JSON, HTTP error, invalid input, and hybrid mismatch categories.

## Observability

Gateway audit metadata includes:

- policy engine mode
- decision id
- allow/block action
- matched rules/categories
- OPA runtime status
- OPA error category
- policy hash/version
- latency in milliseconds
- cache hit status

It does not include raw prompts, provider payloads, provider keys, or Vault references.

## Known Limitations

- Rego examples prove the runtime contract but are not a full tenant-specific policy compiler.
- OPA mode depends on sanitized metadata derived from the current YAML/Python policy adapter.
- Live OPA deployment topology is available as an optional Compose profile and has been validated locally with the example Rego policy.
- Full production staging proof should run with the target OPA sidecar or service topology before AWS deployment.
