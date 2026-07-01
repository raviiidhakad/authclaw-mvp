# AuthClaw Threat Model Summary

Status: pentest-readiness threat model. This document identifies risks and expected controls; it is not a completed external assessment.

## High-Value Assets

- Tenant data and tenant configuration.
- AuthClaw user accounts, roles, sessions, and MFA approval state.
- AuthClaw gateway API keys.
- Provider credentials and Vault-stored secret references.
- Gateway prompts, completions, redaction outputs, and tokenization mappings.
- Policy definitions, YAML imports, OPA runtime decisions, and route bindings.
- Audit logs, security events, hash-chain data, and cryptographic audit exports.
- Trust reports, evidence packages, report artifacts, and access logs.
- Remediation plans, artifacts, approvals, policy checks, execution jobs, and worker tokens.
- Rate-limit counters and tenant-plan metadata.

## Trust Boundaries

- Browser to AuthClaw API.
- Public gateway client to AuthClaw gateway.
- AuthClaw API to database.
- AuthClaw API/workers to Redis.
- AuthClaw API/workers to Vault.
- AuthClaw API/workers to ClickHouse.
- AuthClaw event producers/consumers to Redpanda.
- AuthClaw gateway to provider adapters.
- AuthClaw policy layer to OPA runtime.
- AuthClaw remediation/connector workers to scoped job tokens.
- Tenant A data boundary to Tenant B data boundary.

## Attacker Profiles

- Unauthenticated internet user.
- Authenticated low-privilege user.
- Malicious tenant admin.
- Cross-tenant attacker with another tenant's object IDs.
- Leaked gateway API-key holder.
- Compromised provider credential user.
- Compromised worker token holder.
- Insider with log or artifact access.
- Supply-chain attacker targeting dependencies or CI.

## Key Abuse Cases

### Tenant Isolation Bypass

Risk: attacker reads or mutates another tenant's providers, policies, reports, audit logs, remediation plans, or exports.

Expected controls:

- Tenant-scoped database queries.
- RLS where implemented.
- Tenant-bound API key verification.
- Tenant-bound worker tokens.
- Cross-tenant tests for core surfaces.

### Gateway API Key Abuse

Risk: leaked AuthClaw gateway key is used to proxy requests, bypass rate limits, or access another tenant route.

Expected controls:

- Raw key shown once.
- Hash-only storage.
- Revocation and expiry.
- Tenant and route scoping.
- Tiered rate limits.
- Sanitized traffic logs.

### Provider Credential Theft

Risk: attacker extracts provider API keys from API responses, UI, audit logs, exports, traces, or errors.

Expected controls:

- Vault-backed provider credential storage.
- Metadata-only validation by default.
- Sanitized provider errors.
- No Vault refs or raw keys in frontend/API output.
- Secret scanning in tests and release checks.

### Raw Payload Leakage

Risk: raw prompts, completions, or provider payloads appear in audit logs, traffic inspector, reports, exports, OPA input, or security events.

Expected controls:

- Sanitized audit retention by default.
- Safe previews and hashes.
- OPA input builder omits raw prompt/provider payload fields.
- Safe streaming buffered scan before release.
- Export sanitizer for reports and evidence packages.

### Policy Bypass

Risk: attacker bypasses YAML policy, OPA mode, route-attached policy, redaction, or fail-closed behavior.

Expected controls:

- Route policy loading before provider egress.
- Python/YAML default evaluator.
- OPA authoritative mode.
- Hybrid mismatch fail-closed behavior.
- Safe error responses on policy runtime failure.
- Tests for block before upstream provider call.

### HITL and MFA Bypass

Risk: high-risk remediation execution proceeds without fresh approval, approval replay, or cross-user/cross-tenant approval reuse.

Expected controls:

- Action-bound MFA envelope.
- Binding to tenant, approver, plan, artifact hash, policy-check hash, action, risk, scope, expiry, and nonce.
- Single-use approval.
- Self-approval restrictions for elevated paths.
- Sanitized audit events.

### Worker Token Replay

Risk: connector/remediation worker token is reused, replayed, or used against another tenant/job/action.

Expected controls:

- Cryptographically random token.
- Hash-only storage.
- Tenant/job/action/scope binding.
- Short TTL.
- Single-use or limited-use validation.
- Revocation.
- Fail-closed validation for destructive paths.

### Audit Tampering

Risk: attacker deletes, reorders, or modifies audit records or exported audit packages.

Expected controls:

- Canonical audit integrity path.
- Previous hash and integrity hash on exportable records.
- Chain proof generation.
- Deterministic signed package.
- Verification service and Trust Center verification state.
- Tamper tests for manifest, audit JSONL, chain proof, and signature.

### Report and Export Leakage

Risk: reports, evidence packages, or Trust Center artifacts disclose cross-tenant or sensitive raw data.

Expected controls:

- Tenant-scoped artifact access.
- Sanitized artifact metadata.
- Authenticated download checks.
- Share-link disabled by default.
- Access logging.
- Export sanitizer and package verification.

### Rate-Limit Bypass

Risk: attacker exceeds tenant plan, API key, route, provider, or model quotas.

Expected controls:

- Tenant-plan tier limits.
- Per-key/route/provider/model dimensions.
- Redis-backed counters where available.
- Safe error payloads.
- Fail-safe behavior where counters are unavailable for protected paths.

## Review Notes

- External pentest evidence is still pending.
- Real OPA sidecar validation is still pending in a staging-like environment.
- Multi-region/HA/failover validation is outside this document and remains a separate production-readiness track.
