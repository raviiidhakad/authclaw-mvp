# AuthClaw Security Evidence Package

Status: evidence index for external pentest readiness. It summarizes implemented controls and test evidence available in the repository. It is not a legal attestation or external pentest report.

## Control Summary

| Area | Implemented Evidence | Validation Evidence |
| --- | --- | --- |
| Tenant isolation | Tenant-scoped API queries, RLS-oriented tests, cross-tenant tests across gateway, reports, remediation, audit export. | Backend tests include cross-tenant isolation suites and per-epic tenant boundary tests. |
| Provider credentials | Provider keys stored through Vault/secret abstraction; API/frontend responses expose metadata only. | Provider validation and gateway contract tests check no raw key/Vault ref leakage. |
| AuthClaw API keys | Gateway keys are generated, shown once, hashed at rest, revocable, and tenant-bound. | API key singleton/revocation tests and gateway authentication tests. |
| Gateway fail-closed policy | Route/provider/policy resolution occurs before provider egress; policy errors fail closed. | Gateway MVP phase tests and OPA Phase 4 tests. |
| Redaction/tokenization | Mask/hash/synthetic redaction and reversible tokenization paths are tested. | E2.1 tokenization tests, gateway redaction tests, streaming security tests. |
| Safe streaming | UTF-8 decoder, SSE parser, streaming state machine, safe streaming security integration. | E2.3 streaming suite and closeout tests. |
| Sanitized audit retention | Raw gateway audit retention disabled by default; previews/hashes stored instead of raw payloads. | Gateway phase 5 audit tests and audit export tests. |
| Action-bound MFA | High-risk/destructive remediation approval binds tenant/user/action/plan/artifact/policy-check/risk/scope/expiry/nonce. | PDF gap Phase 2 authorization hardening tests. |
| Scoped worker tokens | Worker tokens are scoped, short-lived, revocable, hash-only at rest, and replay-resistant. | PDF gap Phase 2 worker-token tests. |
| Tiered rate limiting | Tenant-plan, key, route, provider, model, and abuse-control dimensions implemented. | PDF gap Phase 3 rate-limit tests and gateway benchmark regressions. |
| OPA/Rego modes | `python`, `opa`, and `hybrid` policy modes; OPA errors fail closed in authoritative mode. | OPA runtime/integration tests and Phase 4 OPA proof tests. |
| Cryptographic audit export | Canonical export package, manifest, chain proof, ES256 signing abstraction, verification service, Trust Center state mapping. | E4.4 phase tests and package verification tests. |
| Trust/report access logs | Trust/report artifacts are tenant-scoped, sanitized, and access logged. | Sprint 5 report/trust API tests. |
| CI/security scanning | Previous release workflows included unit/integration/contract/security checks such as Bandit, Semgrep, OSV, pip-audit, and Trivy where configured. | GitHub checks must be collected for the exact pentest candidate build before assessment starts. |

## Evidence Artifacts to Provide to Testers

- `docs/security/pentest-scope.md`
- `docs/security/threat-model.md`
- `docs/security/pre-pentest-checklist.md`
- `docs/security/pentest-remediation-workflow.md`
- Gateway MVP closeout docs.
- E2.1 tokenization test results.
- E2.2 OPA/YAML policy test results.
- E2.3 streaming closeout.
- E4.4 audit export closeout.
- E4.3 performance closeout.
- Latest GitHub Actions run for the assessment branch.
- Latest dependency/security scan artifacts.

## Sensitive Data Handling Evidence

Expected behavior:

- Provider keys are never returned after creation/update.
- Vault references are not exposed in API/frontend output.
- Gateway errors are sanitized.
- OPA input omits raw prompts and provider payloads.
- Reports and audit exports use sanitized metadata.
- Share links remain disabled unless explicitly enabled for a test case.

## Audit and Evidence Retention

For the assessment build, collect:

- API logs.
- Worker logs.
- Gateway traffic metadata.
- Security events.
- Audit export verification results.
- Trust/report access logs.
- Rate-limit events.
- MFA challenge/verification/failure events.
- Worker-token issuance/validation/revocation events.

Store pentest evidence in a restricted repository or evidence vault with:

- Finding ID.
- Severity.
- Owner.
- Affected version/commit.
- Reproduction steps.
- Sanitized proof.
- Remediation commit.
- Retest evidence.

## Known Evidence Gaps Before External Pentest

- External pentest has not yet been performed.
- Real OPA sidecar validation is pending for a staging-like environment.
- Multi-region/HA/failover/chaos validation is pending.
- AWS deployment and production network controls are not in scope for this local evidence package.
- Production load benchmark in cloud-like infrastructure remains separate from local benchmark evidence.
