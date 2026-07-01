# SOC2 Evidence Automation Checklist

Status: operational checklist for AuthClaw evidence-supported posture review. This checklist maps existing automation to reviewer evidence and known manual review needs. It is not an external audit result, legal attestation, or assurance report.

## Checklist Fields

- **Control area**: SOC2-aligned area covered by current AuthClaw evidence.
- **Evidence source**: Existing service, API, report artifact, or package.
- **Freshness check**: How reviewers determine whether evidence is current enough for the selected review window.
- **Owner/reviewer**: Role expected to review or maintain the evidence.
- **Export artifact**: Artifact or package that carries the evidence.
- **Verification method**: Hash, manifest, chain proof, access log, package verification, or manual reviewer check.
- **Automation status**: Current support level.
- **Manual review need**: What still needs human review before external use.

## Evidence Checklist

| Control area | Evidence source | Freshness check | Owner/reviewer | Export artifact | Verification method | Automation status | Manual review need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Framework/control catalog | `framework_catalog_v1.json`, compliance framework APIs | Catalog version and active status | Compliance owner, auditor | Evidence package metadata | Framework ID and control IDs in package filters | Implemented | Licensed text and external wording review |
| Logical access protection | Users, roles, tenant isolation tests, report permissions | Latest user/role snapshot and access log window | Tenant admin, auditor | Evidence package, report access logs | Tenant ID, actor ID, role permissions, hashed access metadata | Implemented | Confirm role assignments match review scope |
| API key handling | API key show-once/hash-only behavior and revoke tests | Key state timestamp and audit event timestamp | Security owner, auditor | Evidence package | Sanitized event metadata and hash-only records | Implemented | Confirm inactive keys are expected |
| Provider credential protection | Vault-backed provider credential path and provider validation metadata | Last credential validation and provider status | Security owner, auditor | Evidence package | Sanitized provider metadata, no raw credential or Vault reference | Implemented | Confirm provider inventory is complete |
| Gateway policy enforcement | Gateway traffic metadata, policy decisions, OPA mode metadata | Traffic/event time range in package filters | Security owner, auditor | Evidence package, audit export | Decision metadata, route/provider/model/status/latency/redaction summary | Implemented | Confirm selected routes are in review scope |
| OPA/Rego runtime mode | Policy engine mode metadata and fail-closed tests | Test execution timestamp and deployment config snapshot | Security owner, auditor | Evidence package, closeout docs | Sanitized decision metadata and test result references | Partial | Real sidecar validation remains pending locally |
| Redaction/tokenization | Redaction summaries, reversible tokenization tests, gateway metadata | Tokenization test run and traffic sample window | Security owner, auditor | Evidence package | Sanitized summaries and no raw PII in exposed surfaces | Implemented | Confirm token vault operational mode for environment |
| Safe streaming | Streaming regression evidence and metadata-only audit records | Streaming test run timestamp | Security owner, auditor | Evidence package, closeout docs | UTF-8/SSE/state-machine regression references | Implemented | Confirm streaming providers included in scope |
| HITL and action-bound MFA | Remediation approvals, MFA envelope audit events, execution attempts | Approval expiry and execution timestamp | Security owner, auditor | Evidence package | Bound tenant/user/action/artifact/policy-check metadata | Implemented | Confirm high-risk actions selected for review |
| Scoped worker tokens | Worker token creation/validation/revocation audit events | Token issue/expiry/revoke timestamp | Security owner, auditor | Evidence package | Hash-only token record and sanitized worker validation event | Implemented | Confirm worker types included in review |
| Tenant-plan rate limiting | Tenant plan configuration and abuse control events | Rate-limit event time range | Platform owner, auditor | Evidence package | Sanitized rate-limit metadata and tenant plan identifier | Implemented | Confirm expected limits for selected tenant plan |
| Audit logging | Audit records, security events, report access logs | Event timestamp and review window | Security owner, auditor | Evidence package, audit export | Tenant ID, timestamp, sanitized event payload | Implemented | Confirm source systems are connected |
| Cryptographic audit export | E4.4 package builder, chain proof, signing abstraction, verification service | Export generation and verification timestamp | Security owner, auditor | Signed audit export package | Manifest, chain proof, signature, verification result | Implemented | Confirm trusted signing key policy for environment |
| Trust/report access logs | `report_access_logs` and Trust Center access log view | Access log timestamp and artifact ID | Trust owner, auditor | Report access log list | Hashed IP, hashed user-agent, actor ID, action | Implemented | Confirm external share use is approved |
| Evidence package generation | EvidencePackageBuilder and evidence package APIs | `evidence_freshness_days`, date range, run status | Compliance owner, auditor | Evidence package JSON | Manifest hash, content hash, artifact metadata | Implemented | Confirm package scope and stale evidence decisions |
| Remediation verification | Remediation verification records and dry-run/safe execution outputs | Verification timestamp and plan state | Security owner, auditor | Evidence package | Plan ID, verification state, sanitized evidence | Implemented | Confirm no real destructive action is in demo scope |
| CI/security scans | CI results, local security scan summaries where available | Latest run timestamp and branch/commit | Release owner, auditor | Evidence package, release notes | Workflow status and scanner output references | Partial | Attach current CI artifacts during actual review |
| External pentest readiness | Pentest scope, threat model, remediation workflow | Document version and review date | Security owner, auditor | Security evidence package docs | Document review and owner sign-off | Prepared | External pentest execution remains separate |

## Freshness Review

1. Select a review period and `evidence_freshness_days`.
2. Confirm all package filters reflect that period.
3. Mark evidence outside the selected period as stale or reviewer-needed.
4. Confirm report artifacts have not expired before reviewer download.
5. Confirm access logs show who downloaded or reviewed each artifact.
6. Bind reviewer notes to artifact ID, manifest hash, and package ID.

## Export And Verification Checklist

- Evidence package run status is `completed`.
- Artifact has `content_hash`, `size_bytes`, `sanitization_version`, and `manifest_hash`.
- Manifest endpoint returns `manifest_json`, `manifest_hash`, and `hash_algorithm`.
- Download response includes a watermark with tenant ID, requester ID, artifact ID, timestamp, and manifest hash.
- Access logs show metadata-only review/download events.
- Audit export package verification returns a deterministic state for package integrity, manifest consistency, chain proof, signature, version support, and tenant consistency.
- Cross-tenant package verification is rejected.
- Report payloads do not include raw provider payloads, provider keys, Vault references, decrypted PII, or private keys.

## Demo Tenant Evidence Status

For a demo-ready tenant, prepare and confirm:

- SOC2 framework catalog entries are loaded.
- At least one access-control mapped control has evidence.
- At least one monitoring/auditability mapped control has evidence.
- Evidence package generation succeeds with a freshness window.
- The generated package has a manifest hash.
- At least one package artifact is downloaded through the report download endpoint.
- Report access logs display the download with hashed access metadata.
- Audit export verification is available for cryptographic evidence packages.
- Gaps or stale evidence are visible as reviewer-needed items.

## Remaining Manual Review

- Validate official framework wording with licensed material before external use.
- Attach current CI/security scan artifacts for the exact release being reviewed.
- Confirm production infrastructure evidence after AWS deployment.
- Complete real OPA sidecar validation when the OPA runtime is available locally or in staging.
- Complete external pentest execution and remediation evidence as a separate track.
- Review all tenant-specific sharing decisions before artifact distribution.
