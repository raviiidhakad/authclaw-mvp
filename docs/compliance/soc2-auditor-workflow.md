# SOC2 Auditor Evidence Workflow

Status: auditor workflow preparation for AuthClaw evidence review. This document describes how an auditor or customer reviewer can inspect evidence-supported posture using existing AuthClaw Trust Center, reporting, audit export, and verification surfaces. It is not an external audit result, legal attestation, or assurance report.

## Existing Implementation Evidence

- SOC2 framework summaries and controls are seeded in `apps/api/app/compliance/seeds/framework_catalog_v1.json`.
- SOC2 control mappings are produced by `apps/api/app/services/compliance_mapper.py`.
- Evidence package creation, filtering, and detail retrieval are exposed by `apps/api/app/api/v1/endpoints/evidence_packages.py`.
- Report templates, runs, artifacts, manifests, downloads, and access logs are exposed by `apps/api/app/api/v1/endpoints/reports.py`.
- Trust Center overview and posture APIs are exposed by `apps/api/app/api/v1/endpoints/trust.py`.
- Report permissions, artifact responses, manifest responses, and tenant scoping helpers are implemented in `apps/api/app/api/v1/endpoints/trust_common.py`.
- Trust reporting sanitization, manifest hashing, access metadata hashing, and evidence package event emission are implemented in `apps/api/app/services/trust_reporting.py`.
- Cryptographic audit export package verification is implemented in `apps/api/app/core/audit/package_verification.py`.
- The Trust Center report console shows evidence packages, manifest hashes, access logs, and verification status in `apps/web/src/components/trust/trust-report-console.tsx`.

## Auditor Persona

The auditor persona is a tenant-scoped, read-oriented reviewer who can inspect Trust Center posture, generate or retrieve evidence packages, download authorized artifacts, inspect metadata-only access logs, and verify package integrity. Existing role handling grants the `auditor` role report generation, artifact download, and report access log visibility while keeping tenant boundaries enforced.

The workflow uses evidence-supported posture language. Any formal conclusion remains outside AuthClaw automation and requires human review.

## Workflow

1. **Prepare a tenant-scoped review session**
   - Use a non-production or approved review tenant.
   - Assign the reviewer an `auditor`, `admin`, or `owner` role as appropriate.
   - Confirm that demo data or imported findings include mapped controls, evidence items, assessment results, gaps, and remediation verification records.

2. **Review framework and control mapping**
   - Inspect SOC2 framework summaries in the compliance catalog.
   - Confirm that controls such as `SOC2-SEC-ACCESS` and `SOC2-SEC-MONITOR` have mapped evidence expectations.
   - Use compliance evidence APIs or Trust Center posture views to confirm mapped controls, open gaps, and manual review needs.

3. **Request an evidence package**
   - Use the evidence package flow with optional `framework_id`, `control_ids`, date range, `evidence_freshness_days`, finding inclusion, and remediation inclusion.
   - The package is tenant scoped and JSON only in the current implementation.
   - The resulting run includes status, filters, artifact metadata, and manifest metadata.

4. **Inspect evidence freshness and scope**
   - Review the package request filters and retention window.
   - Confirm the freshness window used for evidence collection.
   - Treat missing, stale, or unmapped evidence as reviewer-needed items.

5. **Review manifest and hash metadata**
   - Retrieve the artifact manifest.
   - Confirm `manifest_hash`, `hash_algorithm`, artifact ID, tenant ID, and artifact metadata.
   - Use manifest metadata to bind reviewer notes to an exact artifact.

6. **Download and review the artifact**
   - Download through the authenticated report artifact endpoint.
   - The download response includes a sanitized artifact and a watermark containing requester ID, artifact ID, timestamp, manifest hash, and the language marker `evidence-supported posture; needs review`.
   - The download path records metadata-only access logs with hashed IP and user-agent values.

7. **Inspect access logs**
   - Review report access logs by artifact or tenant.
   - Confirm actor ID, action, external share reference when present, hashed IP, hashed user agent, and timestamp.
   - Access logs should be used as reviewer evidence that report artifacts were viewed or downloaded by authorized actors.

8. **Verify cryptographic audit package evidence when used**
   - For E4.4 audit export packages, run package verification through the verification service or API surface.
   - Review package integrity, manifest consistency, chain proof, signature status, supported versions, and tenant consistency.
   - Reject cross-tenant verification results and tampered packages.

9. **Record reviewer outcome**
   - Record whether each control is supported, stale, missing, or needs manual review.
   - Link comments to artifact ID, manifest hash, package ID, and verification state.
   - Do not convert the automated posture into a legal conclusion without the external review process.

## Primary API Surfaces

| Review need | Existing surface | Evidence exposed |
| --- | --- | --- |
| Trust posture | `GET /api/v1/trust/overview` and posture endpoints | Tenant-scoped security, controls, remediation, integration, and audit summaries |
| Evidence package creation | `POST /api/v1/evidence-packages` | Package run, artifact metadata, manifest metadata |
| Evidence package list/detail | `GET /api/v1/evidence-packages`, `GET /api/v1/evidence-packages/{package_id}` | Package status, filters, artifacts, manifest |
| Report runs | `GET /api/v1/reports/runs`, `GET /api/v1/reports/runs/{run_id}` | Run status, request filters, artifacts, manifest hash |
| Artifact metadata | `GET /api/v1/reports/artifacts`, `GET /api/v1/reports/artifacts/{artifact_id}` | Content hash, size, sanitization version, manifest hash |
| Manifest review | `GET /api/v1/reports/artifacts/{artifact_id}/manifest` | Manifest JSON, manifest hash, hash algorithm |
| Artifact download | `GET /api/v1/reports/artifacts/{artifact_id}/download` | Sanitized artifact and watermark |
| Access logs | `GET /api/v1/reports/access-logs`, `GET /api/v1/reports/artifacts/{artifact_id}/access-logs` | Metadata-only access events |
| Audit export verification | Audit export verification service/API | Verification state and sanitized metadata |

## Control-To-Evidence Mapping

| Control area | Evidence sources | Reviewer action |
| --- | --- | --- |
| Logical access protection | RBAC roles, API key status, tenant isolation tests, MFA approval records, scoped worker token events | Confirm access paths are tenant scoped and high-risk actions have fresh approval evidence |
| Monitoring and auditability | Security events, report access logs, audit hash chain, audit export package verification | Confirm evidence is complete, recent, and bound to manifest/hash metadata |
| Gateway policy enforcement | Gateway traffic metadata, policy decisions, OPA/Rego mode metadata, redaction summaries | Confirm blocked/redacted paths are recorded without raw provider payloads |
| Credential protection | Vault-backed provider credentials, API key hash-only storage, sanitized report exports | Confirm no raw keys, Vault references, or decrypted secrets appear in exported evidence |
| Remediation safety | HITL approval, action-bound MFA envelope, dry-run or simulated adapters, remediation verification records | Confirm destructive paths require fresh approval and safe execution mode is clear |
| Abuse control | Tenant plan rate limits, abuse events, rate-limit audit metadata | Confirm limit behavior and reviewer-visible metadata for rejected traffic |
| Audit export integrity | Manifest, chain proof, detached signature, verification result | Confirm package integrity and tenant consistency |

## Required Demo Evidence

A demo tenant should include:

- SOC2 framework and control catalog entries.
- Mapped controls such as `SOC2-SEC-ACCESS` and `SOC2-SEC-MONITOR`.
- Evidence items and assessment results.
- Gaps or reviewer-needed items.
- At least one generated evidence package with manifest metadata.
- At least one downloaded artifact so access logs are visible.
- At least one cryptographic audit export package verification result where available.
- Sanitized security event summaries for policy, audit, rate-limit, MFA, and worker-token events.

## Limitations

- This workflow prepares evidence for review; it does not replace an external audit.
- Framework text is stored as internal summaries and requires licensed-text review before official use.
- Freshness depends on connected data sources and the time range selected for the package.
- Real OPA sidecar validation remains a separate production proof item until completed.
- AWS production controls, multi-region resilience, backup, disaster recovery, and external pentest evidence remain separate readiness tracks.
- Evidence packages should be reviewed by a human owner before being shared outside the tenant.

## Safe Language

Use:

- evidence-supported posture
- mapped controls
- needs review
- reviewer-needed item
- auditor review required
- verification result
- tenant-scoped evidence

Avoid:

- legal assurance language
- claims that automation replaces an external audit
- claims that a control has a formal external conclusion without reviewer sign-off
