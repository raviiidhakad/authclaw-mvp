# AuthClaw Frontend PDF Alignment

Date: 2026-06-23

Source: `AuthClaw_Project_Plan.pdf`, Section 3 Product Navigation & IA and Section 8.3 Phase 3 Developer Experience Console.

## PDF Checklist

- Overview: live posture, open approvals, redaction and traffic KPIs.
- Gateway: route table, provider/model routing, redaction strategy, live traffic inspector.
- Policies & Guardrails: policy editor, validation status, guardrail taxonomy.
- Agent & Remediation: assistant, scan results, remediation plans, HITL approvals, safe execution visibility.
- Frameworks: SOC2/GDPR/HIPAA scoring, control drilldown, evidence linkage.
- Audit & Trust Center: searchable audit explorer, integrity badge, reports/evidence/export access.
- Risk & Red Teaming: probe runs, vulnerability register, go/no-go posture.
- Integrations: cloud, SCM, and provider connection status with safe credential handling.
- Settings: tenant/admin profile, MFA, API keys, model-provider lifecycle, rate-limit/admin gaps.

## Coverage

- Implemented top-level sidebar IA matching the PDF.
- Added top-level `Frameworks` route using the existing compliance framework console.
- Added top-level `Agent & Remediation` route using existing remediation APIs and links to assistant, findings, plans, and approvals.
- Added top-level `Risk & Red Teaming` safe backend-gap route with no fake probe or vulnerability rows.
- Gateway now surfaces route/provider configuration and redaction modes from real hooks before the live inspector.
- Overview no longer uses fake provider health or hardcoded operational claims.
- Audit explorer no longer claims backend hash-chain verification when only local digest preview is available.
- Settings no longer renders provider secrets, raw generated API keys, or manual MFA secret text.

## Backend Gaps

- Risk/red-team probe APIs, vulnerability-register APIs, and go/no-go posture APIs are not implemented.
- Audit hash-chain verification endpoint is not wired to the frontend; the page shows a backend-proof-needed state.
- Rate-limit tier and user/RBAC management remain partial settings/admin surfaces unless backend endpoints are expanded.

## Safety Notes

- No public unauthenticated share UI was enabled.
- No real cloud, GitHub, Terraform, or remediation mutation was added.
- No legal compliance guarantee wording was added.
- Raw provider payloads, Vault references, credentials, private keys, raw IP/user-agent, and secret-looking sample values are redacted or absent from the aligned UI surfaces.
