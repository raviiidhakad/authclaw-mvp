# AuthClaw Sprint 5 Demo Acceptance

Date: 2026-06-23

## Scope

Sprint 5 Phase 7 proves the enterprise trust/reporting flow end to end:

Trust Center posture -> report templates -> report runs -> artifact metadata and manifest -> controlled sanitized download metadata -> evidence package -> access logs -> notifications -> activity timeline.

No real cloud, GitHub, Terraform, shell, credential, LLM, or AWS deployment action is part of this demo.

## Seed Command

From `C:\Users\dhaka\OneDrive\Desktop\AuthClaw Project\apps\api`:

```powershell
$env:APP_DEBUG='false'
$env:DATABASE_URL='postgresql+asyncpg://authclaw_app:authclaw_app_password@127.0.0.1:5434/authclaw'
$env:ALEMBIC_DATABASE_URL='postgresql+asyncpg://postgres:password@127.0.0.1:5434/authclaw'
$env:REDIS_URL='redis://127.0.0.1:6379/0'
.\.venv\Scripts\python.exe scripts\seed_sprint5_demo.py
```

Demo login:

- Email: `demo.admin@authclaw-demo.com`
- Password: `demo-only-password`

The seed is idempotent and resets only the `authclaw-sprint5-demo` tenant-scoped data before recreating fake demo rows.

## Demo Dataset

The dataset includes:

- Trust Center overview data.
- Security, compliance, remediation, and integration posture data.
- One report template.
- Completed trust overview report run.
- Completed JSON evidence package run.
- Report artifacts and export manifests.
- Hashed report access logs.
- In-app notifications.
- Activity timeline rows from report, remediation, evidence, and integration records.

Share-link creation remains gated by `ENABLE_EXTERNAL_TRUST_SHARING=false` by default. No public unauthenticated share route is enabled.

## Acceptance Scenario

1. Login as `demo.admin@authclaw-demo.com`.
2. Open `/trust`.
3. Inspect `/trust/security`, `/trust/compliance`, `/trust/remediation`, and `/trust/integrations`.
4. Open `/reports/runs` and view or create a report run.
5. Open `/reports/artifacts`, inspect manifest metadata and manifest hash.
6. Use controlled authenticated artifact download metadata where enabled.
7. Open `/reports/evidence-packages` and create or inspect a JSON evidence package.
8. Open `/reports/access-logs` and confirm only hashed network metadata appears.
9. Open `/notifications`, mark one notification read, then mark all read.
10. Open `/trust/activity` and review sanitized activity timeline rows.
11. Confirm no raw payload, credential, Vault reference, raw IP/user-agent, public share control, or legal guarantee copy appears.

## Intentionally Absent

- Raw provider payload display.
- Raw report body display in the UI.
- Real provider credentials.
- Vault references in exported/user-facing payloads.
- Public unauthenticated share consumption.
- Real remediation/cloud/GitHub/Terraform execution.
- Legal compliance guarantee wording.

## Verification

Verification commands and results are recorded in `docs/sprint-5-closeout.md`.
