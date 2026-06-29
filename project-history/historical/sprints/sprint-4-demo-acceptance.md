# AuthClaw Sprint 4 Demo Acceptance

Date: 2026-06-22

## Scope

Sprint 4 Phase 9 proves the safe remediation lifecycle end to end:

Security finding or compliance gap -> remediation plan -> artifact -> rollback plan -> policy check -> HITL approval -> dry-run -> controlled safe execution job -> verification result -> API/UI visibility.

No real cloud, GitHub, Terraform, shell, credential, LLM, or deployment action is part of this demo.

## Seed Command

From `C:\Users\dhaka\OneDrive\Desktop\AuthClaw Project\apps\api`:

```powershell
$env:APP_DEBUG='false'
$env:DATABASE_URL='postgresql+asyncpg://authclaw_app:authclaw_app_password@127.0.0.1:5434/authclaw'
$env:ALEMBIC_DATABASE_URL='postgresql+asyncpg://postgres:password@127.0.0.1:5434/authclaw'
$env:REDIS_URL='redis://127.0.0.1:6379/0'
.\.venv\Scripts\python.exe scripts\seed_sprint4_demo.py
```

Demo login:

- Email: `sprint4.demo.admin@authclaw-demo.com`
- Password: `demo-only-password`

The dataset is idempotent and resets only the `authclaw-sprint4-demo` tenant data before recreating fake demo rows.

## Demo Scenarios

Scenario A: Safe documentation-only flow

- Source: synthetic low-risk security finding.
- Artifact: documentation-only, redacted, non-executable.
- Policy: passes.
- Approval: requested and approved.
- Dry-run: static documentation check succeeds.
- Execution job: controlled documentation-only adapter succeeds.
- Verification: verified with no external mutation attempted.

Scenario B: Simulated provider flow

- Source: synthetic CloudTrail finding and SOC 2 gap.
- Artifact: documentation-only artifact with `simulated_provider` adapter.
- Policy: passes with elevated review.
- Approval: owner-level approval with MFA flag and separation of duties.
- Dry-run: static check succeeds.
- Execution job: simulated adapter succeeds.
- Verification: states that no external provider was called and no resources were mutated.

Scenario C: Blocked mutation flow

- Source: synthetic critical IAM finding.
- Artifact: intentionally mutation-shaped Terraform/AWS draft.
- Policy: fails with blocking reasons.
- Approval: not issued.
- Dry-run/execution: no successful dry-run or execution.
- Job visibility: disabled job records the blocked reason.

## Expected API/UI Behavior

- `/api/v1/remediation/plans` shows all three flows.
- `/api/v1/remediation/dry-runs` shows successful dry-runs only for the safe flows.
- `/api/v1/remediation/jobs` shows two succeeded safe jobs and one disabled blocked job.
- `/api/v1/remediation/verification-results` shows two verified results.
- The remediation UI shows dry-run and verification records in job visibility.
- The UI exposes no execute/apply/Terraform/provider mutation controls.
- API/UI responses should not expose credentials, raw provider payloads, or legal compliance guarantees.

## Intentionally Blocked

- Terraform apply/destroy.
- AWS/GCP/GitHub mutation commands.
- GitHub PR creation or push.
- Shell/process execution.
- Provider credential retrieval.
- Raw provider payload display.
- Legal or audit-pass guarantee language.

## Known Limitations

- Execution remains limited to documentation-only, local no-op/static validation, and simulated provider adapters.
- Verification is a controlled MVP record, not a real provider-state check.
- AWS deployment remains deferred.
- Future Sprint 5 planning should keep plan/apply separation and HITL gates as hard requirements.

## Verification

Phase 9 verification commands and results are recorded in `docs/sprint-4-closeout.md`.
