# Pre-Sprint-4 Production Readiness and Legal Content Hardening

Date: 2026-06-21

Status: READY FOR SPRINT 4 ARCHITECTURE PLANNING WITH GUARDED SCOPE

This pass is limited to compliance/legal/content safety, dependency-warning triage, demo-data safety, and Sprint 4 risk checklist preparation. It does not start Sprint 4, does not implement remediation execution, does not add Terraform execution, and does not deploy to AWS.

## Scope Checked

- Compliance framework seed catalog: `apps/api/app/compliance/seeds/framework_catalog_v1.json`
- Compliance evidence and scoring language: `apps/api/app/services/compliance_evidence.py`
- Compliance assistant refusal and answer templates: `apps/api/app/services/compliance_answer.py`
- Compliance API user-facing score/dashboard/export wording: `apps/api/app/api/v1/endpoints/compliance.py`
- Compliance frontend copy: `apps/web/src/components/compliance/compliance-console.tsx`, `apps/web/src/app/(dashboard)/page.tsx`
- Sprint 3 closeout and demo docs: `docs/sprint-3-demo-acceptance.md`, `docs/sprint-3-closeout.md`
- Sprint 3 demo seeding and acceptance safety checks: `apps/api/scripts/seed_sprint3_demo.py`, `apps/api/tests/test_sprint3_phase8_demo_acceptance.py`

## Legal and Content Posture

- GDPR and HIPAA entries are public-source-linked summaries, not full regulatory text.
- SOC 2 and ISO/IEC 27001 entries are internal summaries. The seed catalog explicitly states that licensed standard text is not copied and requires licensed/legal review before official wording is used.
- Assistant answers include a not-legal-advice caveat and describe evidence-supported posture rather than legal compliance guarantees.
- Assistant refusal logic blocks legal guarantees, certification claims, raw provider payload requests, secret exposure, and remediation execution requests.
- UI copy uses evidence-supported posture and review status language.
- Legacy dashboard/export score labels were hardened from `compliant` / `non_compliant` style values to posture-oriented labels: `evidence_supported`, `at_risk`, and `high_risk`.

## Warning Triage

| Warning area | Classification | Action |
| --- | --- | --- |
| Compliance-owned `datetime.utcnow()` usage | Must fix before Sprint 4 where low-risk | Replaced in compliance evidence/scoring and compliance API endpoints with a UTC helper that preserves existing naive UTC DB values. |
| Other first-party `datetime.utcnow()` usage | Production hardening later | Auth, gateway, audit, approvals, and older engine paths remain outside this short pass to avoid broad behavioral changes. |
| Pydantic class-based `Config` | Low-risk first-party fix | Updated small response schema files to `ConfigDict(from_attributes=True)`. |
| Redis `close()` deprecation | Safe to defer unless warning reappears in focused tests | No compliance-path change made. |
| LangGraph serializer pending deprecation | Production hardening later | Track before persistent LangGraph state is enabled for remediation planning. |
| botocore datetime warnings | Dependency-owned | Do not patch dependencies; monitor upstream and pin/upgrade during dependency hygiene. |

## Demo Data Safety

- Demo email is fake and syntactically valid: `demo.admin@authclaw-demo.com`.
- Legacy `.local` demo email fallback exists only to migrate older local seeded users to the valid fake email.
- Demo password is a local demo-only credential, not a real secret.
- Demo data uses fake tenant, fake integrations, fake findings, sanitized evidence summaries, and fake knowledge documents.
- Demo seed does not make external provider calls.
- Demo seed does not call an LLM.
- Demo seed does not execute Terraform, scripts, CLI remediation, or cloud changes.
- Raw provider payload and secret-like strings are guarded by safety tests and redaction checks.

## Sprint 4 Risk Checklist

- Command execution safety: Sprint 4 must never run shell commands, cloud CLIs, or generated scripts without explicit human approval and sandbox controls.
- Terraform plan/apply separation: planning artifacts may be generated, but `terraform apply` must remain a separate, explicitly approved human action.
- HITL approval gates: every remediation candidate must require tenant-authorized, expiring, auditable approval before execution is even considered.
- Sandboxing: generated remediation artifacts must be rendered and validated in an isolated workspace; no access to production credentials by default.
- Rollback: every proposed change should include rollback notes or reversible steps before approval.
- Auditability: remediation planning, approval, rejection, and execution state transitions must emit tenant-scoped audit events.
- Tenant isolation: remediation plans, findings, approvals, and credentials must remain tenant-scoped and RLS-safe.
- Provider credential safety: no raw credentials in prompts, logs, UI, exports, or assistant responses; use vault references only.
- No automatic destructive actions: deletion, privilege removal, public access changes, and policy rewrites require explicit scoped approval.

## Recommended Sprint 4 Architecture Prompt Guardrails

- Start with architecture only: threat model, data model, state machine, APIs, approval gates, audit events, and test plan.
- Do not implement remediation execution in the first Sprint 4 phase.
- Keep generated remediation artifacts non-executing until a later approved phase.
- Require deterministic policy checks before any generated action can be queued.
- Separate recommendation, plan generation, approval, execution, rollback, and verification states.
- Treat Terraform, cloud CLI, repository mutation, and IAM changes as high-risk action classes.
- Add tests for refusal, redaction, tenant isolation, approval expiry, replay protection, and audit integrity before enabling execution.

## Remaining Safe Follow-Ups

- Complete broader first-party timezone modernization outside the compliance path.
- Review and modernize Redis close/dependency lifecycle warnings if they appear in current dependency versions.
- Add explicit LangGraph serializer allow-list before remediation state persistence.
- Run legal/licensed-content review before shipping official SOC 2 or ISO wording.
- Replace fake/demo knowledge with reviewed content packages under clear licensing.
- Validate AWS deployment in a separate release-readiness track.
