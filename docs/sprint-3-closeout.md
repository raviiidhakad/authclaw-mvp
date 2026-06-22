# AuthClaw Sprint 3 Closeout

## Final Verdict

READY WITH MINOR FOLLOW-UPS.

Sprint 3 Compliance Intelligence is complete for local/demo acceptance. Core backend flows, frontend console, deterministic assistant behavior, tenant isolation, demo dataset, and safety gates pass. Remaining items are dependency hygiene, production compliance review, real embedding/source licensing work, deployment planning, and future Sprint 4 remediation planning. None are Sprint 3 blockers.

## Scope Completed

Sprint 3 delivered the complete local compliance intelligence path:

```text
SecurityFinding
-> FindingControlMapping
-> EvidenceItem
-> ComplianceAssessment
-> ComplianceGap
-> Recommendation
-> KnowledgeDocument / KnowledgeChunk
-> RetrievalTrace
-> Compliance Assistant answer/refusal
-> Compliance frontend console
```

## Phases Completed

- Phase 1: Compliance catalog models, framework/control seeds, read-only catalog APIs.
- Phase 2: Finding-to-control mapping engine and mapping APIs.
- Phase 3: Evidence lifecycle, assessments, deterministic scoring, gaps APIs.
- Phase 4: Knowledge ingestion, retrieval traces, safe retrieval APIs.
- Phase 5: Compliance assistant backend with deterministic answer/refusal path.
- Phase 6: Compliance API consolidation, RBAC, tenant isolation, filters, pagination, and contracts.
- Phase 7: Compliance frontend console, evidence/gaps/recommendations/knowledge/assistant pages.
- Phase 8: Fake demo dataset, backend/frontend E2E acceptance, demo docs, local seeded demo.

## Backend Modules Delivered

- `apps/api/app/models/compliance.py`
  - `ComplianceFramework`
  - `ComplianceControl`
  - `ControlRequirement`
  - `FindingControlMapping`
  - `EvidenceItem`
  - `ComplianceAssessment`
  - `ControlAssessmentResult`
  - `ComplianceGap`
  - `KnowledgeDocument`
  - `KnowledgeChunk`
  - `RetrievalTrace`
  - `AgentComplianceSession`
- `apps/api/app/schemas/compliance.py`
  - Framework, control, mapping, evidence, assessment, gap, recommendation, knowledge, retrieval, and assistant contracts.
- `apps/api/app/services/compliance_seed_loader.py`
  - Deterministic framework/control catalog seeding.
- `apps/api/app/services/compliance_mapper.py`
  - Deterministic finding-to-control mapping rules.
- `apps/api/app/services/compliance_evidence.py`
  - Evidence refresh, assessment scoring, gap detection.
- `apps/api/app/services/compliance_knowledge.py`
  - Curated ingestion, text sanitization, lexical retrieval, citations, retrieval traces.
- `apps/api/app/services/compliance_answer.py`
  - Deterministic compliance assistant answer/refusal behavior.
- `apps/api/scripts/seed_sprint3_demo.py`
  - Idempotent local fake demo dataset.

## APIs Delivered

Sprint 3 compliance API surface includes:

- `GET /api/v1/compliance/frameworks`
- `GET /api/v1/compliance/frameworks/{framework_id}`
- `GET /api/v1/compliance/frameworks/{framework_id}/controls`
- `GET /api/v1/compliance/controls/{control_id}`
- `GET /api/v1/compliance/mappings`
- `GET /api/v1/compliance/findings/{finding_id}/mappings`
- `GET /api/v1/compliance/controls/{control_id}/mappings`
- `PATCH /api/v1/compliance/mappings/{mapping_id}/review`
- `POST /api/v1/compliance/assessments/run`
- `GET /api/v1/compliance/assessments`
- `GET /api/v1/compliance/assessments/{assessment_id}`
- `GET /api/v1/compliance/assessments/{assessment_id}/controls`
- `GET /api/v1/compliance/evidence`
- `GET /api/v1/compliance/evidence/{evidence_id}`
- `GET /api/v1/compliance/gaps`
- `GET /api/v1/compliance/gaps/{gap_id}`
- `GET /api/v1/compliance/recommendations`
- `GET /api/v1/compliance/knowledge`
- `GET /api/v1/compliance/knowledge/{document_id}`
- `POST /api/v1/compliance/knowledge/ingest`
- `POST /api/v1/compliance/retrieval/query`
- `POST /api/v1/compliance/ask`
- `GET /api/v1/compliance/ask/sessions`
- `GET /api/v1/compliance/ask/sessions/{session_id}`

## Frontend Pages Delivered

- `/compliance`
- `/compliance/frameworks`
- `/compliance/frameworks/[frameworkId]`
- `/compliance/controls/[controlId]`
- `/compliance/evidence`
- `/compliance/gaps`
- `/compliance/recommendations`
- `/compliance/knowledge`
- `/compliance/assistant`

Shared frontend data hooks in `apps/web/src/hooks/use-data.ts` cover the Sprint 3 API contracts. E2E coverage lives in `apps/web/tests/e2e.spec.ts`.

## Demo Dataset

Seed script:

```text
apps/api/scripts/seed_sprint3_demo.py
```

Local demo tenant:

```text
slug: authclaw-sprint3-demo
email: demo.admin@authclaw-demo.com
password: demo-only-password
```

Seeded local demo summary from the closeout run:

```text
integrations: 3
findings: 10
mappings: 38
evidence: 10
assessments: 1
gaps: 12
knowledge_documents: 16
retrieval_traces: 2
assistant_sessions: 2
```

Demo findings include AWS public S3, CloudTrail missing, KMS weakness, IAM over-permission, GitHub dummy secret exposure, branch protection missing, GitHub Actions broad permissions, GCP public bucket, GCP overbroad IAM, and synthetic PII/PHI exposure.

Demo documentation:

```text
docs/sprint-3-demo-acceptance.md
```

## Acceptance Results

Final closeout gate results:

- Sprint 3 Phase 1-8 backend tests: `46 passed`
- Backend collection: `409 collected`
- Regression subset: `29 passed`
- Full backend suite: `392 passed, 17 skipped`
- Frontend typecheck: passed
- Frontend lint: passed
- Frontend build: passed
- Playwright: `17 passed`
- Docker Compose config: passed
- Demo login: `200 OK`
- Compliance frontend page: `200 OK`

After correcting the demo email from the reserved `.local` domain to `demo.admin@authclaw-demo.com`, the affected Phase 8 backend acceptance was rerun and passed: `1 passed`.

## Safety Verification

Verified Sprint 3 safety properties:

- Demo data is fake and deterministic.
- No real customer data is seeded.
- No real AWS, GitHub, or GCP credentials are required.
- No external provider API calls are required for demo acceptance.
- No LLM calls are required for demo acceptance.
- Raw provider payloads are not exposed through compliance responses or frontend tests.
- Assistant refuses legal guarantee requests.
- Assistant refuses raw payload or secret requests.
- Assistant refuses remediation execution requests.
- Assistant answers include citations and confidence.
- UI and assistant use evidence-supported posture language, not legal compliance guarantees.
- Recommendations are derived from gaps and have no execute/apply controls.

## Known Limitations

- Framework catalog content is curated summary content, not licensed verbatim source text.
- Mappings are deterministic and require legal/compliance expert review before production use.
- Retrieval is lexical fallback, not pgvector-backed semantic retrieval.
- Demo data is synthetic and is not audit evidence for a real environment.
- Deployment to AWS was intentionally not performed in Sprint 3.
- Remediation execution was intentionally not implemented in Sprint 3.

## Follow-Up Classification

| Follow-up | Classification | Notes |
| --- | --- | --- |
| Remaining first-party `datetime.utcnow()` warnings | Before production | Compliance-owned usage was hardened in the pre-Sprint-4 pass; continue timezone modernization in auth, gateway, audit, approvals, tests, and older engine paths. |
| botocore datetime warnings | Safe to defer | Dependency hygiene item already tracked; monitor upstream. |
| Pydantic class-based config warnings | Before production | Move legacy schemas/config to `ConfigDict` where applicable. |
| LangGraph serializer warning | Safe to defer | Set explicit `allowed_objects` before production hardening if LangGraph persists state. |
| pgvector / real embedding provider | Next sprint candidate | Needed for scale/semantic retrieval, not Sprint 3 acceptance. |
| Real compliance source licensing | Before production | Legal/content review required before customer-facing framework claims. |
| Legal review of framework mappings | Before production | Required before production positioning or sales use. |
| AWS deployment | Safe to defer | Separate deployment track; not a Sprint 3 blocker. |
| Sprint 4 remediation execution planning | Next sprint candidate | Plan only after closeout approval; execution path remains absent. |

## Recommended Next Track

Recommended next track: Sprint 3 final approval, then a short production-readiness/legal-content hardening track before Sprint 4 remediation execution planning.

Sprint 4 should not begin until the owner explicitly approves the closeout and confirms the remediation execution guardrails.
