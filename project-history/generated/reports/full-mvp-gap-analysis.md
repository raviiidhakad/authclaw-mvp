# AuthClaw Full MVP Gap Analysis

Date: 2026-06-29

Scope: Compare `AuthClaw_Project_Plan.pdf` against the current repository state after Sprint 1-5, Gateway MVP Phases 1-6, real-provider validation work, frontend PDF alignment, and the Risk & Red Teaming MVP implementation.

Important safety note: this audit intentionally does not inspect or print local provider keys, `.env` secret values, real customer data, or deployed infrastructure credentials.

## A. Executive Summary

AuthClaw is now a strong local/demo enterprise MVP with broad backend and frontend coverage across gateway security, cloud integrations, compliance intelligence, remediation workflow, trust/reporting, notifications, activity timelines, and risk/red-teaming. The project is much closer to the PDF vision than the early audit state, but it is still not fully aligned with the PDF's production-grade enterprise gateway and compliance platform requirements.

The most important distinction is this:

- The product is demo-ready and locally usable for the current OpenAI-compatible gateway scope.
- The product is not yet a full PDF-complete production platform because several PDF-level guarantees remain partial: native reverse proxy breadth, token-by-token streaming filtering, full OPA/Rego runtime, cryptographic audit export maturity, production hardening, AWS deployment, and real-data validation.

### Readiness Estimates

These percentages are engineering estimates based on code/docs present in the repository, not a claim of production certification.

| Readiness area | Estimate | Meaning |
| --- | ---: | --- |
| Overall PDF MVP readiness | 72% | Most major modules exist, but key PDF-grade production guarantees remain partial. |
| Local demo readiness | 88% | Sprint closeouts show working demo flows for compliance, remediation, trust/reporting, gateway, and risk surfaces. |
| Real-data readiness | 62% | Provider/connector paths exist and live Groq validation is gated, but broad live-provider/cloud validation is still limited. |
| Production readiness excluding AWS deployment | 52% | Security architecture is solid, but HA, load, full audit export, hardening, CI stability, and operational runbooks need work. |
| AWS deployment readiness | 32% | Docker/local stack exists and deploy workflows exist, but AWS rollout is intentionally deferred and not validated. |

### Current Verdict

AuthClaw is best described as:

**Enterprise local/demo MVP: READY WITH FOLLOW-UPS**

**PDF-complete production MVP: NOT READY YET**

The remaining work is not a rewrite. It is concentrated in a few high-impact areas: full gateway/proxy maturity, streaming guarantees, policy runtime maturity, cryptographic evidence export, real-data/live-provider validation, CI/deployment reliability, and production operations.

## B. PDF Requirement Baseline

The PDF defines three core pillars:

| PDF pillar | Requirement summary |
| --- | --- |
| In-Line Security Gateway / Proxy | Low-latency reverse proxy between clients and foundation models; redact PII/PHI and enforce policy before provider egress. |
| Agentic Compliance Autopilot | Map findings to frameworks, draft remediation, and execute only after explicit human approval. |
| Continuous Observability & Audit Trail | Tamper-proof append-only log of model I/O, agent reasoning, approvals, and exportable cryptographically verifiable evidence. |

The PDF's strongest technical requirements include:

| PDF requirement | Target |
| --- | --- |
| FR-1.1 | Multi-model proxying for OpenAI, Anthropic, Cohere, Azure OpenAI with native payload compatibility. |
| FR-1.2 | Real-time PII/PHI redaction with mask, SHA-256 plus salt hash, and synthetic replacement. |
| FR-1.3 | YAML plus OPA policy enforcement, topic blocking, and regex blocking. |
| FR-2.1 | Orchestrator-worker isolation with scoped temporary tokens. |
| FR-2.2 | Context-aware framework querying via RAG over regulatory docs. |
| FR-2.3 | HITL workflow with pending approval, 0.5 hour expiry, and MFA on execution. |
| FR-3.1 | Automated framework scoring for SOC 2, GDPR, and HIPAA. |
| FR-3.2 | Cryptographically verified audit export. |
| NFR-1.1 | Gateway overhead <= 50 ms per request. |
| NFR-1.2 | Token-by-token streaming filtering with no fragmentation. |
| NFR-2.1 | Tenant isolation via RLS and/or physical isolation. |
| NFR-2.2 | Envelope encryption with AES-256-GCM via KMS/Vault for client credentials. |
| NFR-3.1 | 99.99% uptime and multi-region active-active architecture. |
| NFR-3.2 | Tiered rate limiting and background worker throttling. |

## C. Requirement Coverage Matrix

Legend:

- `Complete`: Implemented for the current MVP scope with tests/docs.
- `Partial`: Meaningful implementation exists, but it does not fully satisfy the PDF requirement.
- `Missing`: Not implemented or not proven in the repository.
- `Deferred`: Intentionally left out by project scope so far.

| Area | PDF requirement | Current status | Evidence in repo | Gap / risk |
| --- | --- | --- | --- | --- |
| Gateway proxy foundation | Go/Rust low-latency reverse proxy | Partial | FastAPI gateway in `apps/api/app/core/engine/gateway.py`; OpenAI-compatible route in `apps/api/app/api/openai_compat.py`; closeout in `docs/gateway-mvp-closeout.md` | Current implementation is Python/FastAPI and scoped to chat completions, not a native Go/Rust reverse proxy. |
| OpenAI-compatible chat completions | External client can call AuthClaw like OpenAI | Complete for MVP | `/v1/chat/completions`; `docs/gateway-external-agent-mvp.md`; gateway phase tests | Good for current agent/SDK demo scope. |
| Native provider breadth | OpenAI, Anthropic, Cohere, Azure OpenAI native payload compatibility | Partial | Provider adapters in `apps/api/app/core/providers/adapters/*`; phase 6 provider contract tests | Adapters normalize to OpenAI-compatible shape; not full native reverse-proxy coverage for every provider API. |
| Groq/OpenAI-compatible live path | Real provider validation path gated and safe | Partial | `ENABLE_PROVIDER_LIVE_VALIDATION`, `ENABLE_GATEWAY_LIVE_E2E`; `test_gateway_mvp_phase3.py`; user validation track | Gated live validation exists, but broad live-provider test matrix is not required in CI. |
| AuthClaw gateway API key | Tenant gateway key for external agents | Complete for MVP | `apps/api/app/api/v1/endpoints/api_keys.py`; `apps/api/tests/test_api_keys_singleton.py` | Current behavior supports one active gateway-capable key per tenant; new key revokes previous. |
| Provider credentials | Server-side provider keys, metadata-only validation | Partial to complete | Vault credential services in `apps/api/app/services/provider_credentials.py` and `vault_credentials.py`; provider API tests | Local/dev defaults and legacy encrypted fallback need production hardening; live validation is deliberately gated. |
| Inbound redaction | PII/PHI detected and redacted before egress | Partial | Presidio engine, custom recognizers, gateway fail-closed path, tests | Strong MVP path exists, but production quality depends on recognizer coverage, tuning, and false-positive/false-negative testing. |
| Redaction modes | Mask, hash, synthetic | Partial | `RuleType.pii_redact`, `pii_synthetic`; token vault tests; gateway route redaction modes | Hashing is present, but PDF calls for SHA-256 plus salt; reversible tokenization exists separately and needs clearer gateway-wide integration. |
| Streaming filtering | Token-by-token, no fragmentation | Partial | Strict buffered safe streaming in `apps/api/app/core/engine/streaming.py`; passthrough blocked | Current gateway buffers and scans before release; safe, but not PDF's token-by-token streaming with no fragmentation and backpressure. |
| Policy-as-code | YAML policy enforcement | Partial to complete | `apps/api/app/core/policy/yaml_policy.py`; policy cache/evaluator; policy UI | YAML path exists; runtime enforcement is Python adapter seam, not full OPA/Rego. |
| OPA runtime | OPA validates traffic | Partial | `full_opa_runtime=False`, `adapter_seam` in YAML policy compiler | Full OPA/Rego runtime is explicitly not implemented yet. |
| Topic and regex blocking | Enterprise policy topic/regex controls | Partial | YAML validation for regex, content filter/rules | Runtime support needs a stronger proof path for topic/regex semantics across gateway and UI-created policies. |
| Fail-closed gateway behavior | Security failures must not leak data | Complete for MVP | Gateway phase tests around scanner failure, provider errors, policy failure | Good MVP posture; needs load/chaos validation. |
| Outbound response scanning | Provider response checked before client release | Partial | Gateway outbound scan/redaction logic; streaming safe buffer tests | Implemented for gateway scope, but needs live-provider and long-stream validation. |
| Traffic inspector | Route/provider/model/status/latency/redaction visibility | Partial to complete | Gateway traffic endpoints and frontend pages | Works for current gateway. Needs production privacy review and clickthrough consistency. |
| Latency target | <=50 ms overhead | Partial | `docs/performance/gateway_mvp_latency.md` shows mocked p95 overhead 9.194 ms | Local mocked benchmark meets target; not proven under live provider, production DB, event backbone, concurrency, or full audit writes. |
| Tenant isolation | RLS / physical isolation | Partial to complete | RLS migrations, app tenant context, cross-tenant tests | RLS exists; some tables such as auth/API-key lookup require application-layer compensation. Physical isolation is not implemented. |
| RBAC | Owner/admin/operator/auditor/viewer style access controls | Partial | `require_roles`, trust/report permissions, frontend gating | Broad coverage exists; needs full product-wide RBAC matrix review and negative tests for every endpoint. |
| Envelope encryption | AES-256-GCM via KMS/Vault | Partial | `core/encryption/*`, Vault credential services, provider credential path | Strong design exists; production KMS/Vault setup and rotation not fully proven. |
| Event backbone | Kafka/Redpanda producer/consumer scaffolding | Partial to complete | `core/events/producer.py`, workers, Redpanda in compose | Local event backbone exists; production durability, DLQ operations, replay, and SLOs need hardening. |
| Immutable audit log | ClickHouse hash-chained audit trail | Partial | Audit models, ClickHouse repository, worker, hash verification | Hash-chain paths exist, but direct gateway logging and ClickHouse best-effort behavior mean PDF-grade immutable audit is not fully proven. |
| Cryptographic audit export | Export validates cryptographically | Partial | Trust report manifests, hashes, audit verification service | Evidence/report manifests exist, but full signed/verifiable audit export package is not PDF-complete. |
| Compliance scoring | SOC 2/GDPR/HIPAA framework posture | Complete for demo, partial for production | Sprint 3 models/services/frontend; `project-history/historical/sprints/sprint-3-closeout.md` | Good deterministic local/demo compliance intelligence; production legal/content review and live evidence validation remain. |
| Compliance assistant | RAG-style answers over compliance data | Partial | `compliance_answer.py`, knowledge services, assistant pages | Safe deterministic answers exist; true production-grade regulatory RAG/source licensing remains follow-up. |
| Cloud connectors | AWS/GCP/GitHub findings ingestion | Partial | Connector services/workers and Sprint 2 closeout | Connectors exist; real enterprise account validation, permissions matrix, retries, and deployment health need more proof. |
| Agentic remediation | Generate remediation plans from findings/gaps | Complete for safe MVP | Sprint 4 services/models/API/frontend; `project-history/historical/sprints/sprint-4-closeout.md` | Real mutation execution remains intentionally disabled. |
| HITL approval | 0.5 hour expiry, approval workflow | Partial to complete | Approval TTL 30 minutes, approval services/tests | Approval lifecycle exists. Production MFA binding and identity assurance need stronger end-to-end validation. |
| Remediation execution | Apply changes only after approval | Partial | Safe execution adapters, dry-run, sandbox, no real cloud mutation | Safe MVP is implemented; PDF eventual real Terraform/CLI/cloud apply path is deferred. |
| Trust/reporting | Trust Center, reports, evidence packages | Complete for demo, partial for production | Sprint 5 closeout, report/evidence services, frontend pages | Strong demo/reporting platform; cryptographic/signed export and production storage lifecycle need hardening. |
| Downloads/share links | Controlled downloads and gated sharing | Partial | Sprint 5 phase 5 tests and share-link models | Public unauthenticated share consumption remains intentionally absent. |
| Notifications/activity | Enterprise timeline and notifications | Complete for demo | `trust_activity.py`, notification pages/tests | Needs scale and retention policy hardening. |
| Risk & Red Teaming | Red-team harness and vulnerability register | Partial | `models/risk.py`, `services/risk_red_teaming.py`, risk endpoint/page | Safe simulated module exists; continuous adversarial execution against live models is not enabled by default. |
| Admin/settings | Provider, routes, policies, users, API keys, tenant settings | Partial | Settings, gateway/provider/routes/API-key pages and APIs | Broad UI exists; production admin completeness, auditability, and RBAC polish remain. |
| Developer docs/API docs | External agent examples and SDK guidance | Partial | Gateway docs with curl/Python/Node placeholders | Needs versioned public API docs, SDK package, and compatibility tests against real clients. |
| CI quality gates | Backend/frontend/security/container/contract/integration checks | Partial | `.github/workflows/*`, closeout verification docs | CI has workflows, but prior baseline failures and local full-suite stalls mean final required-check health must be revalidated. |
| Local infrastructure | DB, Redis, Vault, Redpanda, ClickHouse, API, worker, web | Complete for local demo | `docker-compose.yml` | Local stack is useful; production topology is not equivalent. |
| Production HA | 99.99%, multi-region active-active | Missing | Deploy workflow files exist, but no validated deployment report | Major PDF NFR gap. |
| AWS deployment | Production deployment on AWS | Deferred | Deploy workflow files; AWS repeatedly deferred in prompts/closeouts | Not deployed or proven. |
| Pentest/SOC observation | External hardening/audit window | Missing/deferred | No evidence of external pentest or SOC observation | Required for real enterprise claims. |

## D. Top 10 Biggest Gaps

1. Full native gateway reverse proxy is not complete.

   The current gateway is accepted for OpenAI-compatible chat completions, but the PDF wants a low-latency reverse proxy preserving native provider compatibility across OpenAI, Anthropic, Cohere, and Azure OpenAI.

2. Streaming is safe but not PDF-complete.

   Current strict buffered streaming prevents leakage, which is the right safety posture. However, the PDF requires token-by-token filtering with no fragmentation and production backpressure behavior.

3. Full OPA/Rego runtime is missing.

   YAML policy-as-code and a Python adapter seam exist, but the repository explicitly marks `full_opa_runtime` as false.

4. Cryptographic audit export is not mature enough.

   Hash-chain verification, ClickHouse repository support, manifests, and report hashes exist. The PDF expects a high-confidence cryptographically verifiable export flow over the audit record chain.

5. Production-grade audit path is split.

   Gateway direct logging stores sanitized previews/hashes in Postgres, while the event-backed ClickHouse path exists separately. PDF-level immutable audit should make the authoritative path clearer and harder to bypass.

6. Redaction/tokenization needs production consolidation.

   Mask/hash/synthetic and token vault pieces exist, but PDF-level SHA-256 plus salt hashing, reversible maps per tenant, and consistent gateway-wide mode semantics need tightening.

7. Real-data and live-provider validation is limited.

   Groq/OpenAI-compatible live validation is gated and safe, but the broader matrix across provider types, cloud connectors, streaming, audit, and real tenant workflows is not yet continuously proven.

8. CI and local full-suite stability need renewed proof.

   Sprint closeouts show many passing focused suites, but Sprint 5 closeout notes a full backend suite stall on the local Windows runner, and earlier GitHub checks had baseline failures. Required CI checks should be green before any production claim.

9. Production operations are still thin.

   The PDF calls for HA, multi-region active-active, uptime targets, worker throttling, load testing, pentesting, and operational evidence. Local Docker Compose is not a production operations substitute.

10. Risk/red-team is safe/demo oriented.

   The module now exists, but it is intentionally simulated/safe by default. A continuous adversarial harness against live models and routed policies remains a future hardening track.

## E. Frontend Gap Analysis

### Frontend Coverage Already Present

The repository contains dashboard routes for the major PDF modules:

| Frontend area | Evidence |
| --- | --- |
| Dashboard / overview | `apps/web/src/app/(dashboard)/page.tsx` |
| Gateway playground | `apps/web/src/app/(dashboard)/gateway/page.tsx` |
| Gateway providers | `apps/web/src/app/(dashboard)/gateway/providers/page.tsx` |
| Gateway routes | `apps/web/src/app/(dashboard)/gateway/routes/page.tsx`, `apps/web/src/app/(dashboard)/gateway-routes/page.tsx` |
| Gateway traffic | `apps/web/src/app/(dashboard)/gateway/traffic/page.tsx` |
| Gateway API keys | `apps/web/src/app/(dashboard)/gateway/api-keys/page.tsx` |
| Policies and violations | `apps/web/src/app/(dashboard)/policies/page.tsx`, `policies/violations/page.tsx` |
| Compliance | `apps/web/src/app/(dashboard)/compliance/*` |
| Integrations/findings | `integrations/page.tsx`, `findings/page.tsx` |
| Remediation | `remediation/*`, `approvals/page.tsx`, `agent-remediation/page.tsx` |
| Trust Center | `trust/*` |
| Reports | `reports/*` |
| Notifications/activity | `notifications/page.tsx`, `trust/activity/page.tsx` |
| Risk & Red Teaming | `risk/page.tsx` |
| Settings/admin | `settings/page.tsx` |

### Frontend Strengths

- The UI now looks like an enterprise console rather than a marketing page.
- Major PDF navigation areas exist.
- Gateway pages expose the practical workflow: create provider, create route, create key, test gateway, inspect traffic.
- Trust/reporting pages expose report metadata, manifests, evidence packages, access logs, notifications, and timeline.
- Remediation pages expose plans, approvals, jobs, dry runs, and verification in a safe way.
- Risk & Red Teaming has a connected page and backend API surface.
- The UI copy has been hardened to avoid legal-compliance guarantees.

### Frontend Gaps

| Gap | Impact |
| --- | --- |
| Some flows still depend on local seed/migration freshness | User may see 404/500 if the API container is stale or migrations are not current. The risk page screenshot showing a 404 is likely this class of issue because the backend route file is present. |
| Not all pages have proven real-backend E2E coverage | Playwright coverage exists, but some tests are mocked or demo-seeded. Real API smoke coverage should be expanded. |
| Gateway UI is scoped to chat completions | Matches current MVP, not full native proxy breadth. |
| No production-grade admin matrix visible | RBAC exists but needs a full page-by-page permission matrix and denied-state QA. |
| No full public developer portal | External agent docs exist in markdown, but a polished versioned developer-doc UX is not yet present. |
| No live CI/deployment status surface | Useful for enterprise trust, but not required for local MVP. |
| No public unauthenticated trust/share UX | Intentionally disabled; remains future scope if desired. |

## F. Backend Gap Analysis

### Backend Strengths

The backend is now broad and relatively mature for a local enterprise MVP:

- FastAPI API surface with versioned `/api/v1` routes.
- OpenAI-compatible `/v1/chat/completions` gateway route.
- Provider adapters for Groq/OpenAI-compatible, OpenAI, Anthropic, Cohere, Azure OpenAI, and Gemini code presence.
- Vault-backed provider credential services.
- Gateway API keys stored as hashes, with one active gateway-capable key per tenant.
- Presidio/custom-recognizer redaction pipeline.
- YAML policy compiler and runtime adapter seam.
- Policy cache/evaluator.
- Gateway route/provider/model resolution.
- Inbound and outbound fail-closed security checks.
- Strict buffered safe streaming.
- Audit models, hash chaining, ClickHouse repository, audit worker, and verification service.
- Tenant isolation with RLS migrations and application tenant context.
- Cloud connector services for AWS/GCP/GitHub.
- Compliance models, scoring, evidence, knowledge, assistant, and gap/recommendation services.
- Remediation state machine, deterministic plan generation, HITL approvals, dry-run/sandbox/safe execution.
- Trust/reporting/export sanitizer/evidence package services.
- Notifications and activity timeline.
- Risk & Red Teaming models/services/API.

### Backend Gaps By System

#### Gateway

Current gateway is the most important partial area. It works for the OpenAI-compatible chat-completions MVP, but PDF-level requirements are larger:

- Not a Go/Rust native reverse proxy.
- Not full native payload compatibility across all provider APIs.
- Streaming is buffered safe, not token-by-token.
- Full OPA/Rego runtime is not active.
- Live-provider validation is manual/gated and not required in CI.
- Performance target is proven only with mocked upstream and mocked/local audit path.

#### Redaction and Policy

Strong MVP coverage exists, but production work remains:

- Need tenant-salted hash mode consistency.
- Need clear linkage between token vault and every gateway redaction mode.
- Need stronger topic/regex runtime proof.
- Need long-prompt, multilingual, PHI, and adversarial evasion tests.
- Need production false-positive/false-negative analysis.

#### Audit and Evidence

The project has the right building blocks, but PDF-level audit claims require more:

- Choose and enforce one authoritative immutable audit write path.
- Ensure all gateway, agent, remediation, approval, report, and risk actions enter the hash-chain/export path.
- Add signed export packages, verification CLI/API, and auditor-friendly proof docs.
- Prove no raw prompt/response/provider payload appears in exported surfaces.

#### Agentic Remediation

The safe MVP is strong. The missing part is intentionally risky and should stay gated:

- No real Terraform apply/destroy.
- No real cloud/GitHub mutation.
- MFA binding should be validated end-to-end.
- Scoped temporary worker tokens need production proof.
- Rollback behavior needs real environment validation after architecture approval.

#### Compliance Intelligence

The demo path is complete enough for local acceptance:

- SOC 2/GDPR/HIPAA framework scoring and evidence/gap/recommendation flows exist.
- Assistant behavior is deterministic and caveated.

Production gaps:

- Legal/source licensing review for framework content.
- Real evidence ingestion quality.
- Auditor review of exported reports.
- Stronger RAG/source citation if using dynamic regulatory content.

#### Integrations

Connectors are implemented but need production validation:

- Sandbox AWS/GCP/GitHub test accounts.
- Least-privilege IAM/OAuth permission matrix.
- Rate limits and retry behavior under real provider failures.
- Worker health checks and operational dashboards.
- No raw provider payload leakage in reporting/audit.

#### Trust/Reporting

The reporting platform is demo-ready:

- Templates, report runs, artifacts, manifests, evidence packages, downloads, access logs, notifications, timeline exist.

Remaining PDF gaps:

- Signed cryptographic audit exports.
- External auditor packaging and verification UX.
- Production storage backend and retention enforcement.
- Public share consumption if business scope requires it.

#### Risk & Red Teaming

Safe MVP exists:

- Probe categories, vulnerability register, posture summary, APIs, frontend route, and safe seed/demo data.

Remaining:

- Continuous adversarial execution harness.
- Live model/provider route testing under strict safety gates.
- Regression corpus for prompt injection, data disclosure, credential leakage, harmful content, and sycophancy/policy bypass.
- Link risk findings into compliance/remediation/trust reports with stronger evidence.

## G. PDF Alignment Verdict

### What Is Strongly Aligned

- Inbound security gateway concept exists.
- AuthClaw external gateway key concept exists and is usable.
- Provider credentials stay server-side.
- Route/provider/model configuration exists.
- PII detection and policy blocking/redaction exist.
- Human approval remediation workflow exists.
- Compliance scoring and evidence/gap mapping exist.
- Trust Center and reporting exist.
- Risk/red-team module exists.
- Tenant isolation and RBAC are established.
- Local infrastructure has Postgres, Redis, Vault, Redpanda, ClickHouse, API, worker, and web.

### What Is Partially Aligned

- Gateway provider breadth.
- Streaming safety.
- OPA policy runtime.
- Cryptographic audit export.
- Rate limiting tiers.
- Real connector validation.
- MFA-bound execution.
- Continuous red-team harness.
- Production CI/quality gates.
- Production deployment readiness.

### What Is Not Yet Aligned

- Go/Rust low-latency reverse proxy.
- Full native provider passthrough/proxy breadth.
- Token-by-token no-fragmentation streaming.
- Full OPA/Rego runtime.
- 99.99% uptime / multi-region active-active architecture.
- External pentest and SOC observation window.
- AWS production deployment.
- Production-grade cryptographic audit export package.

### Final Alignment Statement

AuthClaw has reached a credible local enterprise MVP state, but the PDF describes a harder production-grade system. The project should not be marketed as fully PDF-complete, audit-ready, certified, or production-ready yet. It can be honestly positioned as:

> A local/demo enterprise AI security and governance MVP with a working OpenAI-compatible gateway, policy/redaction controls, compliance intelligence, safe remediation workflow, trust/reporting, and risk/red-team foundations.

## H. Recommended Roadmap

### Phase 1 - Stabilize Current Local MVP

Goal: make the current product consistently usable on a developer machine and in demos.

Tasks:

- Ensure local Docker/API/web startup is one-command and documented.
- Ensure migrations and seed scripts are idempotent.
- Fix any 404/route mismatch issues, especially around newly added Risk & Red Teaming pages.
- Re-run backend focused suites and frontend Playwright smoke against real backend where practical.
- Confirm gateway key creation, provider credential creation, route creation, normal request, blocked request, redacted request, and traffic log all work end-to-end.
- Add a current `docs/local-demo-runbook.md`.

Acceptance:

- Fresh clone can start local stack and run demo flows.
- No raw secrets, Vault refs, raw provider payloads, or legal guarantee language appears.
- Current UI does not show stale/old dashboard variants.

### Phase 2 - Gateway PDF Gap Closure

Goal: bring the gateway closer to the PDF's core promise.

Tasks:

- Decide whether to keep Python gateway for MVP or start a Go/Rust proxy track.
- Implement full OPA/Rego runtime or formally scope it out.
- Implement token-by-token safe streaming with backpressure and no fragmentation.
- Consolidate salted hash, synthetic, mask, and token-vault behavior.
- Expand native provider contract tests beyond chat completions.
- Add concurrent/load benchmark including audit/event path.

Acceptance:

- Gateway overhead is proven under realistic local load.
- Streaming does not leak and does not require full-response buffering for ordinary safe streams.
- Policy decisions are reproducible and auditable.

### Phase 3 - Audit Export And Trust Hardening

Goal: satisfy the PDF audit/evidence story.

Tasks:

- Make the hash-chain audit path authoritative.
- Add signed audit export packages.
- Add export verification CLI/API.
- Ensure reports reference audit hashes/manifests consistently.
- Add auditor-facing documentation.
- Backfill/scrub legacy raw rows if any production migration requires it.

Acceptance:

- A generated evidence package can be independently verified against the audit chain.
- Export contents are sanitized and tenant-scoped.

### Phase 4 - Real-Data Validation

Goal: prove the system against safe, controlled external services.

Tasks:

- Use sandbox AWS/GCP/GitHub accounts.
- Run live provider validation for Groq/OpenAI/Anthropic/Cohere/Azure with fresh keys only.
- Validate connector permission errors and least-privilege docs.
- Validate remediation plans but keep mutation disabled unless a separate approval track exists.
- Expand red-team corpus against live routed models.

Acceptance:

- Real provider/cloud tests pass without secret leakage.
- Provider keys never appear in logs, DB exports, UI, or docs.
- No destructive external actions are possible by default.

### Phase 5 - Production Readiness Excluding AWS Deployment

Goal: make quality gates reflect real production risk.

Tasks:

- Repair and lock GitHub required checks.
- Add CI jobs for backend focused suites, frontend build, Playwright smoke, security scans, container build, contract tests, and integration tests.
- Add runbooks for secrets, backups, incident response, audit verification, and key rotation.
- Add observability dashboards and alerting definitions.
- Add threat model and pentest preparation docs.

Acceptance:

- CI is green on main.
- No meaningful tests are skipped without documented reason.
- Security scanners are not weakened.

### Phase 6 - AWS Deployment Architecture And Rollout

Goal: only after local/product readiness, prepare deployment.

Tasks:

- Finalize AWS architecture with VPC, ECS/EKS, RDS, ElastiCache, MSK/Redpanda decision, ClickHouse/cloud alternative, Vault/KMS, WAF, ALB, logs, metrics.
- Create staging deployment first.
- Add migrations, seed, rollback, and blue/green strategy.
- Add external DNS/TLS and secret rotation plan.
- Perform load, failover, and backup/restore tests.

Acceptance:

- Staging is reproducible from IaC.
- Rollback is tested.
- No real production traffic before security signoff.

## I. Prompt For Next Phase

Use this as the next implementation prompt if the goal is to close the most urgent current gap without starting AWS deployment:

```text
AUTHCLAW CURRENT MVP STABILIZATION + PDF GAP CLOSURE PHASE 1

You are working in:
C:\Users\dhaka\OneDrive\Desktop\AuthClaw Project

Context:
- AuthClaw has completed Sprint 1-5, Gateway MVP Phases 1-6, frontend PDF alignment, and Risk & Red Teaming MVP foundations.
- The current project is local/demo enterprise MVP ready with follow-ups, but not PDF-complete production ready.
- Do not start AWS deployment.
- Do not add real cloud/GitHub/Terraform mutation.
- Do not expose provider keys, Vault refs, raw prompts, raw provider payloads, or legal compliance guarantees.

Goal:
Stabilize the current local MVP and fix any live API/UI mismatches so the product can be demoed end-to-end from a fresh local stack.

Required Work:
1. Verify local stack startup:
   - docker compose config --quiet
   - API health
   - DB/Redis/Vault/Redpanda/ClickHouse health where available
   - Alembic head
   - web on localhost:3000

2. Verify and fix route/API mismatches:
   - /gateway
   - /gateway/providers
   - /gateway/routes
   - /gateway/traffic
   - /policies
   - /compliance
   - /remediation
   - /trust
   - /reports
   - /risk
   - /settings

3. Verify demo seed and migrations:
   - seed scripts are idempotent
   - demo tenants/users are fake
   - no real credentials are seeded

4. Gateway smoke:
   - create one tenant gateway API key
   - confirm new key revokes previous gateway key
   - create provider credential using safe path
   - create route
   - run normal request
   - run policy-blocked request
   - run redaction request
   - confirm traffic/audit metadata
   - confirm no raw key/Vault ref/raw prompt leak

5. Risk & Red Teaming smoke:
   - ensure backend routes are registered
   - ensure migrations create required tables
   - ensure frontend page calls the correct API paths
   - seed safe demo rows
   - verify tables/filter/posture load without 404

6. Verification:
   - backend focused tests for gateway, policies, risk, trust/reporting, remediation, compliance
   - frontend typecheck/lint/build
   - Playwright smoke for dashboard, gateway, policies, risk, trust/reporting
   - safety scan for gsk_, sk-, ghp_, xox, Vault refs, raw provider payloads, legal guarantee wording

Output:
- files changed
- bugs found/fixed
- local stack status
- demo smoke result
- tests run
- safety scan result
- remaining PDF gaps
- final local MVP go/no-go

Stop after local MVP stabilization. Do not start AWS deployment or broad native proxy rewrite.
```

## J. Recommended Product Positioning

Use careful language:

- "evidence-supported posture"
- "mapped controls"
- "needs review"
- "safe remediation workflow"
- "local/demo MVP"
- "OpenAI-compatible gateway scope"

Avoid:

- "legally compliant"
- "certified"
- "guaranteed audit-ready"
- "production-ready"
- "full native reverse proxy"
- "full OPA runtime"
- "real destructive remediation"

## K. Immediate Action List

Highest-priority next actions:

1. Run a fresh local stack and verify every top-level UI route.
2. Fix any API 404s or stale frontend calls.
3. Re-run focused backend tests for gateway, risk, compliance, remediation, trust/reporting.
4. Re-run frontend typecheck, lint, build, and Playwright smoke.
5. Produce a fresh safety scan.
6. Only after that, start Gateway PDF Gap Closure Phase 2.

## L. Final Verdict

AuthClaw has become a serious, broad, local enterprise MVP. The team has built most of the product surface described by the PDF, and many safety guardrails are stronger than a typical early MVP.

The project is not done. The core remaining challenge is no longer "build the screens" or "create the models." The challenge is to turn the current safe local MVP into a verified production-grade system with a PDF-complete gateway, audit export, policy runtime, streaming path, live-provider validation, and deployment posture.

Final status:

**Local enterprise demo: ready with follow-ups**

**Real-data pilot: partially ready, needs controlled validation**

**Production enterprise MVP: not ready**

**AWS deployment: deferred, not ready**
