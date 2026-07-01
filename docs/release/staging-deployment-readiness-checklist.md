# AuthClaw Staging Deployment Readiness Checklist

Date: 2026-07-01

Scope: checklist for preparing an AWS or equivalent staging deployment after PDF gap closure. This checklist does not deploy infrastructure and does not approve production launch.

## 1. Preconditions

| Item | Required evidence | Status |
| --- | --- | --- |
| Release branch reviewed | PR created, CI passed, security scans reviewed | Pending |
| Working tree clean | `git status` clean before deployment | Pending |
| Staging owner assigned | Deployment owner and rollback owner named | Pending |
| Change window approved | Time window and communication channel recorded | Pending |
| External systems identified | Provider APIs, OPA runtime, Vault, Redis, Redpanda, ClickHouse, Postgres, artifact storage | Pending |

## 2. Environment And Secrets

Do not paste secrets into tickets, docs, logs, or shell transcripts.

| Area | Checklist |
| --- | --- |
| Environment files | Staging environment variables created from examples, reviewed, and stored in the approved secret manager. |
| Provider keys | Fresh staging provider keys created; old demo keys rotated or revoked. |
| Vault | Vault initialized, unsealed, policy-scoped, and reachable only from approved services. |
| KMS or envelope encryption | Encryption provider selected and validated for staging. |
| OPA | `POLICY_ENGINE_MODE=opa` or approved hybrid staging mode set; `OPA_STRICT_MODE=true`; `OPA_FAIL_CLOSED=true`; `OPA_URL` points to staging OPA. |
| Redis | Staging Redis endpoint configured for rate limiting, tokenization caches, and worker coordination as applicable. |
| Redpanda/Kafka | Staging broker endpoint configured and event publishing tested. |
| ClickHouse | Staging ClickHouse endpoint configured and health checked. |
| Database | Staging Postgres URL configured; RLS and migrations validated. |
| Logging | Logs confirmed to exclude raw prompts, provider payloads, worker tokens, Vault refs, and provider keys. |

## 3. Database And Migration Checklist

1. Confirm current Alembic head locally and in staging.
2. Snapshot or back up the staging database before applying migrations.
3. Run migrations in staging.
4. Verify tenant RLS policies after migration.
5. Run smoke tests for gateway routes, risk/red-team APIs, audit export, Trust Center, and compliance evidence.
6. Confirm rollback procedure is documented and tested on a staging clone.
7. Retain migration logs without secrets.

## 4. Vault Setup

1. Confirm Vault initialization and unseal process.
2. Confirm service policies for API, workers, and read-only validation paths.
3. Validate provider credential create, read-by-reference, revoke, and rotation flows.
4. Validate Vault unavailable behavior for gateway and worker paths.
5. Confirm no Vault refs are exposed in API responses, logs, reports, or exports.

## 5. OPA Sidecar Setup

1. Load the approved Rego policy bundle into staging OPA.
2. Verify OPA health endpoint.
3. Run allow, block, redaction, malformed, timeout, and unavailable test cases.
4. Confirm denied requests do not call providers.
5. Confirm strict/fail-closed behavior.
6. Confirm OPA input excludes provider keys, Vault refs, worker tokens, and unsanitized upstream payload material.
7. Document OPA topology, scaling, and restart behavior.

## 6. Service Health Checks

| Service | Required check |
| --- | --- |
| API | `/health` and security-pipeline health pass. |
| Web | UI loads and dashboard auth boundary works. |
| Postgres | TCP and application DB session checks pass. |
| Redis | TCP and limiter/tokenization dependency checks pass. |
| Redpanda/Kafka | Broker health and event publish smoke pass. |
| Vault | `sys/health` pass and application secret lookup smoke pass. |
| ClickHouse | HTTP ping and audit/report write smoke pass. |
| OPA | Decision endpoint and policy bundle checks pass. |
| Connector worker | Worker heartbeat and scoped-token validation pass. |

## 7. Backup And Restore

1. Postgres backup created and restore tested on staging clone.
2. ClickHouse backup created and restore tested on staging clone.
3. Vault recovery process documented and tested with non-production data.
4. Artifact/report storage backup and restore tested.
5. Restore validation includes audit chain verification and report manifest verification.
6. RTO/RPO assumptions recorded as planning targets, not uptime promises.

## 8. CI And Security Artifacts

Before staging promotion, retain:

- GitHub Actions summary.
- Backend test summary.
- Frontend lint, typecheck, build summary.
- Dependency/security scan summaries.
- Secret scan summary for changed files.
- OPA sidecar validation output.
- Gateway benchmark summary.
- Local or staging resilience check output.

## 9. Smoke Test Plan

Run after deployment:

1. API health and security health.
2. Login and dashboard load.
3. Gateway mocked-provider allow/block/redact requests.
4. Optional Groq/OpenAI-compatible smoke with rotated staging key only.
5. YAML policy CRUD and OPA enforcement.
6. Reversible tokenization round trip with staging-safe values.
7. Streaming UTF-8/SSE smoke with harmless fixtures.
8. Risk/red-team safe probe run, vulnerability register, and posture read.
9. Trust Center report, audit export package generation, and verification.
10. Rate-limit behavior for each tenant plan tier.
11. Worker scoped-token validation.
12. Backup/restore verification on staging clone.

## 10. Rollback Plan

1. Stop new deployments.
2. Preserve logs and security evidence.
3. Revert application image to the previous staging release.
4. Restore database only if migration rollback is unsafe and a validated backup exists.
5. Revalidate Vault, Redis, Redpanda, ClickHouse, OPA, and API health.
6. Run smoke tests after rollback.
7. Open a remediation item for every rollback trigger.

## 11. Copy And Legal Review

Before sharing staging externally:

- Use evidence-supported language.
- Do not claim SOC2 certification or external audit approval.
- Do not claim uptime proof before production failover testing.
- Do not claim external pentest completion until external evidence exists.
- Ensure Trust Center, reports, docs, and UI avoid absolute safety claims.

## 12. Go/No-Go Checklist

| Gate | Go condition |
| --- | --- |
| CI | All required checks pass on the release PR. |
| Migrations | Staging migrations pass and rollback is documented. |
| Secrets | Staging secrets are rotated, scoped, and not exposed. |
| OPA | Real OPA sidecar validates allow/block/redact/fail-closed. |
| Gateway | Mocked provider and optional staging provider smoke pass. |
| Rate limiting | Tenant plan limits enforce expected behavior. |
| Audit export | Package generation and verification pass. |
| Risk/red-team | Safe probe run and posture API pass. |
| Resilience | Health checks and local/staging resilience checks pass. |
| Backup | Restore validated on staging clone. |
| Security docs | Pentest scope, threat model, and remediation workflow are ready. |

Staging recommendation: proceed only when every go condition is recorded with evidence.
