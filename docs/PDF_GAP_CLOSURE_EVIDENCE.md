# PDF Gap Closure Evidence

## Audit Architecture

AuthClaw uses PostgreSQL as the authoritative immutable audit ledger and ClickHouse as a read-optimized analytics mirror.

- Authoritative ledger: `apps/api/app/workers/audit_worker.py`, `apps/api/app/core/audit/integrity.py`, `apps/api/app/core/audit/repository.py`
- PostgreSQL model/migrations: `apps/api/app/models/audit.py`, `apps/api/alembic/versions/4ffee7ad38f6_stream4_audit_integrity.py`, `apps/api/alembic/versions/a3f9d2c81b47_refresh_tokens_reset_token_audit_trigger.py`
- ClickHouse mirror repository: `apps/api/app/core/audit/repository.py`
- ClickHouse local service/table setup: `docker-compose.yml`, `infrastructure/clickhouse/migrations/001_initial_audit_log.sql`

`AuditWorker.storage_status` records PostgreSQL write success/failure and ClickHouse mirror success/failure. ClickHouse mirror failures are logged as `clickhouse_audit_mirror_write_failed` and do not roll back the PostgreSQL ledger write.

## Kafka / Redpanda Evidence

- Producer: `apps/api/app/core/events/producer.py`
- Consumer base: `apps/api/app/workers/consumer_base.py`
- Audit/security workers started by API lifespan: `apps/api/app/main.py`
- Local Redpanda service: `docker-compose.yml`
- Focused proof test: `apps/api/tests/test_pdf_gap_audit_kafka_clickhouse.py`

Status: `MVP-complete local Kafka integration proof`; CI/staging proof is pending until the same command is run in that environment and attached to release evidence.

Local Docker proof command from repo root:

```bash
docker compose up -d db clickhouse redpanda api
docker compose exec -T -e AUTHCLAW_RUN_KAFKA_INTEGRATION=1 api python -m pytest tests/test_pdf_gap_audit_kafka_clickhouse.py -q
```

Current local result on 2026-07-07: `3 passed`.

CI/staging proof command:

```bash
AUTHCLAW_RUN_KAFKA_INTEGRATION=1 KAFKA_BROKERS=<staging-broker-list> python -m pytest tests/test_pdf_gap_audit_kafka_clickhouse.py -q
```

Without `AUTHCLAW_RUN_KAFKA_INTEGRATION=1`, the live Redpanda test is skipped so normal unit CI does not depend on Docker.

## OPA / Rego Runtime Evidence

- Gateway integration: `apps/api/app/core/policy/opa_integration.py`
- OPA HTTP evaluator: `apps/api/app/core/policy/opa_runtime.py`
- Sanitized OPA input builder: `apps/api/app/core/policy/opa_input.py`
- Rego policy bundle: `apps/api/opa/gateway.rego`
- Local OPA sidecar service: `docker-compose.yml`
- Mocked fail-closed proof: `apps/api/tests/test_pdf_gap_phase4_opa_runtime.py`
- Real sidecar proof: `apps/api/tests/test_pdf_gap_phase8_real_opa_sidecar.py`
- Runtime guide: `docs/opa-policy-runtime.md`

Status: `Enterprise MVP complete`; production HA/staging validation is pending until the same tests run against the target OPA deployment topology.

Local Docker proof commands from repo root:

```bash
docker compose up -d opa api
docker compose exec -T api python -m pytest tests/test_pdf_gap_phase4_opa_runtime.py -q
docker compose exec -T -e ENABLE_REAL_OPA_SIDECAR_TESTS=true -e OPA_URL=http://opa:8181/v1/data/authclaw/gateway/decision api python -m pytest tests/test_pdf_gap_phase8_real_opa_sidecar.py -q
```

Current local result on 2026-07-07: Phase 4 OPA runtime tests `9 passed`; real OPA sidecar tests `5 passed`.

Staging/HA proof command:

```bash
ENABLE_REAL_OPA_SIDECAR_TESTS=true OPA_URL=<staging-opa-policy-url> python -m pytest tests/test_pdf_gap_phase8_real_opa_sidecar.py -q
```

## Vault / KMS Encryption Evidence

- Envelope encryption entrypoint: `apps/api/app/core/encryption/__init__.py`
- KMS provider: `apps/api/app/core/encryption/kms.py`
- Vault Transit provider: `apps/api/app/core/encryption/vault.py`
- Local fallback provider: `apps/api/app/core/encryption/local.py`
- Local Vault service: `docker-compose.yml`
- KMS envelope proof: `apps/api/tests/security/test_envelope_encryption.py`
- Vault Transit proof: `apps/api/tests/security/test_vault_provider.py`
- Staging checklist: `docs/release/staging-deployment-readiness-checklist.md`

Status: `Enterprise MVP complete`; production Vault/KMS validation, policies, recovery, and operator rotation drills are pending until run in staging or production-equivalent infrastructure.

Local proof commands from repo root:

```bash
docker compose exec -T api python -m pytest tests/security/test_envelope_encryption.py -q
docker compose exec -T api python -m pytest tests/security/test_vault_provider.py -q
```

Current local result on 2026-07-07: KMS envelope tests `5 passed`; Vault Transit tests `3 passed`.

Production/staging validation checklist:

- Run the Vault provider test against the staging Vault Transit endpoint with staging-only credentials.
- Run an app-level provider credential create/read/rotate/revoke smoke using the selected staging encryption provider.
- For AWS KMS, validate `GenerateDataKey`, `Decrypt`, old-ciphertext decrypt after key rotation, and failure behavior with a staging KMS key or alias.
- Capture Vault/KMS policy, audit log, recovery, and rotation evidence in the staging release package.

## SOC2 Auditor Workflow Evidence

- Auditor workflow guide: `docs/compliance/soc2-auditor-workflow.md`
- Evidence automation checklist: `docs/compliance/soc2-evidence-automation-checklist.md`
- Evidence package APIs: `apps/api/app/api/v1/endpoints/evidence_packages.py`
- Trust/report APIs: `apps/api/app/api/v1/endpoints/trust.py`, `apps/api/app/api/v1/endpoints/reports.py`
- Evidence/report builder: `apps/api/app/services/trust_reporting.py`
- Audit export verification: `apps/api/app/core/audit/package_verification.py`
- Trust console UI: `apps/web/src/components/trust/trust-report-console.tsx`
- Compliance console UI: `apps/web/src/components/compliance/compliance-console.tsx`

Status: `Enterprise MVP complete`; external SOC2 auditor validation and formal attestation are pending.

Focused proof commands from repo root:

```bash
docker compose exec -T api python -m pytest tests/test_sprint5_phase2_report_generation.py tests/test_sprint5_phase3_trust_reporting_api.py -q
docker compose exec -T api python -m pytest tests/test_sprint3_phase6_compliance_api_contracts.py -q
docker compose exec -T api python -m pytest tests/test_e4_4_audit_export_contracts.py tests/test_e4_4_audit_export_builder.py -q
```

Current local result on 2026-07-07: Trust/report/evidence APIs `12 passed`; compliance API contracts `4 passed`; audit export contracts/builder `18 passed`.

The workflow is evidence-supported only. It does not claim SOC2 certification, SOC2 compliance, legal assurance, or an external audit result.

## External Pentest Readiness Evidence

- Scope and rules of engagement: `docs/security/pentest-scope.md`
- Threat model: `docs/security/threat-model.md`
- Security evidence package: `docs/security/security-evidence-package.md`
- Pre-pentest checklist: `docs/security/pre-pentest-checklist.md`
- Finding triage/remediation workflow: `docs/security/pentest-remediation-workflow.md`
- Red-team/risk APIs and tenant-scoped register proof: `apps/api/tests/test_risk_red_teaming_mvp.py`
- CI security checks: `.github/workflows/ci-security.yml`, `.github/workflows/ci-container.yml`

Status: `Enterprise MVP complete for pentest readiness`; external pentest execution, vendor report, and external retest evidence are pending.

Minimum vendor handoff scope includes API gateway/auth, tenant isolation/RLS, audit export/integrity, encryption/Vault/KMS, remediation approval and MFA workflow, web console auth/session behavior, and cloud/IaC review. Remediation evidence must include finding ID, severity, owner, fix commit, regression test or proof, and retest result. No external vulnerabilities are claimed as verified until a real third-party assessment is completed.

Focused local proof command from repo root:

```bash
docker compose exec -T api python -m pytest tests/test_risk_red_teaming_mvp.py -q
```

## Terraform / AWS Readiness Evidence

- Terraform root: `infrastructure/terraform`
- Bootstrap remote state: `infrastructure/terraform/bootstrap`
- Environment stacks: `infrastructure/terraform/environments/dev`, `infrastructure/terraform/environments/staging`, `infrastructure/terraform/environments/prod`
- AWS modules: `vpc`, `kms`, `iam`, `ecs`, `rds`, `redis`, `msk`, `vault`, `monitoring`
- Terraform guide: `infrastructure/terraform/README.md`
- Staging deployment checklist: `docs/release/staging-deployment-readiness-checklist.md`
- HA/failover/backup runbooks: `docs/ops/ha-resilience-architecture.md`, `docs/ops/failover-runbook.md`, `docs/ops/backup-restore-runbook.md`

Status: `Enterprise MVP complete for Terraform readiness`; AWS apply/state validation is pending.

Local validation commands from `infrastructure/terraform`:

```bash
terraform fmt -check -recursive
cd bootstrap && terraform init -backend=false && terraform validate
cd ../environments/dev && terraform init -backend=false && terraform validate
cd ../staging && terraform init -backend=false && terraform validate
cd ../prod && terraform init -backend=false && terraform validate
```

Current local result on 2026-07-07: Terraform v1.15.7 ran locally with backend disabled. `fmt -check -recursive` passed. `init -backend=false` and `validate` passed for bootstrap, dev, staging, and prod roots. No AWS apply or state write was run.

Required AWS apply/state evidence before production approval:

- Bootstrap S3/DynamoDB backend creation output.
- `terraform plan` artifact for staging/prod.
- Approved `terraform apply` output with remote state path and lock table.
- Captured outputs for ALB, ECS cluster, RDS, Redis, MSK, VPC, WAF, and Vault.
- Post-apply health checks for API, workers, OPA, Vault, Redis, Redpanda/MSK, RDS, and ClickHouse/analytics equivalent.
- Rollback/destroy or break-glass plan reviewed before apply.

## HA / Multi-Region Readiness Evidence

- HA architecture: `docs/ops/ha-resilience-architecture.md`
- Failover runbook: `docs/ops/failover-runbook.md`
- Backup/restore runbook: `docs/ops/backup-restore-runbook.md`
- Staging/prod Terraform: `infrastructure/terraform/environments/staging`, `infrastructure/terraform/environments/prod`
- HA modules: ECS desired count/autoscaling, RDS Multi-AZ, Redis automatic failover, MSK three-broker staging/prod, Vault desired count with DynamoDB backend, monitoring backup validator

Status: `Enterprise MVP complete for HA readiness`; 99.99 uptime, active-active multi-region, staging failover, and chaos proof are external pending.

Required staging validation before production approval:

- Deploy staging from Terraform and capture service endpoints, remote state, and health outputs.
- Run rolling restart and single-task failure drills for API/web/workers while gateway smoke tests pass.
- Run RDS failover or PITR restore drill and prove RLS/tenant smoke plus audit continuity.
- Run Redis failover drill and prove rate limiting, locks, and scoped worker-token behavior recover or fail closed.
- Run MSK broker failure/consumer recovery drill and prove event lag drains.
- Run Vault seal/unseal or HA failover drill and prove credential access fails closed while unavailable.
- Run backup restore drills for report artifacts, audit export packages, and analytics data.
- Record measured RTO/RPO/SLO results; do not claim 99.99 until sufficient uptime and failover evidence exists.
- Active-active multi-region requires a separate regional traffic, data-replication, conflict, and failback test record.

## Dependabot Evidence

`.github/dependabot.yml` covers:

- `pip` at `/apps/api`
- `npm` at `/apps/web`
- `github-actions` at `/`

All schedules are weekly with `dependencies` and `security` labels.

## Test Commands

```bash
cd apps/api
pytest tests/test_pdf_gap_audit_kafka_clickhouse.py -q
pytest tests/test_clickhouse_repository.py tests/test_audit_concurrency.py -q
```

## Remaining Risk

ClickHouse is intentionally a mirror, not the source of truth. Production readiness still requires staging evidence that Redpanda, PostgreSQL, and ClickHouse are all healthy and that ClickHouse mirror failures are monitored operationally.
