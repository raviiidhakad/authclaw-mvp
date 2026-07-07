# AuthClaw Failover Runbook

Status: operational runbook for local/staging readiness. Do not use it as proof of a production service level until staging and production drills have been executed.

## Safety Rules

- Do not run destructive tests against production.
- Do not delete volumes unless a verified backup exists and restore has been approved.
- Do not paste secrets, provider keys, Vault tokens, or database passwords into tickets or chat.
- Prefer isolated staging for failover drills.
- For destructive remediation paths, keep fail-closed behavior and action-bound MFA requirements intact.

## Pre-Failover Checklist

1. Identify affected tenant(s), service(s), and environment.
2. Record current commit, release tag, and deployment version.
3. Capture health endpoint output:
   - `GET /health`
   - `GET /api/v1/health/security-pipeline`
   - Connector/integration health endpoint if authenticated access is available.
4. Capture dependency health:
   - PostgreSQL
   - Redis
   - Redpanda/Kafka
   - Vault
   - ClickHouse
5. Confirm backups exist before database or storage recovery.
6. Confirm rollback owner and communications owner.

## API/Web Restart

Expected behavior:

- Existing requests may fail during process restart.
- New requests should resume once API tasks pass health checks.
- Gateway security behavior must remain fail-closed when policy/redaction dependencies are unavailable.

Local validation:

```powershell
docker compose ps api
python scripts/local_resilience_check.py --no-fail
```

Recovery steps:

1. Restart API task/container in the target environment.
2. Wait for `/health` to return 200.
3. Wait for `/api/v1/health/security-pipeline` to return healthy or documented degraded state.
4. Run a safe authenticated smoke test.
5. Confirm no raw payloads or secrets appear in logs.

## PostgreSQL Failover Or Restore Expectation

Expected behavior:

- API dependency health should fail when DB is unavailable.
- Authenticated data paths should reject or fail safely rather than returning cross-tenant data.
- Recovery should preserve RLS configuration, migrations, and tenant-scoped data.

Recovery steps:

1. Promote managed standby or restore backup in staging/production according to cloud procedure.
2. Verify migrations are at head.
3. Verify RLS tenant context behavior.
4. Run a tenant-scoped smoke test.
5. Verify audit chain continuity for records written after restore.

Known local limitation:

- Compose uses a single PostgreSQL container and volume; it does not prove managed failover.

## Redis Outage Behavior

Expected behavior:

- Policy cache and non-critical caches may degrade.
- Rate limiting, locks, token validation, and destructive/sensitive paths should fail closed where Redis is required.
- Connector workers should not run unsafe duplicate work when locks cannot be acquired.

Recovery steps:

1. Restore Redis service or fail over cluster.
2. Confirm local TCP/health check.
3. Confirm policy cache can rebuild.
4. Confirm rate limiting resumes for tenant plans.
5. Confirm connector locks can be acquired and released.

## Redpanda/Kafka Outage Behavior

Expected behavior:

- Event publishing may fail or route to WAL/fallback where implemented.
- Workers should recover from consumer disconnects after broker recovery.
- Audit/report primary persistence must not depend solely on ClickHouse or Kafka.

Recovery steps:

1. Restore broker cluster or promote replacement.
2. Confirm broker health and topic availability.
3. Restart affected workers if needed.
4. Verify event lag drains.
5. Validate no duplicate destructive execution occurred.

## Vault Outage Behavior

Expected behavior:

- Provider credential retrieval should fail closed.
- Connector scans requiring secrets should not proceed.
- Destructive remediation requiring provider credentials should not proceed.
- No raw Vault reference or secret should be exposed in API/UI/log output.

Recovery steps:

1. Restore/unseal Vault or fail over HA Vault.
2. Verify Vault health endpoint.
3. Validate a safe credential metadata-only flow.
4. Do not print or export provider keys.
5. Review sanitized failure events.

## ClickHouse Outage Behavior

Expected behavior:

- Audit worker writes to PostgreSQL first.
- ClickHouse write failures are best-effort and should not block the authoritative PostgreSQL audit write path.
- Analytics/reporting backed by ClickHouse may degrade.

Recovery steps:

1. Restore ClickHouse service or replica.
2. Validate `/ping` and query health.
3. Reconcile any queued or missed analytic writes if a replay path exists.
4. Confirm reports clearly show degraded/missing analytics where applicable.

## Connector Worker Recovery

Expected behavior:

- Worker health reports Redis/database/Vault status and loop state.
- Failed scans should record sanitized failure reasons.
- Worker tokens should remain short-lived, scoped, and hash-only.

Recovery steps:

1. Confirm worker container/process is running.
2. Check worker health or integration health.
3. Confirm Redis locks are not stuck.
4. Confirm Vault credential access is healthy.
5. Run a safe simulated scan or metadata-only connector validation.

## Report And Artifact Recovery

Expected behavior:

- Report artifacts and evidence packages are bound to content hash and manifest hash.
- Downloads create metadata-only access logs.
- Expired artifacts should not download.

Recovery steps:

1. Restore object/artifact storage or local artifact store.
2. Verify artifact metadata and manifest hash.
3. Download a non-sensitive artifact through the authorized API.
4. Confirm access log entry with hashed access metadata.

## Rollback Steps

1. Stop rollout or scale down faulty version.
2. Re-deploy last known good release.
3. Verify `/health` and `/api/v1/health/security-pipeline`.
4. Run gateway, trust report, and audit export smoke tests.
5. Record incident timeline, affected tenants, and evidence artifacts.

## Verification Checklist

- API health restored.
- Security pipeline readiness restored or documented as degraded.
- Database queries succeed and tenant isolation is intact.
- Redis-backed policy cache/rate limits/locks restored.
- Redpanda/Kafka producers and consumers recover.
- Vault health restored and no secrets leaked.
- ClickHouse health restored or degraded mode documented.
- Connector worker health restored.
- Report artifacts and manifests remain retrievable.
- Audit events remain sanitized.

## Critical Observability Alerts

These alerts are repository configuration only until they fire in staging or production.

| Alert | Meaning | First checks | Safe mitigation | Escalate when |
| --- | --- | --- | --- | --- |
| `authclaw-<env>-alb-target-latency` | API target response time is sustained above the operational threshold. | Check API task health, provider latency, DB/Redis health, and recent deploys. | Scale API tasks if saturated, roll back recent deploy if correlated, keep gateway fail-closed controls enabled. | Latency remains elevated after scale/rollback or security pipeline health is degraded. |
| `authclaw-<env>-alb-target-5xx` / `authclaw-<env>-alb-5xx` | API target or ALB is returning sustained 5xx errors. | Check `/health`, `/api/v1/health/security-pipeline`, ECS task restarts, and dependency status. | Roll back faulty release, restart unhealthy tasks, restore failed dependency. | Errors affect authenticated gateway/compliance/trust flows or audit writes. |
| `authclaw-<env>-opa-fail-closed` | Gateway denied safely because policy engine evaluation failed, not because policy intentionally denied. | Check OPA health, OPA URL/config, policy bundle load, and security-pipeline health. | Restore OPA sidecar/runtime or switch only through approved fail-closed incident procedure. | More than one evaluation window is affected or all gateway traffic is denied. |
| `authclaw-<env>-gateway-rate-limit-store-unavailable` | Redis-backed gateway rate-limit check failed closed. | Check Redis health, security groups, credentials, and API Redis client errors. | Restore Redis/fail over cache; do not bypass tenant-plan limits without approval. | Legitimate customer gateway traffic is blocked. |
| `authclaw-<env>-audit-primary-write-failure` | Authoritative PostgreSQL audit write failed. | Check PostgreSQL health, migrations, RLS/session errors, and audit-worker logs. | Stop non-essential mutating workflows, restore DB connectivity, verify audit chain after recovery. | Any primary audit write failure is confirmed. |
| `authclaw-<env>-audit-clickhouse-mirror-failure` | ClickHouse analytics mirror is failing while PostgreSQL remains authoritative. | Check ClickHouse health and audit-worker mirror errors. | Restore ClickHouse and reconcile analytics/reports if replay is available. | Mirror failures persist beyond the evaluation window or reports become materially stale. |
| `authclaw-<env>-worker-dlq-growth` | Worker processing exhausted retries and routed messages to DLQ. | Check worker logs, Kafka broker health, and failing event schema/version. | Pause unsafe worker actions if needed; fix failing processor path; replay only after root cause is known. | DLQ growth continues or affects remediation/audit/security topics. |
| `authclaw-<env>-worker-dlq-publish-failure` | Worker could not publish a failed message to DLQ. | Check Kafka/Redpanda availability, DLQ topic permissions, and producer errors. | Restore broker/topic permissions and preserve original logs for replay analysis. | Any DLQ publish failure is confirmed. |
