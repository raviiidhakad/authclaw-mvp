# HA, Failover, Backup, and Chaos Readiness Architecture

Status: deploy-ready resilience planning evidence for AuthClaw PDF gap closure Phase 7. This document describes current local evidence and intended staging/AWS architecture. It does not prove a 99.99% service level and does not represent production deployment evidence.

## Current Local/Compose Topology

The local Docker Compose topology is single-node and intended for development and validation:

| Component | Local service | Host port | Current resilience role |
| --- | --- | ---: | --- |
| Web | `web` profile `docker-web` | 3000 | Optional local UI container; normally local Next.js dev server |
| API | `api` | 8000 | Single FastAPI process with `/health` and `/api/v1/health/security-pipeline` |
| Connector worker | `connector-worker` | n/a | Single worker process using DB, Redis, Redpanda, Vault, ClickHouse |
| PostgreSQL | `db` | 5434 | Single local database volume `postgres_data` |
| Redis | `redis` | 6379 | Single local cache/lock/rate-limit node |
| Redpanda/Kafka | `redpanda` | 19092 | Single local event broker |
| Redpanda Console | `console` | 8080 | Local broker console |
| Vault | `vault` | 8200 | Local dev Vault only |
| ClickHouse | `clickhouse` | 8123 | Single local analytics/audit volume `clickhouse_data` |

Compose healthchecks exist for PostgreSQL, Redis, Vault, Redpanda, and ClickHouse. The API depends on core services but is still a single local process. This topology is useful for fail-closed and degraded-mode checks, not HA proof.

## Intended AWS/Staging Topology

The production-prep target should be validated in staging before customer traffic:

| Layer | Intended model | Notes |
| --- | --- | --- |
| Web | Multi-AZ stateless web tasks behind load balancer/CDN | Keep static assets and environment configuration immutable per release |
| API gateway | Multi-AZ FastAPI tasks behind an application load balancer | Scale horizontally; keep request context tenant-scoped and fail-closed for sensitive paths |
| Connector workers | Horizontally scaled worker pool with partition-aware queue consumption | Use idempotency, Redis locks, and scoped worker tokens |
| PostgreSQL | Managed multi-AZ PostgreSQL with automated backups and point-in-time recovery | Define RTO/RPO before production approval |
| Redis | Managed Redis/Valkey cluster with replicas and failover | Needed for policy cache, locks, rate limits, and worker coordination |
| Redpanda/Kafka | Multi-broker cluster across availability zones | Required for event durability and worker recovery |
| ClickHouse | Replicated ClickHouse or managed equivalent with backup/restore plan | Used for analytics/raw finding/audit-adjacent data paths |
| Vault/secrets | HA Vault or cloud secrets manager with recovery/unseal process | No raw secrets in docs or evidence packages |
| Artifact/report storage | Durable object storage with versioning and retention policy | Report artifacts, evidence packages, audit export packages |
| OPA runtime | Sidecar or service with health checks and fail-closed behavior | Real sidecar validation remains pending |

## Scaling Model

### API/Web

- API and web tiers are stateless and should scale horizontally.
- API readiness must include database reachability, security pipeline readiness, OPA runtime mode health, and dependency degradation state.
- Public load balancer health should use `/health` for process liveness and `/api/v1/health/security-pipeline` for security-pipeline readiness.
- Sticky sessions should not be required.

### Connector Workers

- Connector workers should scale by work partitioning and Redis-backed integration locks.
- Worker tokens are tenant/job/action scoped and short-lived.
- Worker recovery depends on queue/event replay, idempotent scan lifecycle updates, and safe credential retrieval from Vault.
- Redis lock failure should prevent unsafe duplicate execution rather than allowing uncontrolled concurrency.

## Data Store HA Plans

### PostgreSQL

- Use managed multi-AZ primary/standby or equivalent.
- Enable automated snapshots and point-in-time recovery.
- Validate restore into isolated staging before production cutover.
- Preserve RLS tenant isolation and migration ordering during restore.

### Redis

- Use managed clustered Redis/Valkey with replicas and automatic failover.
- Treat Redis loss as degraded for caches and fail-closed for destructive/sensitive paths that require locks, rate limits, or token validation.
- Validate policy cache rebuild and rate-limit behavior after restart.

### Redpanda/Kafka

- Use at least a three-broker production cluster across availability zones.
- Configure replication factors appropriate to topic criticality.
- Validate producer behavior, worker consumer restart, and lag recovery.
- Preserve write-ahead log fallback behavior where implemented.

### ClickHouse

- Use replicated ClickHouse or managed storage-backed deployment.
- Back up schema, metadata, and table data on a documented schedule.
- Treat ClickHouse write failures as non-critical where PostgreSQL audit write is authoritative, as implemented in the audit worker.
- Validate report/audit queries after restore.

### Vault/Secrets

- Local Vault is development only.
- Production should use HA Vault or a cloud secrets service with audit logging, recovery keys, and sealed/unsealed runbooks.
- Credential paths and provider keys must never appear in logs, reports, or runbooks.
- Vault outage should fail closed for provider credential retrieval and destructive remediation.

### Object/Artifact Storage

- Store report artifacts, evidence packages, and audit export packages in durable object storage.
- Enable versioning, retention, access logs, encryption, and restore testing.
- Bind review evidence to manifest hash and artifact metadata.

## Health And Readiness Evidence

| Surface | Existing evidence | Current gap |
| --- | --- | --- |
| API liveness | `GET /health` returns app/version/environment | Does not check dependencies |
| Security pipeline readiness | `GET /api/v1/health/security-pipeline` includes Presidio, policy cache, OPA metadata | Uses current app process state only |
| Connector/integration health | `/api/v1/integrations/health`, `/api/v1/integrations/{id}/health`, and `ConnectorWorker.health_check()` | Worker health is not exposed as a standalone unauthenticated endpoint |
| PostgreSQL | Compose `pg_isready` healthcheck and local TCP check | No managed failover proof |
| Redis | Compose `redis-cli ping` healthcheck and local TCP check | No clustered failover proof |
| Redpanda | Compose `rpk cluster health` and local Kafka TCP check | No multi-broker proof |
| Vault | Compose `vault status` healthcheck and `/v1/sys/health` local check | Local dev Vault only |
| ClickHouse | Compose `clickhouse-client SELECT 1` and `/ping` local check | No replicated backup proof |

## RTO/RPO Assumptions

These assumptions are planning targets only until staging validation is complete:

| Component | Draft RTO target | Draft RPO target | Evidence still needed |
| --- | ---: | ---: | --- |
| API/web | 15 minutes | 0 data loss for stateless tier | Multi-AZ deployment and rolling restart proof |
| PostgreSQL | 30 minutes | 5 minutes | Managed PITR restore drill |
| Redis | 15 minutes | Cache loss accepted, token/lock loss fail-closed | Cluster failover drill |
| Redpanda/Kafka | 30 minutes | Topic-specific; target near-zero for replicated topics | Broker failure and consumer recovery drill |
| ClickHouse | 4 hours | 1 hour | Backup/restore drill |
| Vault/secrets | 30 minutes | 0 secrets loss | HA/unseal/recovery drill |
| Artifact storage | 1 hour | Near-zero with versioned object storage | Object restore drill |

## Known Gaps

- No AWS/staging HA deployment has been executed in this phase.
- No active-active multi-region validation has been run.
- No chaos test has killed production or staging infrastructure.
- No managed database failover or restore drill has been performed.
- No Redis cluster failover proof exists.
- No multi-broker Redpanda/Kafka proof exists.
- No replicated ClickHouse proof exists.
- No production Vault HA/unseal drill exists.
- No measured 99.99% uptime evidence exists.

## Local Non-Destructive Validation

Use the local readiness harness:

```powershell
python scripts/local_resilience_check.py --no-fail
```

The script only checks local HTTP endpoints and TCP reachability. It does not stop containers, mutate data, delete volumes, or call cloud APIs.
