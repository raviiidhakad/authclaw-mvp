# AuthClaw Backup And Restore Runbook

Status: backup and restore preparation for staging/AWS readiness. This document avoids real secrets and does not perform backups by itself.

## Backup Inventory

| Asset | Backup method | Restore validation |
| --- | --- | --- |
| PostgreSQL | Managed snapshots, PITR, logical dumps for selected tenants where approved | Restore to isolated database, run migrations, validate RLS and tenant smoke tests |
| ClickHouse | Table/data backups or managed snapshot equivalent | Restore to isolated ClickHouse, validate schema and representative analytic queries |
| Vault/secrets | HA Vault snapshots or cloud secret manager backup process | Restore/unseal in isolated environment and validate metadata-only credential flow |
| Report artifacts | Versioned object storage or local artifact store backup | Retrieve artifact, manifest, content hash, and access log path |
| Audit export packages | Versioned object storage and manifest/hash inventory | Verify package manifest, chain proof, signature, and tenant consistency |
| Configuration | Version-controlled config templates and environment-specific secret inventory | Recreate staging environment without exposing secret values |
| Redpanda/Kafka | Topic replication, broker snapshots where supported, WAL/event replay strategy | Restore broker/topic state and validate producer/consumer recovery |
| Redis | Snapshot if needed for operational continuity | Validate cache rebuild; do not rely on Redis as source of record |

## PostgreSQL Backup

Production/staging target:

- Enable automated backups and point-in-time recovery.
- Retain backups according to tenant and security policy.
- Encrypt backups at rest.
- Restrict backup access to approved operators.
- Record backup job ID, timestamp, source cluster, and retention.

Restore validation:

1. Restore into an isolated environment.
2. Run migrations to expected head.
3. Validate tenant isolation and RLS.
4. Verify representative users, roles, policies, routes, audit records, report metadata, and evidence package metadata.
5. Verify no cross-tenant data access.

## ClickHouse Backup

Production/staging target:

- Back up ClickHouse schema and data.
- Document which tables are source-of-record and which are analytics/replayable.
- Validate large report and audit-adjacent query recovery.

Restore validation:

1. Restore to isolated ClickHouse.
2. Run `SELECT 1` or `/ping`.
3. Validate representative analytics/report queries.
4. Document any acceptable data lag or replay gaps.

## Vault Backup, Unseal, And Recovery

Production/staging target:

- Use HA Vault or approved cloud secrets service.
- Store recovery keys according to operator policy.
- Enable audit logging.
- Never put real root tokens, unseal keys, provider keys, or credential material in runbooks.

Restore validation:

1. Restore/unseal only in an approved isolated environment.
2. Validate service authentication without printing token values.
3. Validate metadata-only provider credential status.
4. Confirm failed credential retrieval is sanitized.

## Artifact And Report Storage Backup

Production/staging target:

- Store artifacts in versioned object storage.
- Enable access logs and retention.
- Back up manifest and artifact inventory.
- Keep report artifacts tenant scoped.

Restore validation:

1. Retrieve artifact metadata.
2. Retrieve manifest.
3. Validate manifest hash and content hash.
4. Download through authorized API.
5. Confirm metadata-only access log entry.

## Audit Export Package Backup

Production/staging target:

- Store signed audit export packages with immutable or retention-protected storage where required.
- Keep package ID, tenant ID, manifest hash, chain proof metadata, signature metadata, and verification result.

Restore validation:

1. Retrieve package from backup storage.
2. Run package verification.
3. Confirm tenant consistency.
4. Confirm tamper detection still works on modified package copy.

## Configuration And Secret Boundaries

- Store config templates in Git.
- Store environment-specific secret values only in approved secret systems.
- Do not include raw provider keys, Vault tokens, database passwords, private keys, or cloud credentials in backup docs.
- Rotate secrets after suspected exposure.

## Restore Drill Checklist

- Backup source and timestamp identified.
- Restore target is isolated.
- Migrations run to expected head.
- API starts and `/health` returns 200.
- Security pipeline readiness checked.
- Tenant isolation smoke test passed.
- Gateway safe request smoke test passed.
- Trust report/evidence package smoke test passed.
- Audit export verification smoke test passed.
- Access logs verified.
- No secret or raw payload leakage observed.

## Known Gaps

- Local Compose volumes are not production backup evidence.
- Managed PostgreSQL PITR has not been validated in AWS/staging.
- ClickHouse restore has not been validated in replicated deployment.
- Vault HA recovery has not been validated in staging.
- Object storage versioning and lifecycle policy are not provisioned in this phase.
