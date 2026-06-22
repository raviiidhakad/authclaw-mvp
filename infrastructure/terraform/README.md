# AuthClaw Infrastructure — Terraform Module Directory

## Structure
```
infrastructure/terraform/
├── bootstrap/             # One-time S3+DynamoDB state backend setup
├── modules/
│   ├── vpc/               # VPC, subnets, NAT, flow logs, Cloud Map namespace
│   ├── kms/               # All CMKs: app, db, cache, vault-unseal
│   ├── iam/               # ECS execution, task, and Vault IAM roles
│   ├── ecs/               # ECS Cluster, ALB, WAFv2, all 5 services, auto-scaling
│   ├── rds/               # PostgreSQL 15, Multi-AZ, KMS, SSL enforcement
│   ├── redis/             # ElastiCache Redis 7, snapshots, auth, Cloud Map
│   ├── msk/               # MSK Serverless (dev) or Provisioned (staging/prod)
│   ├── vault/             # Vault on Fargate, DynamoDB backend, KMS auto-unseal
│   └── monitoring/        # CloudWatch alarms, dashboards, backup validation Lambda
└── environments/
    ├── dev/               # Cost-optimised, single-AZ, MSK Serverless
    ├── staging/           # Multi-AZ parity, provisioned MSK 3-broker
    └── prod/              # Full HA, m6g/m5x instances, 3-node Vault
```

## MSK Topics (applied post-`terraform apply` via Kafka provider)
| Topic | Partitions | Replication | Retention |
|---|---|---|---|
| `authclaw.audit.events`    | 6 | 3 | 30 days  |
| `authclaw.gateway.events`  | 6 | 3 | 7 days   |
| `authclaw.security.events` | 6 | 3 | 90 days  |
| `authclaw.user.events`     | 6 | 3 | 30 days  |

## WAFv2 Rules
| Rule | Priority | Action |
|---|---|---|
| AWSManagedRulesCommonRuleSet       | 10 | Block |
| AWSManagedRulesKnownBadInputsRuleSet | 20 | Block |
| AWSManagedRulesSQLiRuleSet         | 30 | Block |
| AWSManagedRulesBotControlRuleSet   | 40 | Count |

## Cloud Map DNS
| Service | DNS |
|---|---|
| API      | `api.authclaw.local:8000`     |
| Vault    | `vault.authclaw.local:8200`   |
| Postgres | `postgres.authclaw.local:5432`|
| Redis    | `redis.authclaw.local:6379`   |
| Kafka    | `kafka.authclaw.local:9098`   |
