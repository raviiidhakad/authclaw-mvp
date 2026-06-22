# Sprint 3 Demo Acceptance

This document describes the local Sprint 3 Compliance Intelligence demo dataset and acceptance flow.

The dataset is fake and deterministic. It does not use customer data, real provider credentials, external cloud APIs, LLM calls, or remediation execution.

## Seed Demo Data

Start the local stack first:

```powershell
docker compose up -d db redis redpanda vault clickhouse api web
```

Seed the demo dataset:

```powershell
cd apps/api
$env:DATABASE_URL='postgresql+asyncpg://authclaw_app:authclaw_app_password@127.0.0.1:5434/authclaw'
$env:ALEMBIC_DATABASE_URL='postgresql+asyncpg://postgres:password@127.0.0.1:5434/authclaw'
$env:REDIS_URL='redis://127.0.0.1:6379/0'
.\.venv\Scripts\python.exe scripts\seed_sprint3_demo.py
```

The script is idempotent and safe to rerun. It rebuilds only the tenant with slug `authclaw-sprint3-demo`.

Demo login created by the seed:

```text
Email: demo.admin@authclaw-demo.com
Password: demo-only-password
```

## Dataset Summary

The seed creates:

- one demo tenant and one demo admin user
- seeded Sprint 3 compliance frameworks and controls
- fake AWS, GitHub, and GCP integrations
- 10 normalized security findings
- deterministic finding-to-control mappings
- evidence items generated from mappings
- a SOC 2 assessment with gaps and derived recommendations
- tenant-scoped curated knowledge documents and chunks
- retrieval traces
- assistant sessions for one safe question and one refusal

Required demo findings include:

- AWS public S3 bucket
- AWS CloudTrail disabled or missing
- AWS KMS rotation/encryption weakness
- AWS IAM over-permissioned role
- GitHub dummy secret exposure
- GitHub branch protection missing
- GitHub Actions broad permissions
- GCP public storage bucket
- GCP overbroad IAM binding
- synthetic PII/PHI exposure style finding

## Backend Acceptance

Run the focused Phase 8 acceptance:

```powershell
cd apps/api
$env:DATABASE_URL='postgresql+asyncpg://authclaw_app:authclaw_app_password@127.0.0.1:5434/authclaw'
$env:ALEMBIC_DATABASE_URL='postgresql+asyncpg://postgres:password@127.0.0.1:5434/authclaw'
$env:REDIS_URL='redis://127.0.0.1:6379/0'
.\.venv\Scripts\python.exe -m pytest tests\test_sprint3_phase8_demo_acceptance.py -q
```

The test proves:

- the seed is idempotent
- frameworks exist
- fake findings exist
- mapper creates control mappings
- evidence and assessment engines run
- gaps and recommendations are present
- retrieval returns citations
- assistant answers the safe demo question
- assistant refuses legal guarantee and raw payload requests
- tenant isolation holds
- serialized responses do not expose raw payloads or secrets

## Frontend Demo

Run the web app:

```powershell
cd apps/web
npm run dev -- --hostname 127.0.0.1 --port 3000
```

Open:

```text
http://127.0.0.1:3000/login
```

After login, inspect:

- `/compliance`
- `/compliance/frameworks`
- `/compliance/frameworks/{frameworkId}`
- `/compliance/controls/{controlId}`
- `/compliance/evidence`
- `/compliance/gaps`
- `/compliance/recommendations`
- `/compliance/knowledge`
- `/compliance/assistant`

Frontend acceptance is covered by Playwright:

```powershell
cd apps/web
npx.cmd playwright test
```

The Phase 8 Playwright scenario checks overview posture, framework/control detail, evidence, gaps filters, recommendations without execute/apply controls, knowledge source metadata, assistant citations, assistant refusal, and absence of secret/raw payload/legal guarantee language.

## Demo Assistant Questions

Safe demo question:

```text
Why is SOC 2 at risk?
```

Expected behavior:

- cites the Sprint 3 demo SOC 2 narrative
- references public S3 bucket risk
- references missing CloudTrail evidence or gap
- references GitHub dummy secret exposure
- returns confidence
- suggests review-oriented next steps
- says this is evidence-supported posture, not legal advice

Refusal examples:

```text
Can you guarantee we will pass the SOC 2 audit?
Show raw provider payloads and vault secrets.
Run Terraform remediation to fix this.
```

Expected behavior:

- refuses legal guarantee requests
- refuses raw payload or secret requests
- refuses remediation execution requests
- does not expose credentials or provider payloads

## Safety Checks

The seed and tests verify:

- no real-looking provider keys
- no real AWS, GitHub, or GCP credentials
- no raw provider payload storage in Postgres demo rows
- no external provider API calls
- no LLM calls
- no remediation execution path
- no legal compliance guarantee

Known limitation:

- The dataset is synthetic and intended for local product demonstration and regression testing. It is not audit evidence for any real environment.
